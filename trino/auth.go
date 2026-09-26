package trino

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	externalAuthenticationConfig         = "externalAuthentication"
	externalAuthenticationTimeoutConfig  = "externalAuthenticationTimeout"
	defaultExternalAuthenticationTimeout = 2 * time.Minute
)

var errExternalAuthenticationNeedsTLS = errors.New("trino: TLS/SSL is required for external authentication")

// validateExternalAuthentication rejects the settings that send their own
// Authorization header, which a token must not silently replace.
func (c *Config) validateExternalAuthentication(serverURL *url.URL) error {
	if !c.ExternalAuthentication {
		return nil
	}
	if serverURL.Scheme != "https" {
		return errExternalAuthenticationNeedsTLS
	}
	password, _ := serverURL.User.Password()
	if password != "" || c.KerberosEnabled || c.ForwardAuthorizationHeader {
		return errors.New("trino: external authentication cannot be combined with a password, Kerberos or " + forwardAuthorizationHeaderConfig)
	}
	return nil
}

// RedirectHandler sends the user to redirectURL to authenticate, when the
// server asks for external authentication.
type RedirectHandler func(ctx context.Context, redirectURL *url.URL) error

// TokenCache keeps the token obtained through external authentication. It is
// used by all connections of a Connector, so it must be safe for concurrent use.
type TokenCache interface {
	// Token returns the cached token, or "" when there is none.
	Token() string
	SetToken(token string)
}

// OpenBrowser is a RedirectHandler that opens redirectURL in the default browser.
func OpenBrowser(ctx context.Context, redirectURL *url.URL) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", redirectURL.String())
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", redirectURL.String())
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", redirectURL.String())
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trino: opening a browser: %w", err)
	}
	return nil
}

type memoryTokenCache struct {
	mu    sync.Mutex
	token string
}

func (m *memoryTokenCache) Token() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token
}

func (m *memoryTokenCache) SetToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = token
}

// externalAuthenticator obtains tokens for the connections of one Connector.
type externalAuthenticator struct {
	redirect RedirectHandler
	cache    TokenCache
	timeout  time.Duration
	// lock lets one connection obtain a token while the others wait for it.
	lock chan struct{}
}

func newExternalAuthenticator(conf *Config) *externalAuthenticator {
	if !conf.ExternalAuthentication {
		return nil
	}
	a := &externalAuthenticator{
		redirect: conf.RedirectHandler,
		cache:    conf.TokenCache,
		timeout:  defaultExternalAuthenticationTimeout,
		lock:     make(chan struct{}, 1),
	}
	if a.redirect == nil {
		a.redirect = OpenBrowser
	}
	if a.cache == nil {
		a.cache = &memoryTokenCache{}
	}
	if conf.ExternalAuthenticationTimeout != nil {
		a.timeout = *conf.ExternalAuthenticationTimeout
	}
	return a
}

// authenticate returns a token to use instead of the rejected one, reusing a
// token another connection obtained in the meantime.
func (a *externalAuthenticator) authenticate(ctx context.Context, client *http.Client, challenge *externalAuthChallenge, rejected string) (string, error) {
	select {
	case a.lock <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-a.lock }()

	if token := a.cache.Token(); token != "" && token != rejected {
		return token, nil
	}
	a.cache.SetToken("")

	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	if challenge.redirectURL != nil {
		if err := a.redirect(ctx, challenge.redirectURL); err != nil {
			return "", fmt.Errorf("trino: external authentication redirect: %w", err)
		}
	}
	token, err := pollToken(ctx, client, challenge.tokenURL.String())
	if err != nil {
		return "", err
	}
	a.cache.SetToken(token)
	return token, nil
}

type externalAuthChallenge struct {
	tokenURL    *url.URL
	redirectURL *url.URL
}

// parseExternalAuthChallenge reads the challenge Trino sends when external
// authentication is enabled: Bearer x_redirect_server="...", x_token_server="...".
func parseExternalAuthChallenge(header http.Header) (*externalAuthChallenge, error) {
	for _, value := range header.Values("WWW-Authenticate") {
		scheme, params, _ := strings.Cut(value, " ")
		if !strings.EqualFold(scheme, "Bearer") {
			continue
		}
		fields := make(map[string]string)
		for _, param := range strings.Split(params, ",") {
			key, value, _ := strings.Cut(strings.TrimSpace(param), "=")
			fields[key] = strings.Trim(value, `"`)
		}
		if fields["x_token_server"] == "" {
			continue
		}
		challenge := &externalAuthChallenge{}
		var err error
		if challenge.tokenURL, err = parseChallengeURL("x_token_server", fields["x_token_server"]); err != nil {
			return nil, err
		}
		if redirect := fields["x_redirect_server"]; redirect != "" {
			if challenge.redirectURL, err = parseChallengeURL("x_redirect_server", redirect); err != nil {
				return nil, err
			}
		}
		return challenge, nil
	}
	return nil, nil
}

// parseChallengeURL accepts only absolute http and https URLs, since the
// redirect URL is handed to the system's URL opener.
func parseChallengeURL(name, value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("trino: invalid %s: %w", name, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("trino: invalid %s: %q is not an absolute http or https URL", name, value)
	}
	return u, nil
}

type tokenPollResponse struct {
	Token   string `json:"token"`
	NextURI string `json:"nextUri"`
	Error   string `json:"error"`
}

// pollToken follows the token server until it returns the token, retrying
// unavailable responses and network errors until ctx is done.
func pollToken(ctx context.Context, client *http.Client, uri string) (string, error) {
	const initialDelay, maxDelay = 100 * time.Millisecond, 500 * time.Millisecond
	delay := initialDelay
	for {
		poll, err := getTokenPoll(ctx, client, uri)
		var retryable *retryableError
		if errors.As(err, &retryable) {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", fmt.Errorf("trino: external authentication: %w, last error: %w", ctx.Err(), retryable.err)
			case <-timer.C:
			}
			delay = min(delay*2, maxDelay)
			continue
		}
		if err != nil {
			return "", err
		}
		switch {
		case poll.Token != "":
			// Tell the server the token arrived; a failure only delays its cleanup.
			if req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, nil); err == nil {
				if resp, err := client.Do(req); err == nil {
					resp.Body.Close()
				}
			}
			return poll.Token, nil
		case poll.Error != "":
			return "", fmt.Errorf("trino: external authentication failed: %s", poll.Error)
		case poll.NextURI != "":
			uri = poll.NextURI
			delay = initialDelay
		default:
			return "", errors.New("trino: external authentication failed: empty token server response")
		}
	}
}

type retryableError struct{ err error }

func (e *retryableError) Error() string { return e.err.Error() }

func getTokenPoll(ctx context.Context, client *http.Client, uri string) (*tokenPollResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("trino: invalid token server URL: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("trino: external authentication: %w", ctx.Err())
		}
		return nil, &retryableError{err}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var poll tokenPollResponse
		if err := json.NewDecoder(resp.Body).Decode(&poll); err != nil {
			return nil, fmt.Errorf("trino: decoding token server response: %w", err)
		}
		return &poll, nil
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return nil, &retryableError{fmt.Errorf("token server returned %s", resp.Status)}
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("trino: token server returned %s: %s", resp.Status, body)
	}
}
