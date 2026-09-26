package trino

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeExternalAuth makes a fake coordinator answer requests without its
// current token with Trino's external authentication challenge, and serves
// the token from /oauth2/token after pending polls that return a nextUri.
type fakeExternalAuth struct {
	fc       *fakeCoordinator
	mu       sync.Mutex
	token    string
	pending  int
	failure  string
	polls    int
	deletes  int
	rejected chan struct{}
}

func newFakeExternalAuth(fc *fakeCoordinator, token string) *fakeExternalAuth {
	a := &fakeExternalAuth{fc: fc, token: token, rejected: make(chan struct{}, 100)}
	fc.onRequest(a.serve)
	return a
}

func (a *fakeExternalAuth) serve(w http.ResponseWriter, r *http.Request) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if index, ok := strings.CutPrefix(r.URL.Path, "/oauth2/token/"); ok {
		if r.Method == http.MethodDelete {
			a.deletes++
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		a.polls++
		n, _ := strconv.Atoi(index)
		response := map[string]string{"token": a.token}
		switch {
		case a.failure != "":
			response = map[string]string{"error": a.failure}
		case a.pending != 0:
			a.pending--
			response = map[string]string{"nextUri": a.fc.url() + "/oauth2/token/" + strconv.Itoa(n+1)}
		}
		_ = json.NewEncoder(w).Encode(response)
		return true
	}
	if r.Header.Get(authorizationHeader) == "Bearer "+a.token {
		return false
	}
	w.Header().Add("WWW-Authenticate", `Basic realm="Trino"`)
	w.Header().Add("WWW-Authenticate", `Bearer x_redirect_server="`+a.fc.url()+`/oauth2/initiate/1", x_token_server="`+a.fc.url()+`/oauth2/token/1"`)
	w.WriteHeader(http.StatusUnauthorized)
	a.rejected <- struct{}{}
	return true
}

// expire makes the coordinator reject the current token and hand out next.
func (a *fakeExternalAuth) expire(next string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = next
}

func (a *fakeExternalAuth) counts() (polls, deletes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.polls, a.deletes
}

type recordingRedirects struct {
	mu   sync.Mutex
	urls []string
}

func (r *recordingRedirects) handle(_ context.Context, u *url.URL) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.urls = append(r.urls, u.String())
	return nil
}

func (r *recordingRedirects) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.urls)
}

func openExternalAuth(t *testing.T, fc *fakeCoordinator, conf *Config) *sql.DB {
	t.Helper()
	conf.ServerURI = fc.url()
	conf.ExternalAuthentication = true
	conf.HTTPClient = fc.server.Client()
	connector, err := NewConnector(conf)
	require.NoError(t, err)
	db := sql.OpenDB(connector)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}

func TestExternalAuthentication(t *testing.T) {
	t.Parallel()
	fc := newFakeTLSCoordinator(t)
	fc.respond(statementPage(), resultPage([][]any{{1}}))
	auth := newFakeExternalAuth(fc, "token1")
	auth.pending = 2
	redirects := &recordingRedirects{}
	db := openExternalAuth(t, fc, &Config{RedirectHandler: redirects.handle})

	rows, err := db.Query("SELECT 1")
	require.NoError(t, err)
	assert.Equal(t, []int{1}, collectInts(t, rows))

	assert.Equal(t, []string{fc.url() + "/oauth2/initiate/1"}, redirects.urls)
	polls, deletes := auth.counts()
	assert.Equal(t, 3, polls, "two pending polls, then the token")
	assert.Equal(t, 1, deletes, "the token server is told the token arrived")
	var statements []capturedRequest
	for _, r := range fc.capturedRequests() {
		if r.path == "/v1/statement" {
			statements = append(statements, r)
		}
	}
	require.Len(t, statements, 2)
	assert.Equal(t, "SELECT 1", string(statements[1].body), "the retried statement keeps its body")
	assert.Equal(t, "Bearer token1", statements[1].header.Get(authorizationHeader))
}

func TestExternalAuthenticationSharesTokenAcrossConnections(t *testing.T) {
	t.Parallel()
	fc := newFakeTLSCoordinator(t)
	// fresh responses, since the fake sets nextUri on the value it serves
	fc.respond(
		page{response: func(string) any { return &stmtResponse{ID: fakeQueryID} }},
		page{response: func(base string) any { return resultPage([][]any{{1}}).response(base) }},
	)
	auth := newFakeExternalAuth(fc, "token1")
	redirects := &recordingRedirects{}
	db := openExternalAuth(t, fc, &Config{RedirectHandler: func(ctx context.Context, u *url.URL) error {
		// wait until the other connection was rejected too
		for range 2 {
			select {
			case <-auth.rejected:
			case <-time.After(5 * time.Second):
				return errors.New("the second connection was not rejected")
			}
		}
		return redirects.handle(ctx, u)
	}})

	ctx := context.Background()
	conns := make([]*sql.Conn, 2)
	for i := range conns {
		conn, err := db.Conn(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, conn.Close()) })
		conns[i] = conn
	}
	var wg sync.WaitGroup
	errs := make([]error, len(conns))
	for i, conn := range conns {
		wg.Go(func() {
			var n int
			errs[i] = conn.QueryRowContext(ctx, "SELECT 1").Scan(&n)
		})
	}
	wg.Wait()
	for _, err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, 1, redirects.count())
}

func TestExternalAuthenticationRenewsTokenDuringQuery(t *testing.T) {
	t.Parallel()
	fc := newFakeTLSCoordinator(t)
	fc.respond(statementPage(), resultPage([][]any{{1}}))
	auth := newFakeExternalAuth(fc, "token1")
	fc.onPage(func(index int, r *http.Request) {
		if index == 0 {
			auth.expire("token2")
		}
	})
	redirects := &recordingRedirects{}
	db := openExternalAuth(t, fc, &Config{RedirectHandler: redirects.handle})

	rows, err := db.Query("SELECT 1")
	require.NoError(t, err)
	assert.Equal(t, []int{1}, collectInts(t, rows))
	assert.Equal(t, 2, redirects.count())
}

func TestExternalAuthenticationUsesTokenCache(t *testing.T) {
	t.Parallel()
	fc := newFakeTLSCoordinator(t)
	fc.respond(statementPage(), resultPage([][]any{{1}}))
	auth := newFakeExternalAuth(fc, "cached")
	cache := &memoryTokenCache{}
	cache.SetToken("cached")
	db := openExternalAuth(t, fc, &Config{
		TokenCache: cache,
		RedirectHandler: func(context.Context, *url.URL) error {
			return errors.New("the cached token should have been used")
		},
	})

	rows, err := db.Query("SELECT 1")
	require.NoError(t, err)
	assert.Equal(t, []int{1}, collectInts(t, rows))
	assert.Empty(t, auth.rejected, "the first request carries the cached token")
}

func TestExternalAuthenticationStoresTokenInCache(t *testing.T) {
	t.Parallel()
	fc := newFakeTLSCoordinator(t)
	fc.respond(statementPage(), resultPage([][]any{{1}}))
	newFakeExternalAuth(fc, "token1")
	cache := &memoryTokenCache{}
	db := openExternalAuth(t, fc, &Config{TokenCache: cache, RedirectHandler: (&recordingRedirects{}).handle})

	rows, err := db.Query("SELECT 1")
	require.NoError(t, err)
	collectInts(t, rows)
	assert.Equal(t, "token1", cache.Token())
}

func TestExternalAuthenticationFailures(t *testing.T) {
	t.Parallel()
	redirectErr := errors.New("no browser")
	tests := []struct {
		name    string
		setup   func(*fakeExternalAuth)
		conf    Config
		wantErr string
		wantIs  error
	}{
		{
			name:    "token server error",
			setup:   func(a *fakeExternalAuth) { a.failure = "access denied" },
			wantErr: "access denied",
		},
		{
			name:   "redirect handler error",
			conf:   Config{RedirectHandler: func(context.Context, *url.URL) error { return redirectErr }},
			wantIs: redirectErr,
		},
		{
			name:   "timeout",
			setup:  func(a *fakeExternalAuth) { a.pending = 1 << 30 },
			conf:   Config{ExternalAuthenticationTimeout: ptr(50 * time.Millisecond)},
			wantIs: context.DeadlineExceeded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fc := newFakeTLSCoordinator(t)
			fc.respond(statementPage(), resultPage([][]any{{1}}))
			auth := newFakeExternalAuth(fc, "token1")
			if tt.setup != nil {
				tt.setup(auth)
			}
			conf := tt.conf
			if conf.RedirectHandler == nil {
				conf.RedirectHandler = (&recordingRedirects{}).handle
			}
			db := openExternalAuth(t, fc, &conf)

			_, err := db.Query("SELECT 1")
			require.Error(t, err)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			}
			if tt.wantIs != nil {
				assert.ErrorIs(t, err, tt.wantIs)
			}
		})
	}
}

func TestExternalAuthenticationDisabled(t *testing.T) {
	t.Parallel()
	fc := newFakeTLSCoordinator(t)
	fc.respond(statementPage(), resultPage([][]any{{1}}))
	auth := newFakeExternalAuth(fc, "token1")
	connector, err := NewConnector(&Config{ServerURI: fc.url(), HTTPClient: fc.server.Client()})
	require.NoError(t, err)
	db := sql.OpenDB(connector)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	_, err = db.Query("SELECT 1")
	var qf *ErrQueryFailed
	require.ErrorAs(t, err, &qf)
	assert.Equal(t, http.StatusUnauthorized, qf.StatusCode)
	polls, _ := auth.counts()
	assert.Zero(t, polls)
}

func TestExternalAuthenticationRequiresTLS(t *testing.T) {
	t.Parallel()
	_, err := ParseDSN("http://localhost:8080?externalAuthentication=true")
	assert.ErrorIs(t, err, errExternalAuthenticationNeedsTLS)
	_, err = NewConnector(&Config{ServerURI: "http://localhost:8080", ExternalAuthentication: true})
	assert.ErrorIs(t, err, errExternalAuthenticationNeedsTLS)
}

func TestExternalAuthenticationConflicts(t *testing.T) {
	t.Parallel()
	for name, conf := range map[string]*Config{
		"password":                   {ServerURI: "https://user:secret@localhost"},
		"Kerberos":                   {ServerURI: "https://localhost", KerberosEnabled: true},
		"forwardAuthorizationHeader": {ServerURI: "https://localhost", ForwardAuthorizationHeader: true},
	} {
		conf.ExternalAuthentication = true
		_, err := NewConnector(conf)
		assert.ErrorContains(t, err, "cannot be combined", name)
	}

	db, err := sql.Open("trino", "https://localhost?externalAuthentication=true&forwardAuthorizationHeader=true")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	assert.ErrorContains(t, db.Ping(), "cannot be combined")
}

func TestExternalAuthenticationDSNRoundTrip(t *testing.T) {
	t.Parallel()
	conf := &Config{ServerURI: "https://localhost:8443", ExternalAuthentication: true, ExternalAuthenticationTimeout: ptr(time.Minute)}
	dsn, err := conf.FormatDSN()
	require.NoError(t, err)
	parsed, err := ParseDSN(dsn)
	require.NoError(t, err)
	assert.True(t, parsed.ExternalAuthentication)
	assert.Equal(t, time.Minute, *parsed.ExternalAuthenticationTimeout)

	_, err = ParseDSN("https://localhost:8443?externalAuthenticationTimeout=0s")
	assert.ErrorContains(t, err, "must be a positive duration")
}

func TestFormatDSNRejectsExternalAuthenticationCallbacks(t *testing.T) {
	t.Parallel()
	for name, conf := range map[string]*Config{
		"RedirectHandler": {ServerURI: "https://localhost", RedirectHandler: OpenBrowser},
		"TokenCache":      {ServerURI: "https://localhost", TokenCache: &memoryTokenCache{}},
	} {
		_, err := conf.FormatDSN()
		assert.ErrorContains(t, err, name+" cannot be expressed in a DSN", name)
	}
}

func TestParseExternalAuthChallenge(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		headers      []string
		wantToken    string
		wantRedirect string
	}{
		{
			name:         "redirect and token servers",
			headers:      []string{`Basic realm="Trino"`, `Bearer x_redirect_server="https://t/initiate", x_token_server="https://t/token"`},
			wantToken:    "https://t/token",
			wantRedirect: "https://t/initiate",
		},
		{
			name:      "token server only",
			headers:   []string{`Bearer x_token_server="https://t/token"`},
			wantToken: "https://t/token",
		},
		{
			name:    "plain bearer challenge",
			headers: []string{`Bearer realm="Trino"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			header := http.Header{"Www-Authenticate": tt.headers}
			challenge, err := parseExternalAuthChallenge(header)
			require.NoError(t, err)
			if tt.wantToken == "" {
				assert.Nil(t, challenge)
				return
			}
			require.NotNil(t, challenge)
			assert.Equal(t, tt.wantToken, challenge.tokenURL.String())
			if tt.wantRedirect == "" {
				assert.Nil(t, challenge.redirectURL)
			} else {
				assert.Equal(t, tt.wantRedirect, challenge.redirectURL.String())
			}
		})
	}
}

func TestParseExternalAuthChallengeRejectsNonHTTPURLs(t *testing.T) {
	t.Parallel()
	for _, header := range []string{
		`Bearer x_redirect_server="file:///etc/passwd", x_token_server="https://t/token"`,
		`Bearer x_redirect_server="-a Calculator", x_token_server="https://t/token"`,
		`Bearer x_token_server="smb://t/token"`,
	} {
		_, err := parseExternalAuthChallenge(http.Header{"Www-Authenticate": []string{header}})
		assert.ErrorContains(t, err, "not an absolute http or https URL", header)
	}
}

func TestNewConnectorCopiesExternalAuthenticationTimeout(t *testing.T) {
	t.Parallel()
	conf := &Config{ServerURI: "https://localhost", ExternalAuthentication: true, ExternalAuthenticationTimeout: ptr(time.Minute)}
	connector, err := NewConnector(conf)
	require.NoError(t, err)
	*conf.ExternalAuthenticationTimeout = time.Second
	assert.Equal(t, time.Minute, *connector.conf.ExternalAuthenticationTimeout)
}
