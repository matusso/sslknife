package server

import (
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	skcrypto "github.com/matusso/sslknife/internal/crypto"
)

const (
	sessionCookie = "sslknife_session"
	csrfHeader    = "X-CSRF-Token"
	sessionTTL    = 12 * time.Hour
)

type session struct {
	csrf    string
	expires time.Time
}

// auth holds the access token and browser sessions. The access token is
// shown once at startup (in the URL) and exchanged for an HttpOnly,
// SameSite=Strict session cookie; API clients may send it as a bearer token.
type auth struct {
	token    string
	mu       sync.Mutex
	sessions map[string]*session
}

func newAuth(token string) *auth {
	if token == "" {
		token = hex.EncodeToString(skcrypto.RandomBytes(24))
	}
	return &auth{token: token, sessions: map[string]*session{}}
}

func (a *auth) tokenOK(t string) bool {
	return t != "" && subtle.ConstantTimeCompare([]byte(t), []byte(a.token)) == 1
}

func (a *auth) newSession() (string, *session) {
	id := hex.EncodeToString(skcrypto.RandomBytes(32))
	s := &session{csrf: hex.EncodeToString(skcrypto.RandomBytes(24)), expires: time.Now().Add(sessionTTL)}
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range a.sessions {
		if time.Now().After(v.expires) {
			delete(a.sessions, k)
		}
	}
	a.sessions[id] = s
	return id, s
}

func (a *auth) lookup(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok || time.Now().After(s.expires) {
		delete(a.sessions, c.Value)
		return nil
	}
	return s
}

func (a *auth) logout(r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
}

// securityHeaders applies strict headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// hostCheck rejects requests whose Host header is not an expected name,
// which defeats DNS-rebinding attacks against the local server.
func hostCheck(allowed map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
		if !allowed[host] {
			http.Error(w, "unexpected Host header", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin checks Origin/Referer for state-changing browser requests.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return true // non-browser clients; CSRF token still required for cookies
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

// requireAuth protects API routes. Cookie sessions must present the CSRF
// token on unsafe methods; bearer tokens are not ambient and need none.
func (a *auth) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			if a.tokenOK(strings.TrimPrefix(h, "Bearer ")) {
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		s := a.lookup(r)
		if s == nil {
			writeError(w, http.StatusUnauthorized, "not authenticated: open the URL printed by 'sslknife server'")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(s.csrf)) != 1 {
				writeError(w, http.StatusForbidden, "CSRF check failed")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// login exchanges ?token= for a session cookie and redirects to strip the
// token from the address bar and history.
func (a *auth) login(w http.ResponseWriter, r *http.Request) bool {
	t := r.URL.Query().Get("token")
	if t == "" {
		return false
	}
	if !a.tokenOK(t) {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return true
	}
	id, _ := a.newSession()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: r.TLS != nil, //nolint:gosec // Secure whenever HTTPS is used; loopback HTTP mode cannot use it
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return true
}
