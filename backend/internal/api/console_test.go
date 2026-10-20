package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Altiward/altiward/backend/internal/api"
)

func consoleServer(t *testing.T) http.Handler {
	t.Helper()
	return consoleServerWith(t, true)
}

func consoleServerWith(t *testing.T, updateCheck bool) http.Handler {
	t.Helper()
	dist := fstest.MapFS{
		"index.html":          {Data: []byte("<!doctype html><title>Altiward</title>")},
		"assets/index-1.js":   {Data: []byte("console.log(1)")},
		"brand/mark.svg":      {Data: []byte("<svg/>")},
		"assets/nested/x.css": {Data: []byte("body{}")},
	}
	if err := api.CheckConsole(dist); err != nil {
		t.Fatal(err)
	}
	return api.WithConsole(newServer(t), dist, updateCheck)
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestConsoleServesFilesAndRoutes(t *testing.T) {
	h := consoleServer(t)
	for _, c := range []struct {
		path, body, cache, contentType string
	}{
		{"/", "<!doctype html>", "no-cache", "text/html"},
		{"/index.html", "<!doctype html>", "no-cache", "text/html"},
		{"/fleet", "<!doctype html>", "no-cache", "text/html"},
		{"/sessions/abc", "<!doctype html>", "no-cache", "text/html"},
		{"/assets/index-1.js", "console.log(1)", "public, max-age=31536000, immutable", "text/javascript"},
		{"/brand/mark.svg", "<svg/>", "public, max-age=3600", "image/svg+xml"},
	} {
		rec := get(t, h, "GET", c.path)
		if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), c.body) {
			t.Errorf("%s: %d %q", c.path, rec.Code, rec.Body)
			continue
		}
		if got := rec.Header().Get("Cache-Control"); got != c.cache {
			t.Errorf("%s: Cache-Control = %q", c.path, got)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, c.contentType) {
			t.Errorf("%s: Content-Type = %q", c.path, got)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP = %q", c.path, csp)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", c.path)
		}
	}
}

func TestConsoleLeavesTheAPIAlone(t *testing.T) {
	h := consoleServer(t)
	if rec := get(t, h, "GET", "/healthz"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("healthz: %d %s", rec.Code, rec.Body)
	}
	if rec := get(t, h, "GET", "/v1/sessions"); rec.Code != 401 {
		t.Fatalf("API without a token: %d %s", rec.Code, rec.Body)
	}
	// An unknown API path is a 404, not the console's index.html.
	if rec := get(t, h, "GET", "/v1/nothing-here"); rec.Code != 404 || strings.Contains(rec.Body.String(), "doctype") {
		t.Fatalf("unknown API path: %d %s", rec.Code, rec.Body)
	}
}

func TestConsoleMissingFilesAndMethods(t *testing.T) {
	h := consoleServer(t)
	if rec := get(t, h, "GET", "/assets/gone.js"); rec.Code != 404 {
		t.Fatalf("missing asset: %d", rec.Code)
	}
	if rec := get(t, h, "GET", "/assets/nested"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "doctype") {
		t.Fatalf("a directory is not listed: %d %s", rec.Code, rec.Body)
	}
	// The router cleans paths before the console sees them, redirecting to the clean one
	// (301 before Go 1.26, 307 since).
	if rec := get(t, h, "GET", "/assets/../index.html"); rec.Code != http.StatusMovedPermanently &&
		rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") != "/index.html" {
		t.Fatalf("unclean path: %d %v", rec.Code, rec.Header())
	}
	if rec := get(t, h, "POST", "/fleet"); rec.Code != 405 {
		t.Fatalf("POST: %d", rec.Code)
	}
	if rec := get(t, h, "HEAD", "/"); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("HEAD: %d %q", rec.Code, rec.Body)
	}
}

func TestCheckConsoleWantsIndex(t *testing.T) {
	if err := api.CheckConsole(fstest.MapFS{}); err == nil {
		t.Fatal("an empty directory passed")
	}
}

// The console's browser asks GitHub for the release list (update check), so the CSP lets
// it connect there only while ALTIWARD_UPDATE_CHECK leaves the check on.
func TestConsoleCSPAllowsGitHubOnlyWithUpdateCheck(t *testing.T) {
	connectSrc := func(csp string) string {
		for _, d := range strings.Split(csp, ";") {
			if d = strings.TrimSpace(d); strings.HasPrefix(d, "connect-src ") {
				return d
			}
		}
		return ""
	}
	on := get(t, consoleServerWith(t, true), "GET", "/").Header().Get("Content-Security-Policy")
	if got := connectSrc(on); got != "connect-src 'self' https://api.github.com" {
		t.Errorf("update check on: %q (CSP %q)", got, on)
	}
	off := get(t, consoleServerWith(t, false), "GET", "/").Header().Get("Content-Security-Policy")
	if got := connectSrc(off); got != "connect-src 'self'" || strings.Contains(off, "github") {
		t.Errorf("update check off: %q (CSP %q)", got, off)
	}
	for _, csp := range []string{on, off} {
		if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("CSP lost a directive: %q", csp)
		}
	}
}
