package api_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/api"
	"github.com/Altiward/altiward/backend/internal/auth"
	"github.com/Altiward/altiward/backend/internal/store"
)

// tokenActor is consoleToken's fingerprint, the actor its sign-ins are recorded as.
var tokenActor = fmt.Sprintf("token:%x", sha256.Sum256([]byte(consoleToken)))[:14]

// signInStore counts RecordTokenSignIn calls, fails them while fail is set, and makes each
// take delay.
type signInStore struct {
	store.Store
	calls atomic.Int32
	fail  atomic.Bool
	delay time.Duration
}

func (s *signInStore) RecordTokenSignIn(ctx context.Context, a store.AuditEntry, within time.Duration) (time.Time, error) {
	s.calls.Add(1)
	time.Sleep(s.delay)
	if s.fail.Load() {
		return time.Time{}, errors.New("database unavailable")
	}
	return s.Store.RecordTokenSignIn(ctx, a, within)
}

// newTokenServer serves st on clock, with newServer's tokens.
func newTokenServer(t *testing.T, st store.Store, clock *testClock) http.Handler {
	t.Helper()
	tokens, err := auth.Parse("acme="+agentToken, "acme="+consoleToken+",other="+otherConsole)
	if err != nil {
		t.Fatal(err)
	}
	return api.New(st, tokens, slog.New(slog.NewTextHandler(io.Discard, nil)), clock.now)
}

// signIns returns acme's sign-in entries, newest first.
func signIns(t *testing.T, st store.Store) []store.AuditEntry {
	t.Helper()
	entries, err := st.ListAudit(context.Background(), "acme", store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range entries {
		if e.Action == store.AuditSignIn {
			out = append(out, e)
		}
	}
	return out
}

// withoutSignIns leaves out the sign-ins, which a console token's first request in an hour
// records whatever the request does.
func withoutSignIns(entries []store.AuditEntry) []store.AuditEntry {
	return slices.DeleteFunc(slices.Clone(entries), func(e store.AuditEntry) bool { return e.Action == store.AuditSignIn })
}

// tokenSignIn is a token sign-in by consoleToken at at, as another server would record it.
func tokenSignIn(t *testing.T, at time.Time) store.AuditEntry {
	t.Helper()
	id, err := store.NewDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	return store.AuditEntry{ID: id, TenantID: "acme", At: at, Actor: tokenActor, Action: store.AuditSignIn, Target: "console",
		Detail: map[string]any{"method": "token", "role": "admin", "route": "GET /v1/devices"}}
}

func TestTokenUseIsRecordedOncePerHour(t *testing.T) {
	st, clock := store.NewMemory(nil), &testClock{t: serverNow(t)}
	h := newTokenServer(t, st, clock)
	if rec, _ := do(t, h, "GET", "/v1/devices", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("devices: %d %s", rec.Code, rec.Body)
	}
	entries := signIns(t, st)
	want := map[string]any{"method": "token", "role": "admin", "route": "GET /v1/devices"}
	if len(entries) != 1 || entries[0].Actor != tokenActor || entries[0].Target != "console" ||
		!entries[0].At.Equal(serverNow(t)) || !reflect.DeepEqual(entries[0].Detail, want) {
		t.Fatalf("sign-ins = %+v", entries)
	}

	// The rest of the hour is covered, whichever endpoint the token calls.
	clock.advance(59 * time.Minute)
	if rec, _ := do(t, h, "GET", "/v1/overview", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("overview: %d %s", rec.Code, rec.Body)
	}
	if entries := signIns(t, st); len(entries) != 1 {
		t.Fatalf("sign-ins within the hour = %+v", entries)
	}
	clock.advance(2 * time.Minute)
	if rec, _ := do(t, h, "GET", "/v1/devices", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("devices: %d %s", rec.Code, rec.Body)
	}
	if entries := signIns(t, st); len(entries) != 2 || !entries[0].At.Equal(clock.now()) || !reflect.DeepEqual(entries[0].Detail, want) {
		t.Fatalf("sign-ins after the hour = %+v", entries)
	}
}

func TestTokenUseSurvivesARestart(t *testing.T) {
	st, clock := store.NewMemory(nil), &testClock{t: serverNow(t)}
	if rec, _ := do(t, newTokenServer(t, st, clock), "GET", "/v1/devices", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("devices: %d %s", rec.Code, rec.Body)
	}
	// A restarted server, or another replica, finds the entry in the store.
	clock.advance(30 * time.Minute)
	restarted := newTokenServer(t, st, clock)
	if rec, _ := do(t, restarted, "GET", "/v1/devices", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("devices after a restart: %d %s", rec.Code, rec.Body)
	}
	if entries := signIns(t, st); len(entries) != 1 {
		t.Fatalf("sign-ins = %+v", entries)
	}
	// That entry covers it for the rest of its own hour, not for an hour from the restart.
	clock.advance(31 * time.Minute)
	if rec, _ := do(t, restarted, "GET", "/v1/devices", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("devices: %d %s", rec.Code, rec.Body)
	}
	if entries := signIns(t, st); len(entries) != 2 || !entries[0].At.Equal(clock.now()) {
		t.Fatalf("sign-ins an hour after the first = %+v", entries)
	}
}

func TestBreakGlassUseIsRecorded(t *testing.T) {
	env := newSSOServer(t)
	if rec, _ := do(t, env.h, "GET", "/v1/devices", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("devices: %d %s", rec.Code, rec.Body)
	}
	entries := signIns(t, env.store)
	if len(entries) != 1 || entries[0].Actor != "break-glass:"+strings.TrimPrefix(tokenActor, "token:") ||
		entries[0].Detail["method"] != "token" {
		t.Fatalf("sign-ins = %+v", entries)
	}
}

func TestTokenUseFailsClosed(t *testing.T) {
	st := &signInStore{Store: store.NewMemory(nil)}
	st.fail.Store(true)
	h := newTokenServer(t, st, &testClock{t: serverNow(t)})
	before, err := st.TenantSettings(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	rec, out := do(t, h, "PUT", "/v1/settings", consoleToken, map[string]any{"silent_after_hours": before.SilentAfterHours + 24})
	if rec.Code != http.StatusInternalServerError || out["error"] != "internal error" {
		t.Fatalf("settings with the sign-in unrecorded: %d %s", rec.Code, rec.Body)
	}
	if after, _ := st.TenantSettings(context.Background(), "acme"); after != before {
		t.Fatalf("settings changed to %+v", after)
	}
	if entries, _ := st.ListAudit(context.Background(), "acme", store.AuditFilter{}); len(entries) != 0 {
		t.Fatalf("audit = %+v", entries)
	}

	// The failure isn't remembered as coverage: the next request tries again.
	st.fail.Store(false)
	if rec, _ := do(t, h, "GET", "/v1/settings", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("settings once the store is back: %d %s", rec.Code, rec.Body)
	}
	if entries := signIns(t, st); len(entries) != 1 {
		t.Fatalf("sign-ins = %+v", entries)
	}
}

func TestTokenUseRecordsTheRouteNotThePath(t *testing.T) {
	st := store.NewMemory(nil)
	h := newTokenServer(t, st, &testClock{t: serverNow(t)})
	if rec, _ := do(t, h, "GET", "/v1/sessions/"+strings.Repeat("a", 5000)+"%0Aforged", consoleToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("session: %d %s", rec.Code, rec.Body)
	}
	entries := signIns(t, st)
	if len(entries) != 1 || entries[0].Detail["route"] != "GET /v1/sessions/{id}" {
		t.Fatalf("sign-ins = %+v", entries)
	}
	for k, v := range entries[0].Detail {
		if strings.Contains(fmt.Sprint(v), "forged") {
			t.Errorf("detail %s carries the request path: %q", k, v)
		}
	}
}

func TestFutureTokenEntryDoesNotCover(t *testing.T) {
	st, clock := store.NewMemory(nil), &testClock{t: serverNow(t)}
	// A server whose clock is three hours fast recorded a sign-in.
	if err := st.RecordAudit(context.Background(), tokenSignIn(t, clock.now().Add(3*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if rec, _ := do(t, newTokenServer(t, st, clock), "GET", "/v1/devices", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("devices: %d %s", rec.Code, rec.Body)
	}
	if entries := signIns(t, st); len(entries) != 2 || !entries[1].At.Equal(clock.now()) {
		t.Fatalf("sign-ins = %+v", entries)
	}
}

func TestTokenUseCoverageEndsAnHourFromNowAtTheLatest(t *testing.T) {
	st, clock := &signInStore{Store: store.NewMemory(nil)}, &testClock{t: serverNow(t)}
	// A server whose clock is 30 seconds fast recorded a sign-in, close enough to cover this
	// request, but this server still asks the store again an hour from now.
	if err := st.RecordAudit(context.Background(), tokenSignIn(t, clock.now().Add(30*time.Second))); err != nil {
		t.Fatal(err)
	}
	h := newTokenServer(t, st, clock)
	if rec, _ := do(t, h, "GET", "/v1/devices", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("devices: %d %s", rec.Code, rec.Body)
	}
	clock.advance(time.Hour)
	if rec, _ := do(t, h, "GET", "/v1/devices", consoleToken, nil); rec.Code != 200 {
		t.Fatalf("devices: %d %s", rec.Code, rec.Body)
	}
	if n, entries := st.calls.Load(), signIns(t, st); n != 2 || len(entries) != 1 {
		t.Fatalf("%d store calls, sign-ins = %+v", n, entries)
	}
}

func TestConcurrentFirstTokenUseRecordsOnce(t *testing.T) {
	// A slow store keeps the first request's call open while the others arrive.
	st := &signInStore{Store: store.NewMemory(nil), delay: 20 * time.Millisecond}
	h := newTokenServer(t, st, &testClock{t: serverNow(t)})
	codes := make([]int, 20)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Go(func() {
			req := httptest.NewRequest("GET", "/v1/devices", nil)
			req.Header.Set("Authorization", "Bearer "+consoleToken)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			codes[i] = rec.Code
		})
	}
	wg.Wait()
	for i, code := range codes {
		if code != 200 {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if n, entries := st.calls.Load(), signIns(t, st); n != 1 || len(entries) != 1 {
		t.Fatalf("%d store calls, sign-ins = %+v", n, entries)
	}
}

func TestRequestsThatRecordNoTokenUse(t *testing.T) {
	st := &signInStore{Store: store.NewMemory(nil)}
	h := newTokenServer(t, st, &testClock{t: serverNow(t)})
	for _, c := range []struct {
		method, path, token string
		code                int
	}{
		{"GET", "/v1/auth/config", consoleToken, 200},
		{"POST", "/v1/auth/logout", consoleToken, 204}, // a token has no session to end
		{"GET", "/v1/devices", "not-a-token-at-all", 401},
		{"GET", "/v1/devices", agentToken, 403},
	} {
		if rec, _ := do(t, h, c.method, c.path, c.token, nil); rec.Code != c.code {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, rec.Code, c.code)
		}
	}
	if n, entries := st.calls.Load(), signIns(t, st); n != 0 || len(entries) != 0 {
		t.Fatalf("%d store calls, sign-ins = %+v", n, entries)
	}
}
