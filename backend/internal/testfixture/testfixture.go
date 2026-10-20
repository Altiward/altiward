// Package testfixture loads the contract fixtures in docs/schema/examples for tests.
// The Swift agent tests decode the examples too, so both sides agree on the wire format.
package testfixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
)

// Names of the fixture files, without extension.
var Names = []string{
	"elevation-granted", "elevation-revoked", "elevation-overdue", "elevation-expired-enforced",
	"admin-out-of-band", "agent-health", "agent-tamper", "agent-silent", "persistence-detected",
	"elevation-revoked-permanent-admin", "agent-tamper-retired",
}

func read(t testing.TB, dir, name string) []byte {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	b, err := os.ReadFile(filepath.Join(root, "docs", "schema", dir, name+".json"))
	if err != nil {
		t.Fatalf("read fixture %s/%s: %v", dir, name, err)
	}
	return b
}

func decode(t testing.TB, dir, name string) event.Event {
	t.Helper()
	e, err := event.Decode(read(t, dir, name))
	if err != nil {
		t.Fatalf("decode fixture %s/%s: %v", dir, name, err)
	}
	if err := e.Validate(e.Timestamp); err != nil {
		t.Fatalf("validate fixture %s/%s: %v", dir, name, err)
	}
	return e
}

// Raw returns the bytes of docs/schema/examples/<name>.json.
func Raw(t testing.TB, name string) []byte {
	t.Helper()
	return read(t, "examples", name)
}

// Event decodes and validates a fixture.
func Event(t testing.TB, name string) event.Event {
	t.Helper()
	return decode(t, "examples", name)
}

// Ptr returns a pointer to v.
func Ptr[T any](v T) *T { return &v }

// Time parses an RFC 3339 timestamp or fails the test.
func Time(t testing.TB, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// SignatureVector is docs/schema/signature-vector.json, the request-signing contract.
type SignatureVector struct {
	DeviceID      string `json:"device_id"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Timestamp     int64  `json:"timestamp"`
	Body          string `json:"body"`
	Canonical     string `json:"canonical"`
	PublicKeySPKI []byte `json:"public_key_spki"`
	Signature     []byte `json:"signature"`
}

// Signature loads the shared request-signing vector.
func Signature(t testing.TB) SignatureVector {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "schema", "signature-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v SignatureVector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
