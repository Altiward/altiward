package sentinel_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Altiward/altiward/integrations/sentinel"
)

// TestSchemaMatchesTheRowType keeps the stream setup.sh declares in step with sentinel.Row,
// the row the server (and altiward-forwarder) upload.
func TestSchemaMatchesTheRowType(t *testing.T) {
	b, err := os.ReadFile("setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)\nSCHEMA="([^"]*)"`).FindSubmatch(b)
	if m == nil {
		t.Fatal("no SCHEMA= in setup.sh")
	}
	if got, want := strings.Fields(string(m[1])), strings.Fields(sentinel.Columns); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("setup.sh declares\n  %v\nsentinel.Columns is\n  %v", got, want)
	}
}
