package auth_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Altiward/altiward/backend/internal/auth"
)

func TestRolesIncludeTheOnesBelow(t *testing.T) {
	for _, c := range []struct {
		have, need auth.ConsoleRole
		ok         bool
	}{
		{auth.Admin, auth.Viewer, true}, {auth.Admin, auth.Admin, true}, {auth.Operator, auth.Viewer, true},
		{auth.Operator, auth.Admin, false}, {auth.Viewer, auth.Operator, false}, {"", auth.Viewer, false},
		{"root", auth.Viewer, false},
	} {
		if got := c.have.Allows(c.need); got != c.ok {
			t.Errorf("%q allows %q = %v", c.have, c.need, got)
		}
	}
}

func TestConsoleTokensAreAdminsAndBreakGlassWithSSO(t *testing.T) {
	tokens, err := auth.Parse("acme=agent-token-acme-0001", "acme=console-token-acme-0001")
	if err != nil {
		t.Fatal(err)
	}
	get := func(token string) auth.Principal {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		p, ok := tokens.Authenticate(r)
		if !ok {
			t.Fatalf("%s not accepted", token)
		}
		return p
	}
	console := get("console-token-acme-0001")
	if console.ConsoleRole != auth.Admin || !strings.HasPrefix(console.Actor, "token:") {
		t.Fatalf("console = %+v", console)
	}
	tokens.BreakGlass()
	after := get("console-token-acme-0001")
	if after.Actor != "break-glass:"+strings.TrimPrefix(console.Actor, "token:") || after.ConsoleRole != auth.Admin {
		t.Fatalf("break-glass = %+v", after)
	}
	if agent := get("agent-token-acme-0001"); agent.ConsoleRole != "" || !strings.HasPrefix(agent.Actor, "token:") {
		t.Fatalf("agent = %+v", agent)
	}
}
