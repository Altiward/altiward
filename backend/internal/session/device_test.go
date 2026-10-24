package session_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/session"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// signIn is a started and an ended event that share one use ID, as the agent sends them.
func signIn(t *testing.T) (started, ended event.Event) {
	started = testfixture.Event(t, "admin-permanent-use-started")
	ended = testfixture.Event(t, "admin-permanent-use-ended")
	ended.Detail["use_id"] = started.Detail["use_id"]
	ended.Detail["started"] = started.Detail["started"]
	return started, ended
}

func TestDevicePermanentUseEndedReplacesStarted(t *testing.T) {
	started, ended := signIn(t)
	d := session.NewDevice("t1", started.Device.Serial)
	d.Apply(started)
	if len(d.RecentPermanentUses) != 1 || d.RecentPermanentUses[0].State != event.UseStateStarted ||
		d.RecentPermanentUses[0].EndedAt != nil {
		t.Fatalf("after started: %+v", d.RecentPermanentUses)
	}
	d.Apply(ended)
	if len(d.RecentPermanentUses) != 1 {
		t.Fatalf("uses = %+v", d.RecentPermanentUses)
	}
	u := d.RecentPermanentUses[0]
	if u.State != event.UseStateEnded || u.EndedAt == nil || !u.EndedAt.Equal(testfixture.Time(t, "2026-10-16T09:42:00Z")) ||
		!u.StartedAt.Equal(testfixture.Time(t, "2026-10-16T09:00:00Z")) || u.Account != "breakglass" ||
		u.Method != "ssh" || u.RemoteHost == nil || *u.RemoteHost != "10.0.0.5" || u.Count != 1 {
		t.Fatalf("use = %+v", u)
	}
}

func TestDevicePermanentUseOrderIndependent(t *testing.T) {
	started, ended := signIn(t)
	d := session.NewDevice("t1", started.Device.Serial)
	d.Apply(ended)
	d.Apply(started)
	if len(d.RecentPermanentUses) != 1 {
		t.Fatalf("uses = %+v", d.RecentPermanentUses)
	}
	if u := d.RecentPermanentUses[0]; u.State != event.UseStateEnded || u.EndedAt == nil {
		t.Fatalf("a started replaced an ended: %+v", u)
	}
}

func TestDevicePermanentUseKeepsNewest(t *testing.T) {
	base := testfixture.Event(t, "admin-permanent-use-prompt")
	uses := make([]event.Event, 25)
	for i := range uses {
		e := base
		e.EventID = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		e.Detail = map[string]any{}
		for k, v := range base.Detail {
			e.Detail[k] = v
		}
		e.Detail["use_id"] = fmt.Sprintf("10000000-0000-4000-8000-%012d", i)
		e.Detail["started"] = base.Timestamp.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		uses[i] = e
	}
	d := session.NewDevice("t1", base.Device.Serial)
	for i := len(uses) - 1; i >= 0; i-- { // oldest last, to show delivery order doesn't matter
		d.Apply(uses[i])
	}
	if len(d.RecentPermanentUses) != session.MaxRecentAlerts {
		t.Fatalf("kept %d", len(d.RecentPermanentUses))
	}
	for i, u := range d.RecentPermanentUses {
		want := fmt.Sprintf("10000000-0000-4000-8000-%012d", len(uses)-1-i)
		if u.UseID != want {
			t.Fatalf("use %d = %s, want %s", i, u.UseID, want)
		}
	}
	u := d.RecentPermanentUses[0]
	if u.State != event.UseStateSingle || u.OnSessionOf == nil || *u.OnSessionOf != "alex" ||
		u.Right == nil || *u.Right != "com.apple.ServiceManagement.daemons.modify" || u.EndedAt != nil {
		t.Fatalf("use = %+v", u)
	}
}

func TestDevicePermanentUseCountAndCheckIn(t *testing.T) {
	e := testfixture.Event(t, "admin-permanent-use-prompt")
	e.Detail["count"] = float64(4)
	d := session.NewDevice("t1", e.Device.Serial)
	d.Apply(e)
	if got := d.RecentPermanentUses[0].Count; got != 4 {
		t.Fatalf("count = %d", got)
	}
	if !d.LastSeenAt.Equal(e.Timestamp) || d.AgentVersion != e.Device.AgentVersion {
		t.Fatalf("a use wasn't a check-in: %+v", d)
	}
}

func TestDeviceStateWithoutPermanentUses(t *testing.T) {
	var d session.Device
	if err := json.Unmarshal([]byte(`{"serial":"C02XK0AAJGH5","last_seen_at":"2026-10-16T10:05:00Z"}`), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.RecentPermanentUses) != 0 {
		t.Fatalf("uses = %+v", d.RecentPermanentUses)
	}
	d.Apply(testfixture.Event(t, "admin-permanent-use-started"))
	if len(d.RecentPermanentUses) != 1 {
		t.Fatalf("uses = %+v", d.RecentPermanentUses)
	}
	b, _ := json.Marshal(session.NewDevice("t1", "C02XK0AAJGH5"))
	if !strings.Contains(string(b), `"recent_permanent_uses":[]`) {
		t.Fatalf("a new device doesn't list an empty array: %s", b)
	}
	b, _ = json.Marshal(d.RecentPermanentUses[0])
	for _, key := range []string{"use_id", "account", "method", "state", "started_at", "ended_at", "on_session_of", "remote_host", "right", "count"} {
		if !strings.Contains(string(b), `"`+key+`"`) {
			t.Fatalf("no %s in %s", key, b)
		}
	}
}

func TestDevicePermanentUseSudoRunAs(t *testing.T) {
	sudo := testfixture.Event(t, "admin-permanent-use-prompt")
	sudo.Detail = map[string]any{
		"use_id": "20000000-0000-4000-8000-000000000001", "method": "sudo", "state": "single",
		"source": "unified_log", "started": "2026-10-16T10:20:00Z", "tty": "ttys003", "run_as": "root", "count": float64(2),
	}
	d := session.NewDevice("t1", sudo.Device.Serial)
	d.Apply(sudo)
	if u := d.RecentPermanentUses[0]; u.RunAs == nil || *u.RunAs != "root" || u.Count != 2 {
		t.Fatalf("use = %+v", u)
	}
	delete(sudo.Detail, "run_as")
	sudo.Detail["use_id"] = "20000000-0000-4000-8000-000000000002"
	d.Apply(sudo)
	for _, u := range d.RecentPermanentUses {
		if u.UseID == "20000000-0000-4000-8000-000000000002" && u.RunAs != nil {
			t.Fatalf("run_as invented: %+v", u)
		}
	}
	b, _ := json.Marshal(d.RecentPermanentUses[0])
	if !strings.Contains(string(b), `"run_as"`) {
		t.Fatalf("no run_as in %s", b)
	}
}
