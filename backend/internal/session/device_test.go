package session_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
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
		e.Detail["last"] = e.Detail["started"]
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

// Events the backend raises say nothing about the Mac itself, so they are not a check-in:
// they leave the seen times and the versions alone.
func TestServerRaisedEventsLeaveTheDeviceAlone(t *testing.T) {
	for _, name := range []string{"agent-enrollment-pending", "agent-enrollment-enrolled"} {
		t.Run(name, func(t *testing.T) {
			e := testfixture.Event(t, name)
			d := session.NewDevice("t1", e.Device.Serial)
			d.Apply(e)
			d.Received(e, e.Timestamp)
			if !d.FirstSeenAt.IsZero() || !d.LastSeenAt.IsZero() || !d.LastReceivedAt.IsZero() {
				t.Fatalf("seen times moved: %+v", d)
			}
			if d.HardwareUUID != "" || d.OSVersion != "" || d.AgentVersion != "" || d.PrivilegesVersion != nil {
				t.Fatalf("identity or versions moved: %+v", d)
			}
			if !reflect.DeepEqual(d, session.NewDevice("t1", e.Device.Serial)) {
				t.Fatalf("device changed: %+v", d)
			}
		})
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

// permanentUse is an admin.permanent_use event with only the detail a device keeps. ended
// and last are left out when empty.
func permanentUse(t *testing.T, useID, method, state, started, ended, last string) event.Event {
	t.Helper()
	e := testfixture.Event(t, "admin-permanent-use-prompt")
	e.EventID = "e-" + useID + "-" + state
	e.Detail = map[string]any{"use_id": useID, "method": method, "state": state, "source": "utmpx", "started": started}
	if ended != "" {
		e.Detail["ended"] = ended
		e.Detail["end_basis"] = "logged"
	}
	if last != "" {
		e.Detail["last"] = last
		e.Detail["count"] = float64(2)
	}
	return e
}

// at is a time on the fixtures' day, i minutes after 08:00.
func at(i int) string {
	return time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
}

func singles(t *testing.T, n, from int) []event.Event {
	out := make([]event.Event, n)
	for i := range out {
		out[i] = permanentUse(t, fmt.Sprintf("single-%03d", from+i), "sudo", event.UseStateSingle, at(from+i), "", "")
	}
	return out
}

func useStates(d session.Device) map[string]string {
	m := map[string]string{}
	for _, u := range d.RecentPermanentUses {
		m[u.UseID] = u.State
	}
	return m
}

func TestDevicePermanentUseOpenSurvivesManyNewer(t *testing.T) {
	d := session.NewDevice("t1", "C02XK0AAJGH5")
	d.Apply(permanentUse(t, "ssh-open", "ssh", event.UseStateStarted, at(0), "", ""))
	for _, e := range singles(t, 25, 1) {
		d.Apply(e)
	}
	states := useStates(d)
	if states["ssh-open"] != event.UseStateStarted {
		t.Fatalf("the open sign-in was trimmed: %v", states)
	}
	if len(d.RecentPermanentUses) != 1+session.MaxRecentAlerts {
		t.Fatalf("kept %d uses, want the open one and %d singles", len(d.RecentPermanentUses), session.MaxRecentAlerts)
	}
	if d.RecentPermanentUses[0].UseID != "ssh-open" {
		t.Fatalf("open sign-ins aren't listed first: %+v", d.RecentPermanentUses[0])
	}
	for i, u := range d.RecentPermanentUses[1:] {
		if want := fmt.Sprintf("single-%03d", 25-i); u.UseID != want {
			t.Fatalf("single %d = %s, want %s (the newest 20, newest first)", i, u.UseID, want)
		}
	}
}

func TestDevicePermanentUseEndedAfterManyNewerIsKept(t *testing.T) {
	d := session.NewDevice("t1", "C02XK0AAJGH5")
	d.Apply(permanentUse(t, "ssh-open", "ssh", event.UseStateStarted, at(0), "", ""))
	for _, e := range singles(t, 25, 1) {
		d.Apply(e)
	}
	d.Apply(permanentUse(t, "ssh-open", "ssh", event.UseStateEnded, at(0), at(30), ""))
	if len(d.RecentPermanentUses) != session.MaxRecentAlerts {
		t.Fatalf("kept %d uses: %v", len(d.RecentPermanentUses), useStates(d))
	}
	if u := d.RecentPermanentUses[0]; u.UseID != "ssh-open" || u.State != event.UseStateEnded {
		t.Fatalf("the newest ended isn't listed first as ended: %+v", u)
	}
	if _, ok := useStates(d)["single-006"]; ok {
		t.Fatal("the ended didn't push the oldest single out")
	}

	// An ended older than the newest 20 finished uses is trimmed, and still closes its started.
	d.Apply(permanentUse(t, "console-open", "console", event.UseStateStarted, at(-10), "", ""))
	d.Apply(permanentUse(t, "console-open", "console", event.UseStateEnded, at(-10), at(-5), ""))
	if _, ok := useStates(d)["console-open"]; ok {
		t.Fatalf("an old ended was kept, or its started stayed open: %v", useStates(d))
	}
}

func TestDevicePermanentUseFinishedOrderedByNewestTime(t *testing.T) {
	d := session.NewDevice("t1", "C02XK0AAJGH5")
	d.Apply(permanentUse(t, "sudo-group", "sudo", event.UseStateSingle, at(0), "", at(50)))
	d.Apply(permanentUse(t, "ssh-ended", "ssh", event.UseStateEnded, at(5), at(40), ""))
	d.Apply(permanentUse(t, "su-single", "su", event.UseStateSingle, at(45), "", ""))
	var got []string
	for _, u := range d.RecentPermanentUses {
		got = append(got, u.UseID)
	}
	if want := []string{"sudo-group", "su-single", "ssh-ended"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order = %v, want %v (by ended, else last, else started)", got, want)
	}
}

// permutations calls f with every order of events.
func permutations(events []event.Event, f func([]event.Event)) {
	var walk func(int)
	walk = func(k int) {
		if k == len(events) {
			f(slices.Clone(events))
			return
		}
		for i := k; i < len(events); i++ {
			events[k], events[i] = events[i], events[k]
			walk(k + 1)
			events[k], events[i] = events[i], events[k]
		}
	}
	walk(0)
}

func TestDevicePermanentUseEveryArrivalOrder(t *testing.T) {
	// 19 singles fill the list to one below the cap. Then, in every order: a sign-in's
	// started, its ended (the newest use), and a single older than all the others, which
	// the ended pushes past the cap.
	base := singles(t, 19, 10)
	events := []event.Event{
		permanentUse(t, "ssh", "ssh", event.UseStateStarted, at(0), "", ""),
		permanentUse(t, "ssh", "ssh", event.UseStateEnded, at(0), at(60), ""),
		permanentUse(t, "oldest", "su", event.UseStateSingle, at(1), "", ""),
	}
	var want []session.PermanentUse
	permutations(events, func(order []event.Event) {
		d := session.NewDevice("t1", "C02XK0AAJGH5")
		for _, e := range append(slices.Clone(base), order...) {
			d.Apply(e)
		}
		if want == nil {
			want = d.RecentPermanentUses
			if len(want) != session.MaxRecentAlerts || want[0].UseID != "ssh" || want[0].State != event.UseStateEnded {
				t.Fatalf("final list: %v", useStates(d))
			}
			if _, ok := useStates(d)["oldest"]; ok {
				t.Fatalf("the oldest single wasn't trimmed: %v", useStates(d))
			}
			return
		}
		if !reflect.DeepEqual(d.RecentPermanentUses, want) {
			var ids []string
			for _, e := range order {
				ids = append(ids, e.Detail["use_id"].(string)+"/"+e.Detail["state"].(string))
			}
			t.Fatalf("order %v gave %v, want %v", ids, useStates(d), want)
		}
	})
}
