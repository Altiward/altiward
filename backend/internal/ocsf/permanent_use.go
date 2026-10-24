package ocsf

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/store"
)

// permanentUse maps an admin.permanent_use event: someone used an account that is always
// an administrator. It is an Authentication record: a sign-in is a Logon and, when the Mac
// saw it end, a Logoff that shares the Logon's correlation_uid, the use ID. A prompt,
// sudo or su has no end, so it is a Logon. The logon type says how the account was used.
func permanentUse(e store.StoredEvent, tenantID string) Record {
	method := detailString(e.Detail, "method")
	state := detailString(e.Detail, "state")
	host := detailString(e.Detail, "remote_host")
	onSessionOf := detailString(e.Detail, "on_session_of")

	activityID, activity := 1, "Logon"
	if state == event.UseStateEnded {
		activityID, activity = 2, "Logoff"
	}
	r := base(e, tenantID, 3002, "Authentication", 3, "Identity & Access Management", activityID, activity, SeverityInformational)
	r["status_id"], r["status"] = 1, "Success"
	r["message"] = permanentUseMessage(e, method, state, host, onSessionOf)

	if use := detailString(e.Detail, "use_id"); use != "" {
		r["metadata"].(map[string]any)["correlation_uid"] = use
	}
	switch method {
	case "console", "terminal":
		r["logon_type_id"], r["logon_type"] = 2, "Interactive"
	case "ssh", "screen_sharing":
		r["logon_type_id"], r["logon_type"] = 10, "Remote Interactive"
		r["is_remote"] = true
	case "prompt":
		r["logon_type_id"], r["logon_type"] = 99, "Authorisation prompt"
	default:
		// sudo and su, and any method a later agent adds.
		r["logon_type_id"], r["logon_type"] = 99, method
	}
	if host != "" {
		src := map[string]any{}
		if ip, err := netip.ParseAddr(host); err == nil {
			src["ip"] = ip.String()
		} else {
			src["hostname"] = host
		}
		r["src_endpoint"] = src
	}
	if onSessionOf != "" {
		r["actor"] = map[string]any{"user": map[string]any{"name": onSessionOf}}
	}
	if t, ok := detailTime(e.Detail, "started"); ok {
		r["start_time"] = t.UnixMilli()
	}
	if t, ok := detailTime(e.Detail, "ended"); ok {
		r["end_time"] = t.UnixMilli()
	}
	return r
}

func permanentUseMessage(e store.StoredEvent, method, state, host, onSessionOf string) string {
	account := "an unknown account"
	if e.User != nil {
		account = e.User.LocalName
	}
	from := ""
	if host != "" {
		from = " from " + host
	}
	ended := state == event.UseStateEnded
	var what string
	switch method {
	case "console":
		what = "signed in at the Mac"
		if ended {
			what = "signed out of the Mac"
		}
	case "terminal":
		what = "signed in using Terminal"
		if ended {
			what = "signed out of Terminal"
		}
	case "ssh":
		what = "signed in to SSH" + from
		if ended {
			what = "signed out of SSH" + from
		}
	case "screen_sharing":
		what = "shared the screen" + from
		if ended {
			what = "signed out of screen sharing" + from
		}
	case "prompt":
		what = "approved an authorisation prompt"
		if right := detailString(e.Detail, "right"); right != "" {
			what = "approved " + right
		}
		if onSessionOf != "" {
			what += " on " + onSessionOf + "'s session"
		}
	case "sudo":
		what = "ran sudo"
		if runAs := detailString(e.Detail, "run_as"); runAs != "" {
			what += " as " + runAs
		}
		if tty := detailString(e.Detail, "tty"); tty != "" {
			what += " on " + tty
		}
	case "su":
		what = "switched user with su"
		if onSessionOf != "" {
			what += " on " + onSessionOf + "'s session"
		}
	default:
		what = "used the account (" + method + ")"
	}
	// A heartbeat groups repeats of one use into one event.
	if n, ok := e.Detail["count"].(float64); ok && n > 1 {
		what += fmt.Sprintf(" (%d times)", int(n))
	}
	return account + " " + what
}

// detailTime reads an RFC 3339 time from an event's detail.
func detailTime(detail map[string]any, key string) (time.Time, bool) {
	s, _ := detail[key].(string)
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}
