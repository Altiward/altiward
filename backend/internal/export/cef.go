package export

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/ocsf"
	"github.com/Altiward/altiward/integrations/syslog"
)

// SyslogFormat is what the body of each syslog message holds.
type SyslogFormat string

const (
	FormatCEF  SyslogFormat = "cef"  // ArcSight Common Event Format, one line per event
	FormatJSON SyslogFormat = "json" // the OCSF record as compact JSON
)

// SyslogSink sends each record as one RFC 5424 message: facility authpriv, the event type
// as MSGID, and a CEF or OCSF JSON body.
type SyslogSink struct {
	Client *syslog.Client
	Format SyslogFormat
}

func (s *SyslogSink) Name() string { return "syslog" }

func (s *SyslogSink) Send(ctx context.Context, records []Record) error {
	msgs := make([]syslog.Message, 0, len(records))
	for _, r := range records {
		body := CEF(r)
		if s.Format == FormatJSON {
			b, err := json.Marshal(r.OCSF)
			if err != nil {
				return fmt.Errorf("syslog: encode record: %w", err)
			}
			body = string(b)
		}
		msgs = append(msgs, syslog.Message{
			Time: r.Time(), Facility: syslog.FacilityAuthPriv, Severity: syslogSeverity(r.OCSF),
			Hostname: "altiward", AppName: "altiward", MsgID: r.Type(), Body: body,
		})
	}
	return s.Client.Send(ctx, msgs)
}

func syslogSeverity(r ocsf.Record) int {
	switch r["severity_id"] {
	case ocsf.SeverityHigh:
		return syslog.SeverityError
	case ocsf.SeverityMedium:
		return syslog.SeverityWarning
	case ocsf.SeverityLow:
		return syslog.SeverityNotice
	}
	return syslog.SeverityInfo
}

// cefSeverity maps OCSF severity onto CEF's 0–10 scale: Low 0–3, Medium 4–6, High 7–8.
var cefSeverity = map[int]int{
	ocsf.SeverityInformational: 1, ocsf.SeverityLow: 3, ocsf.SeverityMedium: 5, ocsf.SeverityHigh: 8,
}

// CEF renders one record as
//
//	CEF:0|Altiward|Altiward|<agent version>|<signature>|<name>|<severity>|<extensions>
//
// The signature is the finding's analytic (altiward.tamper.code_signature, …) or else the
// event type, so SIEM rules can key on it; the name is the finding's title or the OCSF type.
//
// A console action has the "console." event type as its signature, and the actor as suser.
func CEF(r Record) string {
	if r.Audit != nil {
		return auditCEF(r)
	}
	o, e := r.OCSF, r.Event
	signature, name := string(e.Type), str(o["type_name"])
	if f, ok := o["finding_info"].(map[string]any); ok {
		if a, ok := f["analytic"].(map[string]any); ok && str(a["name"]) != "" {
			signature = str(a["name"])
		}
		if t := str(f["title"]); t != "" {
			name = t
		}
	}
	version := e.Device.AgentVersion
	if version == "" {
		version = "0"
	}
	severity, _ := o["severity_id"].(int)

	var ext []string
	add := func(key, value string) {
		if value != "" {
			ext = append(ext, key+"="+cefValue(value))
		}
	}
	custom := func(n int, label, value string) {
		if value != "" {
			add(fmt.Sprintf("cs%dLabel", n), label)
			add(fmt.Sprintf("cs%d", n), value)
		}
	}
	add("rt", fmt.Sprint(e.Timestamp.UnixMilli()))
	add("externalId", r.UID())
	add("cat", str(o["class_name"]))
	add("act", str(o["activity_name"]))
	add("outcome", str(o["status"]))
	add("dvchost", e.Device.Serial)
	add("deviceExternalId", e.Device.HardwareUUID)
	add("suser", actorName(r))
	if e.User != nil {
		user := e.User.LocalName
		if e.User.UPN != nil {
			user = *e.User.UPN
		}
		add("duser", user)
	}
	add("msg", str(o["message"]))
	custom(1, "tenant", r.TenantID)
	if e.SessionID != nil {
		custom(2, "sessionId", *e.SessionID)
	}
	if e.Elevation != nil {
		if e.Elevation.Reason != nil {
			custom(3, "reason", *e.Elevation.Reason)
		}
		custom(4, "source", string(e.Elevation.Source))
	}
	if f, ok := o["finding_info"].(map[string]any); ok {
		custom(5, "findingUid", str(f["uid"]))
	}
	if e.Type == event.AgentEnrollment {
		custom(5, "target", str(e.Detail["device_id"]))
	}
	custom(6, "eventType", string(e.Type))

	return fmt.Sprintf("CEF:0|Altiward|Altiward|%s|%s|%s|%d|%s",
		cefHeader(version), cefHeader(signature), cefHeader(name), cefSeverity[severity], strings.Join(ext, " "))
}

func auditCEF(r Record) string {
	o, a := r.OCSF, r.Audit
	severity, _ := o["severity_id"].(int)
	var ext []string
	add := func(key, value string) {
		if value != "" {
			ext = append(ext, key+"="+cefValue(value))
		}
	}
	add("rt", fmt.Sprint(a.At.UnixMilli()))
	add("externalId", a.ID)
	add("cat", str(o["class_name"]))
	add("act", a.Action)
	add("outcome", str(o["status"]))
	add("suser", a.Actor)
	add("dvchost", str(a.Detail["serial"]))
	add("duser", str(a.Detail["user"]))
	add("msg", str(o["message"]))
	add("cs1Label", "tenant")
	add("cs1", r.TenantID)
	if id := str(a.Detail["session_id"]); id != "" {
		add("cs2Label", "sessionId")
		add("cs2", id)
	}
	add("cs5Label", "target") // events use cs5 for a finding; console actions have none
	add("cs5", a.Target)
	add("cs6Label", "eventType")
	add("cs6", r.Type())
	return fmt.Sprintf("CEF:0|Altiward|Altiward|0|%s|%s|%d|%s",
		cefHeader(r.Type()), cefHeader(str(o["type_name"])), cefSeverity[severity], strings.Join(ext, " "))
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

var (
	headerEscaper = strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\r", " ", "\n", " ")
	valueEscaper  = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r", `\r`, "\n", `\n`)
)

// cefHeader escapes a header field; CEF headers can't hold a line break, so it becomes a space.
func cefHeader(s string) string { return headerEscaper.Replace(s) }

// cefValue escapes an extension value.
func cefValue(s string) string { return valueEscaper.Replace(s) }
