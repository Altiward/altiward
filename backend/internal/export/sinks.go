package export

import (
	"context"

	"github.com/Altiward/altiward/integrations/sentinel"
	"github.com/Altiward/altiward/integrations/splunk"
)

// SplunkSink sends each record as one HEC event with sourcetype altiward:ocsf.
type SplunkSink struct {
	Client *splunk.Client
	Index  string
}

func (s *SplunkSink) Name() string { return "splunk" }

func (s *SplunkSink) Send(ctx context.Context, records []Record) error {
	events := make([]splunk.Event, 0, len(records))
	for _, r := range records {
		events = append(events, splunk.Event{
			Time:       float64(r.Time().UnixMilli()) / 1000,
			Host:       r.Host(),
			Source:     "altiward",
			SourceType: "altiward:ocsf",
			Index:      s.Index,
			Event:      r.OCSF,
		})
	}
	return s.Client.Send(ctx, events)
}

// SentinelSink sends rows shaped for the AltiwardOCSF_CL table (integrations/sentinel/README.md).
type SentinelSink struct {
	Client *sentinel.Client
}

func (s *SentinelSink) Name() string { return "sentinel" }

func (s *SentinelSink) Send(ctx context.Context, records []Record) error {
	rows := make([]any, 0, len(records))
	for _, r := range records {
		row := sentinel.Row{
			TimeGenerated: r.Time(),
			EventUid:      r.UID(),
			TenantUid:     r.TenantID,
			ClassUid:      r.OCSF["class_uid"].(int),
			ActivityId:    r.OCSF["activity_id"].(int),
			SeverityId:    r.OCSF["severity_id"].(int),
			DeviceSerial:  r.Event.Device.Serial,
			Message:       r.OCSF["message"].(string),
			Ocsf:          r.OCSF,
		}
		if r.Event.SessionID != nil {
			row.SessionUid = *r.Event.SessionID
		}
		if r.Event.User != nil {
			row.UserName = r.Event.User.LocalName
		}
		if row.UserName == "" {
			row.UserName = actorName(r)
		}
		if r.Audit != nil {
			row.UserName = r.Audit.Actor
			row.DeviceSerial, _ = r.Audit.Detail["serial"].(string)
		}
		rows = append(rows, row)
	}
	return s.Client.Upload(ctx, rows)
}

// actorName is the OCSF actor, such as an enrolment token's fingerprint.
func actorName(r Record) string {
	actor, _ := r.OCSF["actor"].(map[string]any)
	user, _ := actor["user"].(map[string]any)
	return str(user["name"])
}
