package sentinel

import "time"

// Row is one record of the Custom-AltiwardOCSF stream, which the data collection rule routes
// into the AltiwardOCSF_CL table. The Altiward server and altiward-forwarder both upload it,
// so their events land in the same table.
type Row struct {
	TimeGenerated time.Time `json:"TimeGenerated"`
	EventUid      string    `json:"EventUid"`
	TenantUid     string    `json:"TenantUid"`
	SessionUid    string    `json:"SessionUid"`
	ClassUid      int       `json:"ClassUid"`
	ActivityId    int       `json:"ActivityId"`
	SeverityId    int       `json:"SeverityId"`
	DeviceSerial  string    `json:"DeviceSerial"`
	UserName      string    `json:"UserName"` // for a console action, who did it
	Message       string    `json:"Message"`
	Ocsf          any       `json:"Ocsf"` // the whole OCSF record
}

// Columns is Row as the stream declares it, in the Name:type form deploy/sentinel/setup.sh
// uses. Tests keep Row, Columns and setup.sh in step.
const Columns = "TimeGenerated:datetime EventUid:string TenantUid:string SessionUid:string ClassUid:int " +
	"ActivityId:int SeverityId:int DeviceSerial:string UserName:string Message:string Ocsf:dynamic"
