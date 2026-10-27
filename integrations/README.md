# SIEM integrations

Reusable Go transport clients used by `backend/internal/export`:

| Directory | Client |
| --- | --- |
| [`splunk/`](splunk/) | Splunk HTTP Event Collector |
| [`sentinel/`](sentinel/) | Azure Monitor Logs Ingestion, with client-secret, certificate or managed-identity authentication |
| [`syslog/`](syslog/) | Syslog over TLS or TCP, with CEF or OCSF JSON bodies |

These packages have their own Go module, `github.com/Altiward/altiward/integrations`,
so other applications can use the transports without importing the server's internals.
Run `go test ./...` from this directory, or `make backend-test` from the repository root.

## Setup and SIEM content

The provider READMEs describe connection settings and troubleshooting. Azure resource
provisioning is owned by [`deploy/sentinel/`](../deploy/sentinel/). The Splunk dashboard
and the Sentinel workbook remain beside the provider guides and ship in the server bundle;
detection rules and searches are in [altiward-siem](https://github.com/Altiward/altiward-siem). Their eventual companion-repository boundary is described in
[the architecture guide](../docs/architecture.md#siem-boundaries).

The server maps events to OCSF in `backend/internal/ocsf`. Console audit actions also
export as OCSF API Activity (`class_uid` 6003), with event type `console.<action>`. So
does `agent.enrollment`, which the server raises when a Mac enrols a key, as activity
Create. Its severity says which state it is: Informational for `enrolled`, Medium (an
alert) for `pending` and High (an alert) for `replaced`. Key rotation is API Activity too,
with `api.operation` `rotate` and the Mac as the actor: `rotated` is Update and Informational,
and `rotated_key_used` (a key that rotation had already replaced signed a request) is
"Stale key used", status Failure, High and an alert. In CEF, rules key on the
signature `agent.enrollment` and the severity ([syslog](syslog/README.md#starter-rules)).
`ocsf-examples/`: the server's OCSF output for sample events (and altiward-siem's
fixtures), kept current by
`TestGoldenExamples` (`go test ./backend/internal/ocsf -run Golden -update` rewrites it).
Planned MDM and identity-provider integrations are on the
[roadmap](https://github.com/orgs/Altiward/projects/1).
