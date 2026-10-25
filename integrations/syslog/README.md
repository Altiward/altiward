# Syslog and CEF

For SIEMs that take syslog: QRadar, ArcSight, LogRhythm, Elastic, Graylog, or a relay such
as rsyslog or syslog-ng. Each event is one RFC 5424 message over TLS (RFC 5425), or plain
TCP if you turn TLS off. The body is ArcSight CEF by default, or the OCSF record as JSON.

There is no UDP: a lost datagram would be a lost event. Syslog has no acknowledgement, so
a batch counts as delivered once it is written and the connection closed cleanly. A
failed batch is retried whole, so a receiver can see a message twice; use `externalId`
(the event ID) to drop repeats.

## Setup

| Variable | Default | |
| --- | --- | --- |
| `ALTIWARD_SYSLOG_ADDR` | None | `host:port` of the receiver. Enables the sink. 6514 is the usual TLS port. |
| `ALTIWARD_SYSLOG_TLS` | `true` | `false` sends plain TCP. Use it only on a network you trust. |
| `ALTIWARD_SYSLOG_CA_FILE` | system roots | PEM file of the CA that signed the receiver's certificate |
| `ALTIWARD_SYSLOG_FORMAT` | `cef` | `cef`, or `json` for the OCSF record |
| `ALTIWARD_SYSLOG_FRAMING` | `octet` | `octet` (length prefix, RFC 6587), or `newline` for receivers that read lines |

The receiver's certificate must match the host in `ALTIWARD_SYSLOG_ADDR`.

## Message

```
<84>1 2026-10-17T09:00:00.123Z altiward altiward - elevation.granted - CEF:0|Altiward|Altiward|0.1.0|elevation.granted|User Access Management: Assign Privileges|1|rt=… externalId=… …
```

- **Facility** `authpriv` (10). **Severity** follows OCSF: High → err, Medium → warning,
  Low → notice, Informational → info.
- **MSGID** is the Altiward event type, such as `elevation.granted`, `agent.tamper` or
  `admin.permanent_use`,
  or `console.` and the action for a console action, such as `console.revoke_device`.

## CEF fields

Header: `CEF:0|Altiward|Altiward|<agent version>|<signature>|<name>|<severity>|`.

- **Signature** is the finding's analytic for detections (`altiward.admin_out_of_band`,
  `altiward.rights_after_expiry`, `altiward.tamper.<check>`, `altiward.agent_silent`,
  and so on). Otherwise it is the event type, such as `agent.enrollment`. Write rules
  against it.
- **Name** is the finding's title, or the OCSF type, such as
  `User Access Management: Assign Privileges`.
- **Severity** is 1 (Informational), 3 (Low), 5 (Medium) or 8 (High).

| Key | Value |
| --- | --- |
| `rt` | When it happened, epoch milliseconds |
| `externalId` | Unique per record: the event ID. A second record from one event adds `/finding`: the finding of an `elevation.expired_enforced`, and the Close of the out-of-band finding when the rights were removed. Each new account a persistence event found adds `/account/<name>` |
| `cat`, `act`, `outcome` | OCSF class, activity and status |
| `dvchost` | The Mac's serial number |
| `deviceExternalId` | The Mac's hardware UUID |
| `duser` | The user's UPN, or their short name |
| `msg` | A sentence describing the event |
| `cs1` `tenant` | Tenant |
| `cs2` `sessionId` | Elevation session, so the grant, revoke and alerts of one session group together |
| `cs3` `reason` | The reason the user gave |
| `cs4` `source` | `privileges` or `out_of_band` |
| `cs5` `findingUid` | Pairs a finding with the event that resolves it (tamper checks, silent Macs, admin rights nobody granted) |
| `cs6` `eventType` | Altiward event type |

Console actions (event types `console.revoke_session`, `console.revoke_device`,
`console.approve_enrollment`, `console.revoke_enrollment`, `console.change_settings`,
`console.test_export`, `console.retry_exports` and `console.end_console_session`) have
the event type as their signature and `API Activity: Create`, `Update` or `Delete` as
their name, with the agent version `0`. They carry `suser` (who did it: a person's email
with single sign-on, otherwise `token:` or `break-glass:` and a console token's
fingerprint), `act` (the action), `cs5` `target` (the session, serial, enrollment ID,
`settings`, `exports` for a test event, the sink retried, or the person whose sign-in was
ended) and, where they apply, `dvchost`, `duser` and `cs2`. Console sign-ins and
sign-outs are OCSF Authentication records, with the event types `console.sign_in` and
`console.sign_out`.

## Starter rules

- **Admin rights nobody granted:** signature `altiward.admin_out_of_band` with `act=Create`.
  The matching `act=Close` with the same `cs5` explains them only with `outcome=Resolved`
  (the account became a permanent admin) or `outcome=Replaced by a Privileges grant`. A
  Close with `outcome=Rights removed` means the rights were taken away, by Altiward, from
  the console or by someone on the Mac, but nobody explained them: keep alerting on it.
- **New local account:** signature `altiward.account_created`, named "Admin account
  created" (severity 8) or "Local account created" (severity 5).
- **Rights after expiry:** signature `altiward.rights_after_expiry`, raised whether or not
  Altiward removed them. Severity 8 means it couldn't.
- **Tampering:** signature starting `altiward.tamper.` with `act=Create`. The matching
  `act=Close` with the same `cs5` means it was fixed.
- **Keys enrolled:** signature `agent.enrollment`, named `API Activity: Create`. Severity 1
  is a Mac's first key, 5 a new key waiting for approval and 8 a key that replaced the
  previous one without approval. Alert on 5 and 8. `dvchost` is the serial, `deviceExternalId`
  the hardware UUID the Mac claimed, and `msg` says which of the three it was.
- **Macs that stopped checking in:** signature `altiward.agent_silent`. The Mac checking in
  again sends `act=Close` with the same `cs5`.
- **Use of a permanent admin account:** signature `admin.permanent_use`. `act=Logon` is a
  sign-in, an approval or screen sharing, and `act=Logoff` is the Mac seeing a sign-in end.
  `duser` is the account and `msg` says how it was used.
- **Settings changes:** signature `console.change_settings`.
- **Break-glass token use:** `suser` starting `break-glass:`.
