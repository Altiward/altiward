# Security assurance

This argument connects Altiward's intended protections to its design and tests. It is
not an independent security audit. The [agent design notes](../agent/README.md#design-notes),
[architecture](architecture.md) and [data-handling promise](data-handling.md) provide the
detailed contracts and limitations.

## Threats and trust boundaries

The logged-in user can invoke the hook with arbitrary arguments. Network callers can
send arbitrary requests or replay captured requests. A stolen enrollment token can be
used to propose device identities, and a device key copied from a backup may be reused.
Console users have different authorized roles. Networks, identity providers and SIEMs
can fail while events and commands are in flight.

The hook-to-root-daemon boundary, the Mac-to-server boundary, the console-to-API boundary
and the API-to-storage/export boundary each enforce their own checks. Neither a console
control nor a hook-supplied value is an authorization decision.

| Protection | Enforcement and evidence |
| --- | --- |
| Hook claims do not become observed facts | The daemon verifies the real admin group and supplies timestamps; see the agent design notes and `agent/Tests/AltiwardCoreTests/`. |
| Device requests need an enrolled identity | Device authentication verifies signatures and replay constraints; see `backend/internal/auth/`, its tests and fuzz targets. Enrollment limits and replacement approval are checked by `backend/internal/api/`. |
| Reused old device keys are detectable | Agent and server rotation tests cover key continuity, contests and revocation; the shared vectors in `docs/schema/` are decoded by both sides. |
| Console permissions are enforced on the server | Console routes declare a role, cookie mutations require CSRF checks, and mutations record an audit entry transactionally; see `backend/internal/api/` and its authorization/audit tests. |
| Network and sink outages delay delivery | Agent and export outboxes retain unacknowledged events and use event IDs for idempotence; see the delivery, store and export tests. |
| Upgrade contracts remain testable | Schema compatibility fixtures and tests retain supported agent formats; store migrations are append-only and are tested from previous migration states. |
| Release downloads can be authenticated | Release workflows verify Apple signatures where applicable, signed checksums and build provenance; see [releasing](releasing.md) and [checking a release](install.md#checking-a-release). |

## Security limits

A person controlling root on a Mac can interfere with the agent or its evidence; this
is oversight and enforcement alongside MDM, not protection against a fully compromised
operating system. A shared enrollment token does not establish that a first enrollment
belongs to the physical Mac whose serial it claims. Inventory verification and enrollment
approval remain operational responsibilities.

A server administrator controls the server and its database. Off-host SIEM delivery helps
retain evidence but does not make locally stored history immutable. Compromised maintainer
or release infrastructure can compromise software delivery. The current single-maintainer
process does not guarantee independent human review of every change.

Schema validation, bounds, authorization tests, fuzzing and CodeQL provide complementary
checks for common implementation errors. They do not prove the absence of vulnerabilities.
Report suspected failures through the organization's
[security policy](https://github.com/Altiward/.github/blob/main/SECURITY.md), rather than
posting exploit details in a public issue. Reassess this argument when a trust boundary,
collection promise, enrollment mechanism or release process changes.
