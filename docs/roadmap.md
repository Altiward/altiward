# Roadmap

Planning horizon: October 2026 through October 2027. These are priorities and scope,
not promised delivery dates. The [issue tracker](https://github.com/Altiward/altiward/issues)
records designs, dependencies, decisions and progress. Work that needs a vendor account,
hardware, an entitlement or demonstrated user demand remains conditional on that access
or evidence.

## Priorities

- Keep the agent's verified view of the Mac's admin group, signed event delivery, key
  rotation and revocation reliable. Preserve upgrade compatibility and improve tests
  around these trust boundaries.
- Extend identity mapping and sign-out integration to Okta, as Entra ID has, once a test
  org is available. Track the designs in
  [Platform SSO with Okta](https://github.com/Altiward/altiward/issues/181),
  [Okta user identity](https://github.com/Altiward/altiward/issues/182) and
  [Okta sign-out](https://github.com/Altiward/altiward/issues/183).
- Evaluate Jamf Pro and Kandji inventory and deployment integration when there are
  accounts to test against; see [inventory checks](https://github.com/Altiward/altiward/issues/178)
  and [Jamf profile deployment](https://github.com/Altiward/altiward/issues/180).
- Maintain usable Compose, Azure and MDM deployment paths, improve release verification
  and dependency monitoring, and work through the [Silver evidence gaps](openssf-silver.md).
- Maintain SIEM delivery and mappings. Additional SIEM content depends on access to the
  target product and an integration that can be tested.

## Scope and limits

Altiward oversees and removes admin rights; it does not grant them or replace SAP
Privileges. It remains self-hosted, with data collection and transfer described in
[data handling](data-handling.md). Changes to that promise require documentation and
release notes in the same change.

Multi-organisation hosting, Kubernetes packaging and broader persistence monitoring
remain demand-driven proposals rather than committed work. Recording `sudo`, `su` and
SSH file copies depends on Apple's Endpoint Security entitlement. Neither this roadmap
nor a badge claims those capabilities are available today.

Server and agent versions follow the [release and support policy](releasing.md#versions).
Changes must preserve the published schema and upgrade contracts. Revisit this roadmap
when priorities or prerequisites change and extend its planning horizon before it expires.
