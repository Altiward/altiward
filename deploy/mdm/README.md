# Mac configuration templates

Deploy these through your MDM with the signed agent package. Follow
[Deploy the agent](../../docs/install.md#2-deploy-the-agent) for the order and settings.

| Template | Purpose |
| --- | --- |
| [`com.altiward.agent.plist`](com.altiward.agent.plist) | Server address, enrollment token, permanent admins and agent policy |
| [`altiward-login-items.mobileconfig`](altiward-login-items.mobileconfig) | Mark the agent as a managed background item |
| [`corp.sap.privileges.plist`](corp.sap.privileges.plist) | Keys to add to the existing SAP Privileges profile |

The Privileges file here is a **source template**. Its checksum placeholder must be
replaced with the checksum of the signed hook. Use `corp.sap.privileges.plist` from the
**same agent release as the package**: the package builder fills it in after signing.
Update that profile with every agent package rollout. A mismatched checksum prevents
Privileges from running the hook.

The server bundle includes the agent and login items templates under `profiles/`. It
leaves out the Privileges template, because only the agent release knows its hook's
checksum. Agent installer scripts and LaunchDaemon resources live in `agent/packaging/`.
