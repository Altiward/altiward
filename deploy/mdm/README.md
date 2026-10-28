# Mac configuration templates

Deploy these through your MDM with the signed agent package. Follow
[Deploy the agent](../../docs/install.md#2-deploy-the-agent) for the order and settings.

| Template | Purpose |
| --- | --- |
| [`com.altiward.agent.plist`](com.altiward.agent.plist) | Server address, enrollment token, permanent admins and agent policy |
| [`com.altiward.agent.mobileconfig`](com.altiward.agent.mobileconfig) | The same agent settings as a ready-made profile |
| [`altiward-login-items.mobileconfig`](altiward-login-items.mobileconfig) | Mark the agent as a managed background item |
| [`corp.sap.privileges.plist`](corp.sap.privileges.plist) | Keys to add to the existing SAP Privileges profile |
| [`corp.sap.privileges.mobileconfig`](corp.sap.privileges.mobileconfig) | The same keys as a ready-made profile |

Each `.mobileconfig` is a complete configuration profile for an MDM that takes one, such
as Intune's Custom profile (Jamf Pro takes them too). Each carries the same keys and
values as its plist, and a test keeps them so (`go test ./deploy/mdm`). Their identifiers and UUIDs are fixed, so uploading an edited
copy again replaces the profile on the Mac rather than adding a second. In
`com.altiward.agent`, `MDMDeviceID` is `{{deviceid}}`, which Intune replaces with the
Mac's device ID. Another MDM needs its own variable there. The agent sends it once, when
the Mac enrols, and with Intune connected the server checks it against Intune (agents
before 1.2.0 ignore the key).

The Privileges files here are **source templates**. Their checksum placeholder must be
replaced with the checksum of the signed hook. Use `corp.sap.privileges.plist` or
`corp.sap.privileges.mobileconfig` from the **same agent release as the package**: the
package builder fills them in after signing. Update that profile with every agent
package rollout. A mismatched checksum prevents Privileges from running the hook.
Privileges reads one profile for its domain, so if you already have one, add the keys to
it rather than deploying the second profile as well.

The server bundle includes the agent and login items templates under `profiles/`. It
leaves out the Privileges templates, because only the agent release knows its hook's
checksum. Agent installer scripts and LaunchDaemon resources live in `agent/packaging/`.
To upload these profiles to Intune with one command, see
[`deploy/intune`](../intune/README.md).
