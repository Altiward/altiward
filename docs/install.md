# Installing Altiward

This guide takes you from nothing to Macs reporting to your own Altiward server. You run
the server; the Altiward project never receives your data. For your security review,
[data handling](data-handling.md) lists what Altiward stores and where data goes.

To look around before you install, the
[demo](https://github.com/Altiward/altiward/blob/main/dev/README.md#try-the-console-with-demo-data)
runs the console with example data on your own computer, needing only Docker.

## What you're installing

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/overview-dark.svg">
  <img src="images/install/overview-light.svg" width="1000" alt="Your MDM installs the Altiward agent and its profiles on each Mac. SAP Privileges grants admin rights and reports each change to the agent through its hook. The agent reports over HTTPS on port 443 to the agent hostname; IT staff open the console hostname over HTTPS on port 443 from allowed networks. On your server, Caddy handles TLS for both hostnames, getting certificates over port 80, and passes requests to Altiward, the API and console. Altiward stores data in Postgres, sends events to your SIEM (Splunk, Microsoft Sentinel or syslog over TLS) and signs people in through Entra ID or Okta.">
</picture>

- **The agent** runs on each Mac as a background service, installed by your MDM. It works
  alongside SAP Privileges, which grants admin rights: it records every grant and revoke
  Privileges reports, checks them against the real `admin` group, and sends events to
  your server. It never grants admin itself.
- **The server** is one container serving the API and the web console, with Postgres for
  storage and Caddy in front for TLS.
- **Two hostnames.** Macs report to the *agent hostname*, which must be reachable from
  the internet so laptops can report from home and on the road. Only the agent endpoints
  answer there. Anything between the Macs and the server, such as a firewall, web filter
  or TLS-inspecting proxy, must pass the whole of `/v1/agent/` to the server unaltered,
  including `/v1/agent/rotate`, which agent 1.0 uses to replace its key. People use the
  *console hostname*, which only accepts connections from the networks you list. On Azure
  Container Apps, one address serves both, split by path, with the same rule.

## Choose how to run it

Altiward is the same software however you run it. Pick the setup that
matches what you already have:

| | The bundle | Your own infrastructure | Azure Container Apps |
| --- | --- | --- | --- |
| For | A site that wants Altiward to bring everything it needs | A site with a managed database and its own load balancer or certificates | A site on Azure that wants no server or VM to look after |
| Database | Postgres in the bundle, backed up by you ([Backups](#backups)) | Your managed Postgres ([An existing Postgres](#an-existing-postgres)) | Azure Database for PostgreSQL on a private network, with Azure's backups |
| TLS | Caddy, with certificates from Let's Encrypt | Your certificates or load balancer ([Your own certificates or load balancer](#your-own-certificates-or-load-balancer)) | The Container Apps ingress, on its own address or your domain |
| Steps | This guide as written | This guide, plus the sections linked here | [Deploy to Azure](../deploy/azure/README.md), then this guide from step 2 |

The bundle and your own infrastructure use the same image and the same `deploy/compose`
files, so you can move from one to the other later without reinstalling. Deploy to Azure
runs the same image, set up by a template, with settings on the container app instead of
in `.env`: wherever this guide says to set something in `.env` and run
`docker compose up -d`, set it on the container app instead
([Changing settings](../deploy/azure/README.md#changing-settings)). If you run Kubernetes,
[open an issue](https://github.com/Altiward/altiward/issues): manifests or a Helm chart
come when someone needs them.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAltiward%2Faltiward%2Fserver-v1.0.0%2Fdeploy%2Fazure%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FAltiward%2Faltiward%2Fserver-v1.0.0%2Fdeploy%2Fazure%2FcreateUiDefinition.json) ([what it creates](../deploy/azure/README.md))

## Before you start

You need:

- **A Linux server or VM** with Docker Engine and the Docker Compose plugin. As a starting
  point, not a measured requirement: 2 vCPUs, 4 GB of memory and 20 GB of disk. Altiward
  keeps every event for now, so watch disk use as your fleet grows.
- **Two DNS names** pointing at the server, for example `altiward-agents.example.com`
  and `altiward.example.com`.
- **Ports 80 and 443** reachable on the server from the internet, so Caddy can get
  certificates and Macs can report. To keep the server off the internet, see
  [Your own certificates or load balancer](#your-own-certificates-or-load-balancer).
- **Macs on macOS 14 or later**, Apple silicon or Intel, with SAP Privileges 2.5 or later
  and its system extension on. With Privileges 2.6 or later, the agent also confirms each
  grant against Privileges' own log
  ([Claims made by running the hook by hand](#claims-made-by-running-the-hook-by-hand)).
- **Your MDM** (Jamf Pro, Intune, Kandji, Mosyle or similar) to install the package and
  configuration profiles.
- **From [GitHub Releases](https://github.com/Altiward/altiward/releases):** a server
  release and an agent release. A server
  release is the bundle (`altiward-server-<version>.tar.gz`, holding the deployment files
  in `deploy/compose/`, this guide, the SIEM guides and Sentinel's setup script in
  `integrations/`, and the agent's example Mac profiles in `profiles/`), the server image
  as a file for your platform (`altiward-api-<version>-linux-amd64.tar.gz` or `…-arm64`),
  `RELEASE_NOTES.md`, `SHA256SUMS` and its signature, `SHA256SUMS.sigstore.json`. An
  agent release is the signed package
  (`Altiward-<version>.pkg`), the SAP Privileges keys pinned to that package's hook
  (`corp.sap.privileges.plist`), and its own notes and checksums. Server releases are tagged
  `server-vX.Y.Z` and agent releases `agent-vX.Y.Z`. Nothing needs an account.

## 1. Start the server

On the server, download the server release into a directory of its own. Set `v` to the
release's version, and on an Arm server use `arm64` in place of `amd64`:

```sh
v=<version>
mkdir ~/altiward-$v && cd ~/altiward-$v
for f in altiward-server-$v.tar.gz altiward-api-$v-linux-amd64.tar.gz \
    RELEASE_NOTES.md SHA256SUMS SHA256SUMS.sigstore.json; do
  curl -fsSLO "https://github.com/Altiward/altiward/releases/download/server-v$v/$f"
done
```

Check the files ([Checking a release](#checking-a-release)), then load the image, unpack
the bundle and copy its deployment files to the directory the server runs from, such as
`/opt/altiward`. Keep the server in that directory: upgrades work in it, whatever version
it runs. (The image is also public at `ghcr.io/altiward/altiward-api`, pulled without
logging in: skip `docker load` and `docker compose up -d` below pulls it.)

```sh
docker load -i altiward-api-$v-linux-amd64.tar.gz
tar xzf altiward-server-$v.tar.gz
sudo mkdir /opt/altiward && sudo chown "$(id -un)" /opt/altiward
cp -R altiward-server-$v/deploy/compose/. /opt/altiward/
cd /opt/altiward
```

In that directory, holding `compose.yaml`, `Caddyfile` and `env.example`:

```sh
cp env.example .env
chmod 600 .env
```

Edit `.env`. `ALTIWARD_VERSION` is already set to the release you downloaded.

| Setting | What to put |
| --- | --- |
| `ALTIWARD_AGENT_HOST`, `ALTIWARD_CONSOLE_HOST` | Your two hostnames |
| `ALTIWARD_CONSOLE_ALLOW` | The networks allowed to open the console, space separated, for example your office and VPN ranges |
| `POSTGRES_PASSWORD` | A new random value: `openssl rand -hex 24` |
| `ALTIWARD_AGENT_TOKENS` | `yourcompany=` followed by a new random value from `openssl rand -hex 32`. It goes into the Mac profile. |
| `ALTIWARD_CONSOLE_TOKENS` | `yourcompany=` followed by a different value from `openssl rand -hex 32`. People sign in to the console with it until you set up single sign-on ([step 5](#5-sign-in-with-your-identity-provider)); after that it is a break-glass login. |

Use the same organisation name in both token settings.

You can give each group of Macs its own agent token, one per MDM profile, listed comma
separated: `yourcompany=<first>,yourcompany=<second>`. **Enrollments** shows which token
each key enrolled with, so if one leaks you change only that group's profile and can find
the keys it made.

Then start everything:

```sh
docker compose up -d
docker compose ps        # all three services should be running
```

Caddy gets certificates for both hostnames within a minute. Open
`https://<console hostname>` from an allowed network and sign in with the console token.
The Fleet view is empty until the first Mac reports.

**You should see** the sign-in page, with a padlock in the address bar. A certificate
warning, or no page at all, is a Caddy problem: see
[Caddy certificate errors](#caddy-certificate-errors).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/sign-in-token-dark.png">
  <img src="images/install/sign-in-token-light.png" width="400" alt="The Altiward sign-in page, asking for the console token.">
</picture>

## 2. Deploy the agent

Create these in your MDM and scope them to a pilot group first.

1. **Configuration profile for `com.altiward.agent`**, from the example
   `com.altiward.agent.plist`. Set at least:
   - `ServerURL`: `https://<agent hostname>`
   - `EnrollmentToken`: the token after `yourcompany=` in `ALTIWARD_AGENT_TOKENS`
   - `PermanentAdmins`: accounts that should always be admins, such as your IT or
     break-glass accounts. Altiward never flags or removes them. Include the local
     admin account your MDM manages with LAPS (Jamf Pro's managed local administrator,
     or the macOS local admin account Intune creates at enrollment): enter the short name
     you set in the MDM, exactly. Left out, it shows in the console as an admin nobody
     granted, revoking every admin on a Mac would remove its rights too, and with
     `OutOfBandEnforcement` set to `enforce` Altiward removes them itself. Altiward
     records each sign-in, prompt approval and screen sharing connection by these accounts
     (`sudo`, `su` and SSH file copies wait for Apple's Endpoint Security entitlement;
     [what it records](data-handling.md)); the MDM records who
     looked up the password.

     > **Warning:** With `OutOfBandEnforcement` set to `enforce`, every admin nobody
     > granted loses their rights within minutes, including the LAPS account your MDM
     > manages if it isn't in `PermanentAdmins`. Read [Enforcement](#enforcement) before
     > turning it on.

   The example explains every other key. Two of them let the agent act, not only report:
   `ExpiryEnforcement`, for rights that outlive the expiry Privileges set, and
   `OutOfBandEnforcement`, for admin rights nobody granted. Both default to `alert`, which
   only reports. Keep them there for the pilot ([Enforcement](#enforcement)).

   Deliver the profile through MDM rather than `defaults write`: Altiward reports
   `ServerURL`, `PermanentAdmins`, `ExpiryEnforcement`, `ExpiryGraceMinutes`,
   `OutOfBandEnforcement`, `OutOfBandGraceMinutes` or `HookCodeRequirement` set outside MDM
   as tampering (it doesn't check the other keys).
2. **Login items profile** (`altiward-login-items.mobileconfig`), so people can't turn
   the agent off and don't see a background-item notice.
3. **SAP Privileges:** download `corp.sap.privileges.plist` from the **same agent release
   as the package** and add its keys to your existing Privileges profile. Its checksum
   pins that package's signed hook: Privileges won't run a hook whose checksum doesn't
   match, and Altiward reports *SAP Privileges no longer reports to Altiward* for that
   Mac. The keys set the hook, so Privileges
   reports each change to Altiward, and turn on Privileges' tamper protection
   (`EnableSystemExtension`). That protection is a system extension, which also needs,
   from your MDM: a system extension policy allowing SAP's team `7R5ZEU67FQ` and Full Disk
   Access for `corp.sap.privileges.extension`. SAP's example
   `Example_ApprovePrivileges.mobileconfig` has both. Until it's on and the extension is
   running, Altiward reports *SAP Privileges tamper protection is off* for each Mac.
   We also suggest `ReasonRequired` (and `ReasonMinLength`), if your profile doesn't set them:
   Privileges keeps the reason someone gives only when it requires one, so without it Altiward
   records no reason.

   Privileges lets users change, in its own settings, any setting its profile doesn't set.
   The file sets three that Altiward relies on, and suggests two more. Altiward checks each
   Mac, and shows a failing check in the Mac's details for any that's missing:

   | Setting | In the file | Why | Check |
   |---|---|---|---|
   | `ExpirationIntervalMax` | 60 minutes: use your own policy's value. A fixed `ExpirationInterval` works too, and is stricter | Without a cap, a user can choose to keep admin rights with no expiry, and expiry enforcement has nothing to enforce | **Privileges expiry cap**, medium severity |
   | `AllowPrivilegeRenewal` | `false`. Don't set `AutoRenewalProcessPaths`, which renews whatever this says | Privileges reports a renewal only in a log line from a process the user runs. The agent checks it came from SAP's agent and moves the expiry, but it can't check a line whose process has gone, and then removes renewed rights at the original expiry. With renewals off, it ignores renewal lines altogether | **Privileges renewals off**, medium, only while `ExpiryEnforcement` is `enforce` |
   | `PostChangeActionOnGrantOnly` | `false` | Unset, a user can tick "Run only if administrator privileges have been granted", and Privileges stops telling Altiward when rights are given back | **Privileges reports give-backs**, medium |
   | `RevokePrivilegesAtLogin` with `RevokeAtLoginExcludedUsers` | Suggested, in a comment | Rights never survive a restart | **Privileges spares permanent admins**, medium |
   | `RevokePrivilegesAfterSystemTimeChange` with `RevokeAfterTimeChangeExcludedUsers` (Privileges 2.4.1 or later) | Suggested, in a comment | Nobody can stretch an expiry by setting the clock back | The same check |

   Only values your MDM profile sets count for the first three: a value in
   `/Library/Preferences` is still one the user can change. The two revoke settings aren't
   required, but if you turn either on, its exclusion list must name **every account in
   `PermanentAdmins`** (break-glass, LAPS, your MDM's admin account): Privileges makes any
   other admin a standard user at their next sign-in, or when the clock changes. The file
   leaves them in a comment for that reason, and Altiward fails the check while a list
   leaves a permanent admin out.
4. **The package**, `Altiward-<version>.pkg`. It installs silently, and the agent starts
   at once.

**In Jamf Pro:**

- Agent settings: **Computers › Configuration Profiles › New**, payload **Application &
  Custom Settings › Upload › Add**, preference domain `com.altiward.agent`, then upload your
  edited `com.altiward.agent.plist`.
- Login items: **Computers › Configuration Profiles › Upload**, then
  `altiward-login-items.mobileconfig`.
- The package: add it in **Settings › Computer management › Packages**, then install it
  with a policy (**Computers › Policies**, payload **Packages**, action **Install**).

**In Intune** (the Microsoft Intune admin center):

- Agent settings: **Devices › Manage devices › Configuration › Create › New policy**,
  platform **macOS**, profile type **Templates › Preference file**, preference domain name
  `com.altiward.agent`. Intune wants the keys alone: upload a copy of your edited
  `com.altiward.agent.plist` without the `<?xml`, `<!DOCTYPE` and comment lines, the
  `<plist>` lines and the outermost `<dict>` lines.
- Login items: the same path with **Templates › Custom**, deployment channel **Device
  channel**, then `altiward-login-items.mobileconfig`.
- The package: **Apps › All Apps › Create**, platform **macOS**, type **macOS app (PKG)**.
  That type takes packages that install outside `/Applications`, as Altiward's does.

In any MDM, the SAP Privileges keys go into the profile that already configures
Privileges.

**You should see**, on a pilot Mac, the Altiward profiles under **System Settings ›
General › Device Management**. The Mac then appears in the console ([step 3](#3-check-it-works)).

Each Mac enrols on first contact: it registers its own key with your server and signs
subsequent requests with it. The enrolment token is used for enrolment, including when a
Mac needs a new key because its old one was revoked. (The agent also replaces its own key
from time to time without the token or an approval: see [Key rotation](#key-rotation).)
The token is readable on every Mac, so anyone with it can enrol a key for a serial number. By default,
a new key for a serial that enrolled before waits for approval, including after its earlier
key was revoked. The current key keeps reporting until you approve the replacement.
**Approve Macs that enrol again** should stay on ([step 6](#6-settings-worth-reviewing)).
Turning it off lets anyone with the token replace an enrolled Mac's identity by naming
its serial and hardware UUID. Neither is a secret, and Secure Enclave key protection does
not prevent that replacement.

Approval protects existing serials; the shared token does not verify that a serial enrolling
for the first time belongs to the caller. Check new enrolments against your device inventory,
or turn on **Approve every new Mac** so each Mac's first key waits for approval too.
Stronger first-enrolment assurance needs per-device bootstrap credentials or independently
verified inventory.

If you export to a SIEM, each key that enrols also reaches it as an `agent.enrollment`
event, so you don't have to watch **Enrollments** for new keys; you still approve a key that
waits in **Enrollments**. The event names the Mac, the new key's fingerprint and the token
the Mac enrolled with, and its `state` says what happened:

- `enrolled`: the Mac's first key, or its first after earlier ones were revoked with
  approval off. Check these against your device inventory.
- `pending`: a Mac that already had a key enrolled another, and the new one waits in
  **Enrollments** for your approval. An active earlier key keeps reporting meanwhile.
  Expect it after a reinstall or a replaced logic board. A new key from different hardware
  than the active one always waits, even with approval off
  ([step 6](#6-settings-worth-reviewing)).
- `replaced`: a new key took the place of the active one without approval. It happens
  only with approval off and the same hardware UUID.
- `rotated`: the Mac replaced its own key by rotation, which needs no approval. Expect
  one per Mac when the agent moves a file key into the Secure Enclave, and one every 30
  days from a Mac without one. It is Informational.
- `rotated_key_used`: a key the Mac had already replaced was used again, so two holders
  share one Mac's identity. It is High, and the server has usually revoked the Mac's
  current key. See [A rotated key was used](#a-rotated-key-was-used).

Alert on `pending`, `replaced` and `rotated_key_used`: they are Medium, High and High in
the SIEM, and each means a Mac's key changed or may have been copied. When you didn't
expect one, it may be someone using the enrolment token. For an unexpected `pending` key,
ask the Mac's owner before you approve it. A `replaced` key is already active: turn
**Approve Macs that enrol again** on and revoke the new key in **Enrollments**, and the
genuine Mac then enrols again and waits for your approval. When a key was active before,
the event says whether the new key reported the same hardware UUID
(`hardware_uuid_matches`). The [event schema](schema/README.md) lists its fields, and the
[syslog guide](../integrations/syslog/README.md#starter-rules) has a starter rule.

On a Mac with a Secure Enclave (Apple silicon, or an Intel Mac with a T2 chip) the key is
made in the Secure Enclave, so it can't be copied to another Mac. Other Macs keep it in a
file only root can read.

### Key rotation

The agent replaces its own device key, so a copy of a file key goes stale and no file key
stays in use for ever:

- A file key on a Mac with a Secure Enclave moves into it once the key has been active for
  24 hours and has signed a request since the daemon started. The daemon checks after each
  long poll and at least hourly, so a Mac that enrolled today moves tomorrow. This
  includes Macs that enrolled before agent 0.2.0 and Macs whose Secure Enclave failed at
  enrolment. You no longer revoke a file key to move it; **Enrollments** says the agent
  does it by itself.
- A file key on a Mac without a Secure Enclave is replaced every 30 days.
- A Secure Enclave key is never replaced.

The Mac makes the new key and asks the server to swap it for the old one, proving it holds
both. The server activates the new key and marks the old one **Rotated** in
**Enrollments** (the inspector says "Replaced by rotation on" the date, and the new key
says "Rotated from" the key it replaced). Nothing waits for approval and the enrolment
limits don't apply. A key must have been active for 24 hours before it is replaced.
Revoking a rotated key is refused: revoke the key in use, which the console links to.

Rolling out agent 1.0 therefore adds a `rotated` event and a **Rotated** row for each Mac
whose key moves. A new agent on an older server finds it doesn't support rotation, keeps
its key, and asks again a day later. If the server doesn't answer a rotation, the Mac
keeps both keys and holds its events, which queue on the Mac, until it does. A firewall or
proxy that answers the rotate request with a server error, or drops it, does the same, and
the Mac shows as **Not checking in**. On the Mac, `altiward-agent status` then shows the
rotation in progress and the last answer that kept it waiting:

```
key rotation: in progress since 2026-11-02T09:14:05.112Z; reports wait until the server answers
  last logged 2026-11-02T10:14:20.384Z: HTTP 502: Bad Gateway. If this goes on, check that the whole of /v1/agent/ reaches the server
```

Once `/v1/agent/rotate` reaches the server, the Mac finishes the rotation at its next try
and sends what it held.

## 3. Check it works

Within five minutes of installing, each Mac appears in **Fleet** with its macOS and agent
versions and who is an admin. If one doesn't, see
[A Mac never appears](#a-mac-never-appears).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/fleet-dark.png">
  <img src="images/install/fleet-light.png" width="720" alt="Fleet in the console: a row per Mac with its serial number, last check-in, admins, and macOS, agent and SAP Privileges versions.">
</picture>

Then grant admin to a test user through Privileges. **You should see** the session under
**Sessions**, marked **Elevated** and **Verified**, and the person under **Admins now**.
Select it for the reason they gave, when the rights expire, and its timeline.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/session-granted-dark.png">
  <img src="images/install/session-granted-light.png" width="720" alt="Sessions in the console, with a session selected: Elevated and Verified, its source Privileges, start and expiry times, the reason given, and a timeline with the grant.">
</picture>

Give the rights back in Privileges, or let them expire. The session ends, and its
timeline shows the revoke.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/session-revoked-dark.png">
  <img src="images/install/session-revoked-light.png" width="360" alt="A session's details after the rights were given back: Ended and Verified, the state Ended in Privileges, the time used, and a timeline with Granted then Revoked.">
</picture>

## 4. Connect your SIEM

Altiward sends every event to your SIEM in OCSF format. Set the variables for your SIEM in
`.env` and run `docker compose up -d`. The console's **Settings › SIEM export** gives, for
each SIEM not connected yet, the lines to copy and its setup guide. It only shows them:
SIEM settings stay with the server, so changing where events go takes access to the server,
not just the console. If your SIEM's certificate comes from your own CA,
put the CA's PEM file in `certs/` and set `ALTIWARD_TRUSTED_CAS_FILE` to
`/etc/altiward/certs/<file>`: the server then trusts it alongside the public CAs. For syslog
alone, `ALTIWARD_SYSLOG_CA_FILE` instead trusts only the CA you name.

| SIEM | Settings | Setup |
| --- | --- | --- |
| Splunk | `ALTIWARD_SPLUNK_HEC_URL`, `ALTIWARD_SPLUNK_HEC_TOKEN`, optional `ALTIWARD_SPLUNK_INDEX` | `integrations/splunk/README.md` |
| Microsoft Sentinel | `ALTIWARD_SENTINEL_ENDPOINT`, `_DCR_ID`, `_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET`, which `integrations/sentinel/setup.sh` prints; on an Azure VM or container app, `_AUTH=managed-identity` needs no tenant ID or secret; elsewhere, `_AUTH=certificate` signs in with a certificate instead of a secret | `integrations/sentinel/README.md` |
| Syslog: QRadar, ArcSight, Elastic and others | `ALTIWARD_SYSLOG_ADDR`, optional `_TLS`, `_CA_FILE`, `_FORMAT`, `_FRAMING` | `integrations/syslog/README.md` |

Analytics rules, hunting queries and saved searches for Sentinel and Splunk are in
[altiward-siem](https://github.com/Altiward/altiward-siem).

Altiward sends the events that happen after you connect a SIEM, not the ones from before.
To send earlier ones too, run this after the restart, with the SIEM's sink name (`splunk`,
`sentinel` or `syslog`) and the date to start from. Anything already sent to that SIEM
since then is sent again.

```sh
docker compose exec altiward /usr/local/bin/altiward-api replay-exports sentinel 2026-10-01
```

Events wait in Postgres until your SIEM accepts them, so a SIEM outage delays them
without losing any. The console's Settings shows, for each SIEM, what is waiting and the
last error. An admin can send a test event from there, and retry failed exports at once
after a fix instead of waiting for the next retry, which can be up to an hour away.

**You should see** your SIEM under **Settings › SIEM export** as **Up to date**, with
nothing waiting. **Failing** means the SIEM isn't accepting events: the row shows the
last error, and **Retry now** sends at once after a fix.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/settings-siem-dark.png">
  <img src="images/install/settings-siem-light.png" width="592" alt="Settings, SIEM export: Syslog, Up to date, nothing waiting, with the time of the last delivery, and a button to send a test event. Below, Connect another SIEM, with Splunk and Microsoft Sentinel to expand.">
</picture>

If you stop sending to a SIEM, whatever was still queued for it stays in Postgres, and
diagnostics lists it as a problem. Once you're sure, drop that queue. The events stay in
the database. Use the sink name diagnostics shows (`splunk`, `sentinel` or `syslog`):

```sh
docker compose exec altiward /usr/local/bin/altiward-api drop-exports splunk
```

## 5. Sign in with your identity provider

People can sign in to the console with their Entra ID or Okta account instead of the
console token, with access that follows their groups:

| Role | Can |
| --- | --- |
| Viewer | See everything |
| Operator | Also revoke admin rights |
| Admin | Also approve and revoke enrollments, and change settings |

Someone in groups for several roles gets the highest. Someone in none of them can't sign
in. Activity, and your SIEM, name each person by email.

**Entra ID:**

1. In **App registrations**, create a registration with the platform **Web** and the
   redirect URI `https://<console hostname>/v1/auth/callback`.
2. Under **Certificates & secrets**, create a client secret.
3. Under **Token configuration**, add a groups claim of **Groups assigned to the
   application**, and assign the groups that should use Altiward in **Enterprise
   applications**. Without the "assigned" limit, people in more than 200 groups can't
   sign in.
4. Use the group object IDs in the settings below. The issuer is
   `https://login.microsoftonline.com/<directory ID>/v2.0`.

Or use **app roles** instead of groups, so tokens carry only Altiward's roles and group
counts never matter:

1. In the registration's **App roles**, create three roles for users, with the values
   `Altiward.Admin`, `Altiward.Operator` and `Altiward.Viewer`.
2. In **Enterprise applications**, assign each group (or person) one of those roles.
   Assigning groups needs Entra ID P1 or P2.
3. Set `ALTIWARD_OIDC_GROUPS_CLAIM=roles`, and put the role values where the settings
   below take group IDs: `ALTIWARD_OIDC_ADMIN_GROUPS=Altiward.Admin` and so on.

**Okta:**

1. Create an **OIDC Web Application** with the sign-in redirect URI
   `https://<console hostname>/v1/auth/callback`.
2. Add a **groups** claim to the ID token (filter it to the groups for Altiward) and set
   `ALTIWARD_OIDC_SCOPES=openid email profile groups`.
3. Use the group names in the settings below. The issuer is your Okta org URL, or your
   authorization server's.

Then set these in `.env` and run `docker compose up -d`:

| Setting | Value |
| --- | --- |
| `ALTIWARD_OIDC_ISSUER` | The issuer above |
| `ALTIWARD_OIDC_CLIENT_ID`, `ALTIWARD_OIDC_CLIENT_SECRET` | From the app registration |
| `ALTIWARD_OIDC_ADMIN_GROUPS`, `_OPERATOR_GROUPS`, `_VIEWER_GROUPS` | Groups for each role, comma separated |

If your identity provider's certificate comes from your own CA, set
`ALTIWARD_TRUSTED_CAS_FILE` as for the SIEM (step 4).

The console then shows **Sign in with single sign-on**. Sessions end after 12 hours, or
after an hour unused. A change to someone's groups applies the next time they sign in.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/sign-in-sso-dark.png">
  <img src="images/install/sign-in-sso-light.png" width="400" alt="The sign-in page with single sign-on: a Sign in with single sign-on button, and a link to use a break-glass token instead.">
</picture>

**You should see** yourself under **Settings › Sign-ins** once you've
signed in, with your role. An admin can end someone's sign-in there, so a role change at
your identity provider applies at once.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/settings-signed-in-dark.png">
  <img src="images/install/settings-signed-in-light.png" width="592" alt="Settings, Signed in to the console: two people, each with their email, role, when they signed in and when the sign-in ends, and an End sign-in button.">
</picture>

The console token keeps working as a **break-glass** login, with the admin role, for
when your identity provider is down or misconfigured. Each use shows in Activity and your
SIEM as `break-glass:` and the token's fingerprint, so alert on it. To turn it off, leave
`ALTIWARD_CONSOLE_TOKENS` empty.

## 6. Settings worth reviewing

In the console, under **Settings › General**:

- **Approve Macs that enrol again.** On by default and recommended. A Mac that comes
  back with a new key, for example after a reinstall or after its key was revoked, waits
  in **Enrollments** for your approval. Its earlier active key keeps working until you
  approve the new one. Turning this off allows anyone with the enrolment token to
  replace an enrolled Mac's identity by naming its serial and hardware UUID. A rotation
  ([Key rotation](#key-rotation)) is not an enrolment and never waits for approval, but
  the new enrolment that follows a [rotated key's use](#a-rotated-key-was-used) does.

  Upgrading to server 0.8.0 enables approval once for every existing tenant, including
  tenants where it was off. Existing credentials and the other settings stay as they are.
  An admin can explicitly turn it off after the upgrade if automatic replacement is
  required. An omitted or null approval flag in a settings API update enables approval;
  only an explicit `false` disables it.

  Whatever you choose, a new key whose hardware UUID differs from the Mac's active key waits
  for approval. The hardware UUID is what the agent says about itself, so this catches a key
  made on another Mac, not someone who sets it by hand. **Enrollments** warns when a key
  waiting for approval reports a different hardware UUID, and shows when the Mac last
  checked in with its current key.
- **Approve every new Mac.** Off by default. A Mac's first key waits in **Enrollments** for
  your approval too, so someone with the enrolment token can't add a Mac of their own, or
  enrol a real Mac's serial before that Mac does. It costs one approval for each Mac you roll
  out; until you approve it, a Mac doesn't report. Each key waiting for approval raises an
  `agent.enrollment` event with state `pending`, so a SIEM alerting on those alerts on every
  new Mac while this is on. An omitted flag in a settings API update turns it off.
- **Alert when a Mac stops checking in.** Hours without a check-in before Altiward raises
  an alert. The default of 72 rides out a weekend with laptops closed.

Two more settings go in `.env`; `0` turns one off:

- **`ALTIWARD_ENROLL_NEW_MACS_PER_HOUR`** (default 1000). How many Macs the organisation
  hasn't enrolled before may enrol in an hour. Raise it if you roll the agent out to more
  Macs than that in an hour; the rest are refused and try again later.
- **`ALTIWARD_ENROLL_KEYS_PER_MAC_PER_DAY`** (default 5). How many keys one Mac may enrol in
  24 hours, in any status. It stops the enrolment token piling keys onto one serial.

A Mac over a limit is refused with HTTP 429 and `Retry-After: 3600`. Agent 0.8.0 and later
wait that hour before asking again (an agent that restarts asks once more straight away);
earlier agents ask about once a minute. A Mac sending a key that is already enrolled is
never refused. The server logs `enrolment rate limited` with the tenant, the serial and
which limit. To keep a flood of refusals out of the log, it logs one per tenant and limit
in each window (an hour, or a day for the keys per Mac), and `not_logged` in the next one
counts the refusals in between. Restarting a server starts new windows. Run
`docker compose up -d` to apply a change (on Azure, see
[Changing settings](../deploy/azure/README.md#changing-settings)).

Someone with the enrolment token can also use the limits against you. They can keep the
new-Macs allowance full with invented serials, so that genuine Macs enrolling for the first
time are refused, or use up a serial's keys for the day (five by default). Revoking a key
frees neither. The signs are Macs being refused (`enrolment rate limited` in the server's
log, with a high `not_logged`, and `device id: (not enrolled)` in `altiward-agent status`)
while **Enrollments** fills with serials or keys you don't recognise. Then change the agent
token ([Changing tokens](#changing-tokens)), revoke the keys you don't recognise, and
meanwhile raise the limit or set it to `0`.

To retire a Mac, revoke its enrollment in **Enrollments**. It then stops being able to
report and never raises a "not checking in" alert. A key that rotation replaced shows as
**Rotated**, not **Revoked**, and offers no actions: revoke the Mac's key in use, which
its inspector links to. A key in a file shows a note that, with agent 1.0 or later, the
agent moves it into the Secure Enclave by itself or, on a Mac without one, replaces it
every 30 days, so there is no need to revoke it.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/enrollments-dark.png">
  <img src="images/install/enrollments-light.png" width="720" alt="Enrollments in the console, with filters for All, Waiting, Active, Revoked and Rotated: each key shows its fingerprint and whether it is kept in the Secure Enclave, in a file, or not reported. One Mac's earlier file key shows as Rotated. That Mac's key in use is selected, with a Revoke button, its device ID, the key it was rotated from, and a note that the agent moves a file key into the Secure Enclave or, on a Mac without one, replaces it every 30 days.">
</picture>

**Activity** keeps every change made in the console forever, and sends each one to your
SIEM. To remove old entries, set `ALTIWARD_AUDIT_RETENTION_DAYS` in `.env` (at least 365)
and run `docker compose up -d`. Altiward then removes older entries once a day, but never
one your SIEM hasn't received yet.

## Enforcement

Two keys in the agent's profile let it act on a Mac, not only report. Both default to
`alert`, and any other value, including `off`, means `alert`. Pilot `enforce` on a small
group before everyone.

> **Warning:** With `OutOfBandEnforcement` set to `enforce`, every admin nobody granted
> loses their rights within minutes, including the LAPS account your MDM manages if it
> isn't in `PermanentAdmins`. The agent counts as a human admin any member of `admin`
> with a UID of 500 or more, and any direct member of `admin` other than `root` and `_`
> accounts, hidden ones included, so list a hidden management account with a low UID too.
> Without SAP Privileges, that is every admin who isn't a permanent admin. Before turning
> it on, check **Admins now** for the rows marked **Without a grant** on the Macs in
> scope.

### Rights past their expiry

`ExpiryEnforcement` decides what happens when rights outlive the expiry Privileges set:
`alert` only reports it, and `enforce` removes the user from `admin`.

### Rights nobody granted

`OutOfBandEnforcement` decides what happens to admin rights nobody granted. `alert` only
raises `admin.out_of_band`. `enforce` removes the account from `admin` at the next
heartbeat after the rights have gone `OutOfBandGraceMinutes` (default 5, minimum 1)
without a grant, and sends `admin.out_of_band_removed`. The heartbeat runs every
`HeartbeatInterval` (default 5 minutes), so it acts up to that late.

In `enforce` mode the agent never removes a permanent admin, and keeps at least one
standing admin: a permanent admin, or else the account nobody granted it has seen
longest. Someone holding admin through a Privileges grant doesn't count, and nor do
admins still in their grace period or not yet raised. Of accounts raised at the same
moment, as on a fresh install, it keeps the one whose short name sorts last. It pauses
every removal while the **Privileges reports to Altiward** check fails (Privileges'
hook path or checksum isn't Altiward's), because then every real Privileges grant would
look like rights nobody granted. A removal that is kept, paused or fails leaves the
finding open, is retried at every heartbeat and is logged on the Mac. A Privileges grant
whose hook never reached the agent looks like rights nobody granted and can be removed;
the person can request it again.

> **Warning:** The pause doesn't cover a `HookCodeRequirement` that doesn't match the
> hook. The daemon then rejects the hook's calls, so in `enforce` mode real Privileges
> grants are removed after the grace period. Check that `HookCodeRequirement` names the
> right Team ID before turning `enforce` on.

### Claims made by running the hook by hand

Someone holding admin rights nobody granted can run the hook by hand to claim a
Privileges grant, or to claim they gave the rights back. The agent checks a grant claim
against SAP Privileges' own log, which a hand-run claim leaves no line in. Full
protection needs **Privileges 2.6 or later with its system extension on, on macOS 14 or
later** (the extension needs the system extension policy and Full Disk Access in
[step 2](#2-deploy-the-agent)). Then, in `enforce` mode:

- A grant claim waits up to a minute for Privileges' log to show it, usually a second or
  two, and a grant logged up to two minutes before the claim arrived counts. The hook
  returns at once, and nothing is recorded until the log backs the claim. A claim the log
  doesn't confirm is refused and sent as `agent.tamper` with check `grant_claim`, and the
  rights are removed after `OutOfBandGraceMinutes` as rights nobody granted, counted from
  when the agent first saw them. A claim sent from another person's account (neither the
  user nor root) is refused and sent the same way, and a caller who sends more than 5
  grant claims in a minute is ignored and logged on the Mac, not sent, so a flood can't
  fill the outbox. Give-back claims have an allowance of their own, 5 a minute from one
  caller, in every mode: past it, a give-back that ends an open session is still
  recorded, and any other is ignored and logged the same way.
- A claim through the hook renews a Privileges session only when fresh log evidence
  confirms it, that is, the log shows Privileges granted the rights again. Otherwise,
  once the minute has passed (or at once if the log becomes unavailable while the claim
  waits), it is refused in every mode and reported as a renewal, and the expiry doesn't
  move, so running the hook again can't keep rights past `ExpiryEnforcement`. Privileges
  sends no claim for a real renewal: the agent reads it from the line SAP's
  `PrivilegesAgent` logs, checks that SAP's agent logged it, and moves the expiry. That
  process runs as the user, so the check is weaker than for a grant, and a line whose
  process has gone is ignored, leaving the original expiry. Setting Privileges'
  `AllowPrivilegeRenewal` to `false`, as the release's `corp.sap.privileges.plist` does
  ([step 2](#2-deploy-the-agent)), is the stricter choice: the agent then ignores renewal
  lines altogether.
- A real grant that the person gives back within seconds is still confirmed: only
  changes to `admin` made before the claim arrived count against it.

Without the log (Privileges older than 2.6, its extension off or stopped, or macOS 13),
enforcement keeps removing rights nobody granted, and the agent accepts a grant claim,
marked `privileges_log: "unavailable"`, with the checks below. Without a fixed
`ExpirationInterval`, the agent answers the hook first and records the claim a moment
later, once it has read Privileges' timer, so the hook logs "Sent admin for" even for a
claim the agent then refuses; the refusal is still sent as `grant_claim`. The Mac's
details then show an integrity check failing, naming what's missing, whenever
`OutOfBandEnforcement` or `ExpiryEnforcement` is `enforce` and Privileges is installed.
Where the agent has read the log on a Mac before and can't now, each claim it accepts is
also sent as `grant_claim`, as someone may have stopped the extension to get one past.

In `enforce` mode, with or without the log, the agent refuses, logs on the Mac and sends
as `grant_claim` a grant claimed on a Mac without SAP Privileges, a grant claimed more
than a minute after Altiward raised the rights (without the log), and a give-back claimed
while they are still an admin, and the rights are still removed. Hand-run claims can
still keep the rights there: a grant claimed before the agent raises them (in the 30
seconds or so before it does, or between heartbeats), and an account with root that
removes itself from `admin`, gives the rights back, adds itself again and claims a grant.

This stops the quiet routes, not someone with root: an admin has root, and with root a
forged log line is possible.

In `alert` mode a claimed grant still turns their session into a Privileges session.
With the log, a claim it doesn't confirm is accepted and marked not confirmed, and sent
as `grant_claim`; the console shows the session as **Followed rights without a grant**
and the SIEM as "Replaced by a Privileges grant". While the log is available, a claim
through the hook renews the session only when fresh log evidence confirms it, in either
mode; without the log, each claim renews it, and each is reported as
`elevation.granted`.

## Running it

### Health and logs

- `docker compose ps` shows whether each service is up. Altiward reports itself healthy
  once it answers on its health endpoint, and Caddy waits for that before starting.
- `docker compose logs altiward` shows the server's logs, one JSON object per line. Warnings
  about export failures mean your SIEM is refusing events; they are retried with
  backoff.
- Each Mac's last check-in, and any **Not checking in** or **Needs attention** tags, are
  in **Fleet**. **Activity** lists every change made in the console.

### Backups

Postgres holds everything. Back it up daily, and keep `.env` somewhere safe as well:

```sh
docker compose exec -T postgres pg_dump -U altiward -Fc altiward > altiward-$(date +%F).dump
```

To run it every night at 02:00, make a `backups` directory only you can read
(`mkdir -m 700 backups`) and add this line with `crontab -e`, as a user who can run
Docker. Copy the dumps off the server, and remove old ones as your policy allows:

```
0 2 * * * cd /opt/altiward && umask 077 && docker compose exec -T postgres pg_dump -U altiward -Fc altiward > backups/altiward-$(date +\%F).dump
```

To restore into an empty database:

```sh
docker compose up -d postgres
docker compose exec -T postgres pg_restore -U altiward -d altiward --clean --if-exists < altiward-<date>.dump
docker compose up -d
```

A restored database can be older than some Macs' last rotation: it knows the key such a
Mac replaced, not the one it holds now. The Mac is refused, enrols again and, with
approval on, waits in **Enrollments** for you to approve it. After a restore, expect that
for every Mac whose key rotated since the backup. Before approving each one, run
`altiward-agent status` on the Mac through your MDM and approve only the pending key whose
fingerprint matches its `key fingerprint:` line ([A rotated key was
used](#a-rotated-key-was-used)).

With [an existing Postgres](#an-existing-postgres), back it up the way you back up your
other databases: these commands are for the bundled one.

### Releases and updates

Releases are published on
[GitHub Releases](https://github.com/Altiward/altiward/releases), with their notes.
Nothing updates itself, and your server never contacts Altiward or GitHub.

**The console tells admins when a release is out.** On Overview and in **Settings › Updates**, people
with the admin role see when a newer server or agent is out, whether it fixes a security
problem, a link to its notes, and the `upgrade.sh` command below with the version filled
in. It only tells: it never upgrades anything. The admin's browser makes the check, not
the server, so it works when the server has no internet access but browsers do. It asks
`api.github.com` for the release list at most once a day per admin's browser after a
successful check, and at most once an hour while GitHub can't be reached or the list
doesn't include your server's version yet, sending nothing about your fleet
([Data handling](data-handling.md#in-the-browser)). A notice can be
dismissed until the next version. Settings always shows the latest versions and when
they were last checked, or "Couldn’t check for updates" when a firewall or proxy blocks
GitHub; **Check now** there asks again, at most once a minute. To turn the check off for everyone, set `ALTIWARD_UPDATE_CHECK=false` in `.env`
and run `docker compose up -d`. On Azure Container Apps, the notice names the image to
change to instead, and upgrades work differently
([Upgrading](../deploy/azure/README.md#upgrading)).

**Upgrading the server:** download the new release into a directory of its own, as in
[step 1](#1-start-the-server), read its `RELEASE_NOTES.md`, then run the upgrade script
from your deployment directory, such as `/opt/altiward`:

```sh
./upgrade.sh ~/altiward-<version>
```

It checks the files and their signature ([Checking a release](#checking-a-release)),
shows the notes' upgrade order, breaking changes and security fixes, and asks before it
changes anything. Then it:

1. backs up the database, `.env` and every file it replaces into `backups/`;
2. loads the image and updates the deployment files you haven't changed;
3. sets `ALTIWARD_VERSION` in `.env` and restarts, and the server updates its database by
   itself as it starts;
4. waits for the server to report healthy, or prints its logs and how to restore the
   backup.

Before step 1 it replaces itself with the new release's copy, so each release's upgrade
runs that release's script.

| Option | Use |
| --- | --- |
| `--yes` | Don't ask, for automation |
| `--skip-signature` | Carry on without cosign; the checksums are still checked. Better: check the signature on another machine first |
| `--skip-backup` | You use your own Postgres and back it up yourself. Without it, the script stops if the bundled Postgres isn't running |
| `--merged` | You've merged the files the script left as `.new` (below) |

**Your settings live in `.env`**, never in `compose.yaml`: every setting is there, off
while empty. That way an upgrade can replace `compose.yaml`. For anything `.env` can't
do, such as another volume, add a `compose.override.yaml` next to it, which Docker Compose
reads too and upgrades never touch. If you did change `compose.yaml` or `Caddyfile`
(for [your own certificates](#your-own-certificates-or-load-balancer) or
[an existing Postgres](#an-existing-postgres)), the script keeps your file whenever the
release doesn't change it. When the release changes it too, the script stops before
changing anything, shows what the release changes, and leaves the new version as
`compose.yaml.new` or `Caddyfile.new`. Bring those changes into your file, then run the
script again with `--merged`.

Going back to an older server version isn't supported; restore the backup instead. The
script shows how if the new version doesn't start. In particular, don't run server 0.9 and
1.0 together on one database: a 0.9 server doesn't know rotation's two new `agent.enrollment`
states, and can drop an event or export a `rotated_key_used` alert as an Informational
"enrolled a new key" record that nothing alerts on. A 0.9 server started on a 1.0
database still refuses the keys that rotation replaced (they are marked revoked), but it
raises no alert and revokes nothing when one is used again while it runs, and its
diagnostics list migration 0006 as unknown.

**Release candidates** (versions such as `<version>-rc.1`) are builds for testing, published on GitHub as
pre-releases. Install one as above; the release itself upgrades over it. The console
tells admins about candidates when the server runs one, or when they turn on **Show
pre-releases** in **Settings › Updates**, which applies to their browser only.

**Upgrading by hand**, if you'd rather: back up the database, `docker load -i` the image,
set `ALTIWARD_VERSION` in `.env`, copy in any changed files from the new bundle's
`deploy/compose`, and run `docker compose up -d`.

**Rolling out a new agent:** upgrade the server first, then upload the new package to
your MDM and deploy it to a pilot group before everyone. The server accepts agents from
the last two agent minor releases, so Macs can catch up at your pace. An agent that can
rotate keys, on a server that can't, keeps its key and tries again a day later, so
nothing breaks if the order slips, but nothing rotates either. Fleet tags Macs
whose agent is older than that **Agent outdated**.
Each agent build's hook has its own checksum: update `PostChangeExecutableChecksum` in your
Privileges profile to the value in the release's `corp.sap.privileges.plist` before or
together with the package, scoped to the same Macs. While the checksum doesn't match the
installed hook, Privileges silently stops running it, and each grant shows as admin rights
**Without a grant** about 30 seconds later. The agent compares the two at each heartbeat
and reports *SAP Privileges no longer reports to Altiward* until they match, so expect
that alert briefly on Macs that get the new profile before the new package.

**Support:** fixes go to the latest two minor versions of the server and of the agent.

**Pulling from the registry instead:** the image is public, so if you'd rather
`docker compose pull` than load files, there is nothing to log in to: set
`ALTIWARD_VERSION` and run `docker compose pull && docker compose up -d`. The image is
`ghcr.io/altiward/altiward-api`, tagged with each version (there is no `latest`).

### Checking a release

Each release comes with `SHA256SUMS`, signed by the release workflow in the
`Altiward/altiward` repository on GitHub. `upgrade.sh`
checks both for you, using cosign if it's installed. To check by hand, or before a first
install, check the files match it. `--ignore-missing` skips files listed that you didn't
download, such as the image for the other platform:

```sh
sha256sum -c --ignore-missing SHA256SUMS     # on macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
```

To check the list itself came from that workflow, use
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) with the
`SHA256SUMS.sigstore.json` beside it. For a server release:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Altiward/altiward/\.github/workflows/release-server\.yml@refs/tags/server-v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For an agent release, use `release-agent\.yml@refs/tags/agent-v` in place of
`release-server\.yml@refs/tags/server-v`. The agent package is also signed by Apple's
Developer ID and notarized, which macOS checks when it installs.

The server image is signed the same way. To check one you pulled:

```sh
cosign verify ghcr.io/altiward/altiward-api:<version> \
  --certificate-identity-regexp '^https://github.com/Altiward/altiward/\.github/workflows/release-server\.yml@refs/tags/server-v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Changing tokens

Edit the token in `.env` and run `docker compose up -d`.

- **Console token:** everyone using it signs in again with the new one. With single
  sign-on, that's only break-glass use.
- **Agent enrolment token:** enrolled Macs keep working, because they sign with their own
  keys. Update the profile in your MDM so new Macs enrol with the new token. If the old
  token leaked, remove it from `ALTIWARD_AGENT_TOKENS` rather than leaving both tokens
  accepted. **Enrollments** shows the token each key enrolled with (from server 0.9.0), as
  `token:` and the first 8 hex digits of its SHA-256. Get the old token's with
  `printf %s '<old token>' | shasum -a 256 | cut -c1-8`, search for it, and revoke the keys
  you don't recognise: changing the token does not revoke keys it already enrolled or
  clear the enrolment limits. While those windows expire, enrol
  expected Macs using the temporary limit increase described under
  [Settings worth reviewing](#6-settings-worth-reviewing).

### Your own certificates or load balancer

The example asks Let's Encrypt for certificates, which needs both hostnames in public DNS
and port 80 open. Alternatives:

- **Your own certificates:** put them in `certs/`, which Caddy sees as `/certs`, and add
  `tls /certs/cert.pem /certs/key.pem` to each site in `Caddyfile`. The console hostname
  can then stay in internal DNS only. Upgrades keep your `Caddyfile`. If an internal CA
  issued the agent hostname's certificate, the Macs must trust that CA: deploy its root
  through your MDM, because a root in a profile installed by hand isn't trusted for TLS on
  recent macOS, and the agent then can't reach the server.
- **Behind a load balancer:** Caddy sees the load balancer's address, not the person's,
  so the console allowlist needs the
  [`trusted_proxies`](https://caddyserver.com/docs/caddyfile/options#trusted-proxies)
  option. Or drop Caddy and terminate TLS on the load balancer: send `/v1/agent/*` from
  the public listener to port 8080 of the `altiward` container, and everything from the
  internal listener. Either way, allow at least 60 seconds of idle time on the agent
  listener: each Mac holds a request open for up to 50 seconds so that revokes reach it
  within about a second.

### An existing Postgres

To use a managed database instead of the bundled one, remove the `postgres` service from
`compose.yaml` and set `ALTIWARD_DATABASE_URL` to your database's URL, with
`sslmode=require` or stronger. Altiward is tested with Postgres 17, and its user must be
able to create tables in its database. Back the database up before each upgrade and run
`upgrade.sh --skip-backup`; it keeps your `compose.yaml`, and stops to ask you to merge
when a release changes the file too.

### Diagnostics for a bug report

When you report a problem, attach a diagnostics report:

```sh
docker compose exec altiward /usr/local/bin/altiward-api diagnose > altiward-diagnose.json
```

It's JSON, so read it before you send it. It holds the version, your
settings with every secret hidden (the database URL keeps only its host and database name), the tokens by
fingerprint, never their values, the database's migrations and counts, and whether each
SIEM endpoint and the identity provider accept a connection. It holds no events, user names or Mac details, and
it sends nothing anywhere itself. Its `problems` list is a good first place to look when
something is wrong.

Logs aren't included. If a maintainer asks for them:
`docker compose logs --since 24h altiward > altiward.log`.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Caddy logs certificate errors | A hostname doesn't resolve to this server, or port 80 is blocked ([Caddy certificate errors](#caddy-certificate-errors)) |
| The console shows "403" | You're outside `ALTIWARD_CONSOLE_ALLOW`, or behind a proxy Caddy doesn't trust |
| Sign-in says the token is wrong | Use the part after `yourcompany=` in `ALTIWARD_CONSOLE_TOKENS` |
| Single sign-on says your account isn't in a group that can use Altiward | The groups claim doesn't carry any group in `ALTIWARD_OIDC_*_GROUPS`. Check the IDs (Entra) or names (Okta), and that the group is assigned to the application. |
| Single sign-on says your identity provider didn't send your groups | Entra ID: limit the groups claim to groups assigned to the application. |
| Single sign-on can't reach your identity provider | The server can't fetch `<issuer>/.well-known/openid-configuration`. Diagnostics checks the connection as `sso`. Use the break-glass token meanwhile. |
| The identity provider says the redirect URI doesn't match | Register `https://<console hostname>/v1/auth/callback` exactly. |
| A Mac never appears | `ServerURL` is wrong, the agent hostname isn't reachable from the Mac, or the enrollment token doesn't match ([A Mac never appears](#a-mac-never-appears)) |
| A Privileges grant shows as **Without a grant** | Privileges didn't run Altiward's hook, usually because its checksum is from another agent release ([Rights show as "Without a grant"](#rights-show-as-without-a-grant)) |
| **Privileges tamper protection** fails on a Mac | `EnableSystemExtension` is off, or SAP's system extension isn't running: the Mac hasn't got SAP's system extension policy and Full Disk Access ([step 2](#2-deploy-the-agent)), or someone stopped it. The check names which |
| **Settings › SIEM export** shows **Failing** | The SIEM is rejecting events or can't be reached. The row shows the last error; after a fix, **Retry now** ([step 4](#4-connect-your-siem)) |
| A Mac waits in **Enrollments** | It enrolled again with a new key while approval is on: approve it. |
| A `rotated_key_used` alert, or a Mac that enrolled again by itself | A key that was replaced was used again: two holders of one Mac's identity ([A rotated key was used](#a-rotated-key-was-used)) |
| `upgrade.sh` stopped and left `compose.yaml.new` | You changed `compose.yaml` and so did the release: merge, then run it again with `--merged` ([Releases and updates](#releases-and-updates)) |
| `upgrade.sh` says a file doesn't match `SHA256SUMS` | The download is incomplete or was changed: download the release again |
| A Mac shows **Not checking in** while it's on and online | Something between the Mac and the server answers or drops its key rotation request, so it holds its reports. `altiward-agent status` shows `key rotation:` and the last answer ([Key rotation](#key-rotation)) |
| A Mac shows **Not checking in** | It has been off, offline or unable to reach the agent hostname for longer than the limit. Its events wait on the Mac and arrive when it reconnects. If laptops show this when they're away from the office, the agent hostname isn't reachable from the internet ([Two hostnames](#what-youre-installing)). |
| **Needs attention** on a Mac | An integrity check failed, for example the agent's files changed, or `ServerURL`, `PermanentAdmins`, `ExpiryEnforcement`, `ExpiryGraceMinutes`, `OutOfBandEnforcement`, `OutOfBandGraceMinutes` or `HookCodeRequirement` was set outside MDM. The Mac's details say which. |

For anything else, run the [diagnostics report](#diagnostics-for-a-bug-report) and check its
`problems` list.

### A Mac never appears

On the Mac, ask the agent:

```sh
sudo "/Library/Application Support/Altiward/Altiward.app/Contents/MacOS/altiward-agent" status
```

```
data directory: /Library/Application Support/Altiward
server: https://altiward-agents.example.com
device id: (not enrolled)
queued events: 4
open sessions: 0
persistence snapshot: (none yet)
```

- `server: (not configured)`: the agent profile hasn't reached the Mac, or its preference
  domain isn't `com.altiward.agent`. Check **System Settings › General › Device
  Management**.
- `device id: (not enrolled)` with a server: the Mac can't reach the agent hostname, or
  `EnrollmentToken` isn't the part after `yourcompany=` in `ALTIWARD_AGENT_TOKENS`. From
  the Mac, `curl -sSI https://<agent hostname>/` should answer `HTTP/2 404`: only the
  agent's own paths answer there. A connection or certificate error means the Mac can't
  reach the server. If the server's logs show `enrolment rate limited` for its serial, it
  is over an [enrolment limit](#6-settings-worth-reviewing) and the agent tries again later.
- A device ID but **queued events** that never go down: the Mac enrolled but can't deliver.
  If **Approve Macs that enrol again** is on, or the Mac's key came from different hardware
  than its earlier one, look in **Enrollments** for a Mac waiting for approval.
- `device key: Secure Enclave` after the device ID: only the agent's daemon can use that
  key, so `altiward-agent flush`, `heartbeat` and `commands` run by hand say the daemon
  sends instead. It does, within a minute.

### A rotated key was used

An `agent.enrollment` event with state `rotated_key_used` (High) means a key the agent had
already replaced by [rotation](#key-rotation) was used again, so two copies of one Mac's
key are in use: the Mac, and a copy. It names the replaced key (`device_id` and
`key_fingerprint`), the key that replaced it (`rotated_to`) and, when the server revoked
one, which (`revoked_device_id`).

1. **What it means.** The server can't tell which holder is the genuine Mac, so when a
   replaced key signs a request and the Mac's current key came from it, the server revokes
   that current key. Neither holder keeps a working key. It does this only when the
   replaced key was replaced in the last 30 days. For an older key, or a Mac that has
   enrolled afresh since, it only raises the alert, at most once a day per key, and the
   key in use keeps working. In **Enrollments** the replaced key shows as **Rotated** and
   the revoked one as **Revoked**. An alert without `revoked_device_id` usually means an
   old copy was used, and the key in use is the Mac's. But if a key for that Mac then
   waits in **Enrollments**, check which key the Mac holds (step 2). If it is the pending
   one, the active key, if there is one, isn't the Mac's: revoke it, then approve the
   pending one.
2. **The Mac enrols again by itself.** Its next request is refused, so it makes a new key
   and enrols, and with **Approve Macs that enrol again** on (the default) it waits in
   **Enrollments**. A copy can enrol too, and a copy of the agent's store carries the
   Mac's serial and hardware UUID, so those don't tell the keys apart. Instead, run the
   agent's status on the Mac through your MDM, as root:

   ```sh
   "/Library/Application Support/Altiward/Altiward.app/Contents/MacOS/altiward-agent" status
   ```

   Approve only the pending key whose **Key fingerprint** in **Enrollments** matches its
   `key fingerprint:` line (an agent older than 1.0 shows only `device id:`, which matches
   the key's **Device ID**), and reject every other pending key for that serial. With
   approval off, the first key that enrols is active at once, which is a reason to leave
   approval on. The new key starts a lineage of its own: old copies of earlier keys can
   raise this alert, at most once a day, but can't revoke anything again.
3. **Find where the copy came from.** A file key is readable by root, so look for it in
   backups of the Mac (Time Machine, a backup agent), disk images and clones, a Mac set
   up with Migration Assistant, and anyone with admin rights on it. It is the Mac's earlier
   file key that leaks: once the key is in the Secure Enclave, there is nothing new to
   copy. Ask the Mac's owner and whoever runs the backups, and remove or protect the copy.
4. **A Mac restored from a backup is a genuine cause.** A Mac restored from a backup made
   before its last rotation signs with the key it had then, which the server replaced
   since. It raises this alert, and the server revokes the key that replaced it, but the key
   it enrols with afterwards is genuine. The same happens when an agent is downgraded to
   0.9 while the server had committed a rotation. When the Mac was restored on purpose,
   approve the key whose fingerprint its status shows, as in step 2.

Anyone holding a copy of a key replaced in the last 30 days can cause this once per
lineage, and revoke the Mac's working key, whether or not they have the enrolment token:
changing the token doesn't stop it. That is the price of not letting a copy take the Mac
over. Someone with many Macs' backups can do it to each Mac once, at the cost of an alert
for each, so keep the backups of `/Library/Application Support/Altiward` protected.

### Rights show as "Without a grant"

When someone gets admin rights through Privileges but the console shows **Without a
grant**, Privileges didn't tell Altiward. Usually its profile pins the hook of a different
agent release: Privileges then skips the hook without a word. The Mac shows **Needs
attention** in **Fleet**, and its details show **Privileges reports to Altiward** failing,
with the reason.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/fleet-hook-not-reporting-dark.png">
  <img src="images/install/fleet-hook-not-reporting-light.png" width="311" alt="A Mac's Integrity checks in Fleet: Privileges reports to Altiward is Failing, high severity. The alert below says PostChangeExecutableChecksum doesn't match Altiward's hook, so Privileges won't run it, and to use the corp.sap.privileges.plist from this agent's release.">
</picture>

Deploy `corp.sap.privileges.plist` from the same agent release as the package installed on
that Mac ([step 2](#2-deploy-the-agent)). Grants after that are recorded as Privileges
grants. The first one also ends the open **Without a grant** session.

If the check passes, the rights really were granted outside Privileges: someone added the
account to `admin` another way. If it's an IT or managed admin account, add it to
`PermanentAdmins`.

With `OutOfBandEnforcement` set to `enforce`, a grant whose hook never reached the agent
is removed once `OutOfBandGraceMinutes` have passed, as rights nobody granted: the console
shows **Removed without a grant**, and the person can request again. The agent pauses
removals while the **Privileges reports to Altiward** check fails, so fix that first.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/session-without-grant-dark.png">
  <img src="images/install/session-without-grant-light.png" width="360" alt="A session found without a grant: Without a grant, a Revoke admin rights button, a note on adding managed admin accounts to PermanentAdmins, and a timeline with Found without a grant.">
</picture>

### Caddy certificate errors

Caddy gets a certificate for each hostname from Let's Encrypt when it starts. If the
console shows a certificate warning, or nothing, look at its log:

```sh
docker compose logs caddy | grep -i error
```

- `DNS problem: NXDOMAIN looking up A for <hostname>`: the hostname doesn't resolve yet.
  Create the DNS record, wait for it to appear, then `docker compose restart caddy`.
- `Timeout during connect (likely firewall problem)`: Let's Encrypt can't reach the
  server. Open ports 80 and 443 to the internet, in the server's firewall and any cloud
  network rules.
- `too many certificates already issued` or `rateLimited`: repeated failed attempts hit
  Let's Encrypt's limits. Fix the cause, then wait for the time the message gives.

For certificates from your own CA or a load balancer, see
[Your own certificates or load balancer](#your-own-certificates-or-load-balancer).
