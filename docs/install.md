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
  answer there. People use the *console hostname*, which only accepts connections from
  the networks you list. On Azure Container Apps, one address serves both, split by path,
  with the same rule.

## Choose how to run it

Altiward is the same software however you run it. Pick the setup that
matches what you already have:

| | The bundle | Your own infrastructure | Azure Container Apps (Preview) |
| --- | --- | --- | --- |
| For | A site that wants Altiward to bring everything it needs | A site with a managed database and its own load balancer or certificates | A site on Azure that wants no server or VM to look after |
| Database | Postgres in the bundle, backed up by you ([Backups](#backups)) | Your managed Postgres ([An existing Postgres](#an-existing-postgres)) | Azure Database for PostgreSQL on a private network, with Azure's backups |
| TLS | Caddy, with certificates from Let's Encrypt | Your certificates or load balancer ([Your own certificates or load balancer](#your-own-certificates-or-load-balancer)) | The Container Apps ingress, on its own address or your domain |
| Steps | This guide as written | This guide, plus the sections linked here | [Deploy to Azure](../deploy/azure/README.md), then this guide from step 2 |

The bundle and your own infrastructure use the same image and the same `deploy/compose`
files, so you can move from one to the other later without reinstalling. Deploy to Azure
runs the same image, set up by a template, with settings on the container app instead of
in `.env`. If you run Kubernetes,
[open an issue](https://github.com/Altiward/altiward/issues): manifests or a Helm chart
come when someone needs them.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAltiward%2Faltiward%2Fserver-v0.2.0%2Fdeploy%2Fazure%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FAltiward%2Faltiward%2Fserver-v0.2.0%2Fdeploy%2Fazure%2FcreateUiDefinition.json) (Preview: [what it creates](../deploy/azure/README.md))

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
- **Your MDM** (Jamf Pro, Intune, Kandji, Mosyle or similar) to install the package and
  configuration profiles.
- **From [GitHub Releases](https://github.com/Altiward/altiward/releases):** a server
  release and an agent release. A server
  release is the bundle (`altiward-server-<version>.tar.gz`, holding the deployment files
  in `deploy/compose/`, this guide, the SIEM guides and Sentinel's setup script in
  `integrations/`, and the agent's example Mac profiles in `profiles/`), the server image
  as a file for your platform (`altiward-api-<version>-linux-amd64.tar.gz` or `…-arm64`),
  `RELEASE_NOTES.md` and `SHA256SUMS`. An agent release is the signed package
  (`Altiward-<version>.pkg`), the SAP Privileges keys pinned to that package's hook
  (`corp.sap.privileges.plist`), and its own notes and checksums. Server releases are tagged
  `server-vX.Y.Z` and agent releases `agent-vX.Y.Z`. Nothing needs an account.

## 1. Start the server

Download the release files from GitHub Releases onto the server, check them (see
[Checking a release](#checking-a-release)), then load the image and unpack the bundle. (The image is also public at
`ghcr.io/altiward/altiward-api`, pulled without logging in: skip `docker load` and
`docker compose up -d` below pulls it.)

```sh
docker load -i altiward-api-<version>-linux-amd64.tar.gz
tar xzf altiward-server-<version>.tar.gz
cd altiward-server-<version>/deploy/compose
```

In that directory, holding `compose.yaml`, `Caddyfile` and `env.example`:

```sh
cp env.example .env
chmod 600 .env
```

Edit `.env`:

| Setting | What to put |
| --- | --- |
| `ALTIWARD_VERSION` | The release you downloaded, for example `0.1.0` |
| `ALTIWARD_AGENT_HOST`, `ALTIWARD_CONSOLE_HOST` | Your two hostnames |
| `ALTIWARD_CONSOLE_ALLOW` | The networks allowed to open the console, space separated, for example your office and VPN ranges |
| `POSTGRES_PASSWORD` | A new random value: `openssl rand -hex 24` |
| `ALTIWARD_AGENT_TOKENS` | `yourcompany=` followed by a new random value. It goes into the Mac profile. |
| `ALTIWARD_CONSOLE_TOKENS` | `yourcompany=` followed by a different random value. People sign in to the console with it until you set up single sign-on ([step 5](#5-sign-in-with-your-identity-provider)); after that it is a break-glass login. |
| `ALTIWARD_UPDATE_CHECK` | Leave it empty: the console tells admins when a newer release is out ([Releases and updates](#releases-and-updates)). `false` turns that off. |

Use the same organisation name in both token settings.

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
     break-glass accounts. Altiward never reports or removes them. Include the local
     admin account your MDM manages with LAPS (Jamf Pro's managed local administrator,
     or the macOS local admin account Intune creates at enrollment): enter the short name
     you set in the MDM, exactly. Left out, it shows in the console as an admin nobody
     granted, and revoking every admin on a Mac would remove its rights too. Altiward
     doesn't record when someone uses a permanent admin account; your MDM records who
     looked up its password.

   The example explains every other key. `ExpiryEnforcement` decides what happens when
   rights outlive the expiry Privileges set: `alert`, the default, only reports it, and
   `enforce` removes the user from `admin`. Deliver the profile through MDM rather than
   `defaults write`: Altiward reports `ServerURL`, `PermanentAdmins`, `ExpiryEnforcement`,
   `ExpiryGraceMinutes` or `HookCodeRequirement` set outside MDM as tampering (it doesn't
   check the other keys).
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
   `Example_ApprovePrivileges.mobileconfig` has both. Until it's on, Altiward reports
   *SAP Privileges tamper protection is off* for each Mac.
   We also suggest `ReasonRequired` (and `ReasonMinLength`), if your profile doesn't set them:
   Privileges keeps the reason someone gives only when it requires one, so without it Altiward
   records no reason.
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

Each Mac enrolls on first contact: it registers its own key with your server and signs
everything after that, so the enrollment token is used once per Mac. The token is
readable on every Mac, so anyone with it can enroll a key for a serial number: a new key
for a Mac that is already enrolled replaces the old one, unless **Approve Macs that enroll
again** is on ([step 6](#6-settings-worth-reviewing)).

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
`.env` and run `docker compose up -d`. If your SIEM's certificate comes from your own CA,
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
  <img src="images/install/settings-siem-light.png" width="592" alt="Settings, SIEM export: Syslog, Up to date, nothing waiting, with the time of the last delivery, and a button to send a test event.">
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

**You should see** yourself under **Settings › Signed in to the console** once you've
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

In the console, under **Settings**:

- **Approve Macs that enroll again.** On means a Mac that comes back with a new key, for
  example after a reinstall, waits in **Enrollments** for your approval. Its earlier key
  keeps working until you approve the new one.
- **Alert when a Mac stops checking in.** Hours without a check-in before Altiward raises
  an alert. The default of 72 rides out a weekend with laptops closed.

To retire a Mac, revoke its enrollment in **Enrollments**. It then stops being able to
report and never raises a "not checking in" alert.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/install/enrollments-dark.png">
  <img src="images/install/enrollments-light.png" width="720" alt="Enrollments in the console: a Mac waiting for approval is selected, with its key fingerprint, Approve and Reject buttons, and a note that it enrolled again with a new key.">
</picture>

**Activity** keeps every change made in the console forever, and sends each one to your
SIEM. To remove old entries, set `ALTIWARD_AUDIT_RETENTION_DAYS` in `.env` (at least 365)
and run `docker compose up -d`. Altiward then removes older entries once a day, but never
one your SIEM hasn't received yet.

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

To restore into an empty database:

```sh
docker compose up -d postgres
docker compose exec -T postgres pg_restore -U altiward -d altiward --clean --if-exists < altiward-2026-10-17.dump
docker compose up -d
```

### Releases and updates

Releases are published on
[GitHub Releases](https://github.com/Altiward/altiward/releases), with their notes.
Nothing updates itself, and your server never contacts Altiward or GitHub.

**The console tells admins when a release is out.** On Overview and in Settings, people
with the admin role see when a newer server or agent is out, whether it fixes a security
problem, a link to its notes, and the `upgrade.sh` command below with the version filled
in. It only tells: it never upgrades anything. The admin's browser makes the check, not
the server, so it works when the server has no internet access but browsers do. It asks
`api.github.com` for the release list at most once a day per admin's browser after a
successful check, and at most once an hour while GitHub can't be reached, sending nothing
about your fleet ([Data handling](data-handling.md#in-the-browser)). A notice can be
dismissed until the next version. Settings always shows the latest versions and when
they were last checked, or "Couldn’t check for updates" when a firewall or proxy blocks
GitHub. To turn the check off for everyone, set `ALTIWARD_UPDATE_CHECK=false` in `.env`
and run `docker compose up -d`. On Azure Container Apps, the notice names the image to
change to instead, and upgrades work differently
([Upgrading](../deploy/azure/README.md#upgrading)).

**Upgrading the server:** put the release files in one directory on the server, read
`RELEASE_NOTES.md`, then run the upgrade script from your deployment directory:

```sh
./upgrade.sh ~/altiward-0.1.0
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
script shows how if the new version doesn't start.

**Release candidates** (`0.1.1-rc.1`) are builds for testing, published on GitHub as
pre-releases. Install one as above; the release itself upgrades over it.

**Upgrading by hand**, if you'd rather: back up the database, `docker load -i` the image,
set `ALTIWARD_VERSION` in `.env`, copy in any changed files from the new bundle's
`deploy/compose`, and run `docker compose up -d`.

**Rolling out a new agent:** upgrade the server first, then upload the new package to
your MDM and deploy it to a pilot group before everyone. The server accepts agents from
the last two agent minor releases, so Macs can catch up at your pace. Fleet tags Macs
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
install, check the files match it:

```sh
sha256sum -c SHA256SUMS          # on macOS: shasum -a 256 -c SHA256SUMS
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
- **Agent enrollment token:** enrolled Macs keep working, because they sign with their own
  keys. Update the profile in your MDM so new Macs enroll with the new token.

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
| The identity provider says the redirect URI doesn't match | Register `ALTIWARD_CONSOLE_URL` plus `/v1/auth/callback` exactly. |
| A Mac never appears | `ServerURL` is wrong, the agent hostname isn't reachable from the Mac, or the enrollment token doesn't match ([A Mac never appears](#a-mac-never-appears)) |
| A Privileges grant shows as **Without a grant** | Privileges didn't run Altiward's hook, usually because its checksum is from another agent release ([Rights show as "Without a grant"](#rights-show-as-without-a-grant)) |
| **Privileges tamper protection** fails on a Mac | `EnableSystemExtension` is off, or the Mac hasn't got SAP's system extension policy and Full Disk Access ([step 2](#2-deploy-the-agent)) |
| **Settings › SIEM export** shows **Failing** | The SIEM is rejecting events or can't be reached. The row shows the last error; after a fix, **Retry now** ([step 4](#4-connect-your-siem)) |
| A Mac waits in **Enrollments** | It enrolled again with a new key while approval is on: approve it. |
| `upgrade.sh` stopped and left `compose.yaml.new` | You changed `compose.yaml` and so did the release: merge, then run it again with `--merged` ([Releases and updates](#releases-and-updates)) |
| `upgrade.sh` says a file doesn't match `SHA256SUMS` | The download is incomplete or was changed: download the release again |
| A Mac shows **Not checking in** | It has been off, offline or unable to reach the agent hostname for longer than the limit. Its events wait on the Mac and arrive when it reconnects. If laptops show this when they're away from the office, the agent hostname isn't reachable from the internet ([Two hostnames](#what-youre-installing)). |
| **Needs attention** on a Mac | An integrity check failed, for example the agent's files changed, or `ServerURL`, `PermanentAdmins`, `ExpiryEnforcement`, `ExpiryGraceMinutes` or `HookCodeRequirement` was set outside MDM. The Mac's details say which. |

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
  reach the server.
- A device ID but **queued events** that never go down: the Mac enrolled but can't deliver.
  If **Approve Macs that enroll again** is on, look in **Enrollments** for a Mac waiting
  for approval.

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
grants. From agent 0.1.1, the first one also ends the open **Without a grant** session.

If the check passes, the rights really were granted outside Privileges: someone added the
account to `admin` another way. If it's an IT or managed admin account, add it to
`PermanentAdmins`.

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
