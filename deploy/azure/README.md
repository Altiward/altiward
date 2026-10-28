# Deploy to Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAltiward%2Faltiward%2Fserver-v1.0.0%2Fdeploy%2Fazure%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FAltiward%2Faltiward%2Fserver-v1.0.0%2Fdeploy%2Fazure%2FcreateUiDefinition.json)

The button creates an Altiward server in your own Azure subscription, running on Azure
Container Apps, with nothing to install on a VM. It is the third way to run the server, next to the
Compose bundle and your own infrastructure in the [install guide](../../docs/install.md),
which covers everything else: the agent, your SIEM and single sign-on. This page covers
what differs on Azure. After each server release, an automated
check deploys it from the release tag, tests it as a Mac and an admin would, and deletes it
again ([docs/releasing.md](../../docs/releasing.md#deploy-to-azure-check)).

The button deploys `azuredeploy.json` at a release tag, and the template runs that
release's image. `main.bicep` is its source.

## What it creates

| Resource | What for |
| --- | --- |
| Container app `<prefix>` | Two containers: Altiward (0.5 vCPU, 1 GiB) and caddy (0.25 vCPU, 0.5 GiB), one replica. The Container Apps ingress handles TLS for its `*.azurecontainerapps.io` address |
| Container Apps environment `<prefix>-environment` | Runs the app, on the network's `apps` subnet |
| Azure Database for PostgreSQL `<prefix>-db-…` | Postgres 17, Burstable B1ms, 32 GB, with 7 days of point-in-time restore. On the network's `database` subnet, with no public endpoint |
| Virtual network `<prefix>-network` and a private DNS zone | Keep the database private to the app |
| Key vault `<prefix>-…` | The database URL and the agent and console tokens. The app reads them as its managed identity; whoever deployed can read and change them |
| Managed identity `<prefix>-identity` | The app's identity, which Sentinel's export and the Intune connection can sign in as too |
| Log Analytics workspace `<prefix>-logs` | The containers' logs, kept 30 days |

**Cost:** roughly US$75–100 a month in UK South. Most of it is the container app, which
Macs keep busy with their long-held requests, and about $18 is the database. Check the
[Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/) for your
region. A small VM running the Compose bundle costs less, if you'd rather look after a VM.

**The console stays on your networks.** One address serves both Macs and people, and the
caddy container sorts them as the bundle's Caddy does with two hostnames. The agent
endpoints (`/v1/agent/*`) and `/healthz` answer everyone, so Macs report from anywhere. The
console and its API answer only the networks you list, and everyone else gets 403. Caddy
takes the address the ingress saw from the end of `X-Forwarded-For`, so a client can't claim
an allowed address. Inside the virtual network, Altiward's own port 8080 is reachable without caddy;
the console token or single sign-on still guards it there.

The server sends nothing new and runs in your subscription, so
[data handling](../../docs/data-handling.md) applies as it is.

## Before you deploy

- **A role that can grant access:** Owner, or Contributor plus Role Based Access Control
  Administrator, on the resource group. The template gives its managed identity, and you,
  access to the key vault. With Contributor alone the deployment fails on
  `Microsoft.Authorization/roleAssignments/write`.
- **The resource providers** `Microsoft.App`, `Microsoft.DBforPostgreSQL`,
  `Microsoft.KeyVault`, `Microsoft.OperationalInsights`, `Microsoft.Network` and
  `Microsoft.ManagedIdentity`, registered in the subscription. A subscription owner's
  deployment registers them itself.
- **Your public addresses** for the console: your office's and VPN's ranges, such as
  `203.0.113.0/24`. `0.0.0.0/0` allows everyone to reach the sign-in page.
- **The address Macs will use.** Each Mac's credential is tied to the exact `ServerURL` it
  enrolled with, so changing it later makes every Mac enroll again. Decide now whether to
  use the app's own `*.azurecontainerapps.io` address or [your own domain](#your-own-domain),
  and set up your domain before you roll out the agent.

## Deploy

Select the button and fill in the form: a resource group, a region, a name prefix, your
organisation's short name, the networks allowed to open the console, and a database
password. The deployment takes about 15 minutes, most of it Postgres.

With the Azure CLI instead:

```sh
az group create --name rg-altiward --location uksouth
az deployment group create --resource-group rg-altiward \
  --template-uri https://raw.githubusercontent.com/Altiward/altiward/server-v1.0.0/deploy/azure/azuredeploy.json \
  --parameters organisationName=yourcompany consoleAllowedNetworks="203.0.113.0/24" \
  postgresAdminPassword='<a strong password>'
```

Run it once per server. Running the template again over an install generates new tokens
and resets the app's settings and domain. To upgrade, change the image instead
([Upgrading](#upgrading)).

## After it deploys

The deployment's **Outputs** list what you need next:

| Output | Use |
| --- | --- |
| `consoleUrl` | The console, and the agent's `ServerURL` unless you add your own domain |
| `tokensUrl` | The key vault's secrets in the portal |
| `vaultName`, `appName` | For the commands below |
| `identityClientId` | For Sentinel's export and the Intune connection, below |
| `fqdn`, `customDomainVerificationId` | For [your own domain](#your-own-domain) |

1. **Get the tokens.** `console-tokens` and `agent-tokens` each hold your organisation's
   name, `=`, then the token:

   ```sh
   az keyvault secret show --vault-name <vaultName> --name console-tokens --query value -o tsv
   ```

   Use the part after `=`. The console token signs you in to the console, and is a
   break-glass login once single sign-on is set up: the install guide's
   [Console token and break-glass](../../docs/install.md#console-token-and-break-glass)
   covers what's recorded, where to keep it and what to do if it leaks. The agent token is
   the profile's `EnrollmentToken`.

2. **Open the console** at `consoleUrl` from one of the allowed networks, and sign in
   with the console token.

3. **Add your own domain** now if you'll use one ([Your own domain](#your-own-domain)).

4. **Deploy the agent** as in the install guide's
   [step 2](../../docs/install.md#2-deploy-the-agent), with `ServerURL` set to
   `consoleUrl` or your domain. The example profiles are in [`deploy/mdm/`](../mdm/) at the
   release's tag.

5. **Connect your SIEM and set up single sign-on**, as in the install guide's
   [steps 4](../../docs/install.md#4-connect-your-siem) and
   [5](../../docs/install.md#5-sign-in-with-your-identity-provider), setting each
   `ALTIWARD_*` setting on the app ([Changing settings](#changing-settings)) instead of in
   `.env`. For Microsoft Sentinel, sign in as the app's managed identity, with no secret:
   run the Sentinel setup script with `--identity <identityClientId>`
   ([Sentinel's guide](../../integrations/sentinel/README.md#on-azure-container-apps-no-secret)).
   The single sign-on redirect URL is `<consoleUrl>/v1/auth/callback`.

6. **Connect Intune** if you want it ([step 7](../../docs/install.md#7-connect-intune-optional)).
   The app's managed identity reads Intune with no secret: grant it Microsoft Graph's
   `DeviceManagementManagedDevices.Read.All` permission with
   [`intune-read.bicep`](intune-read.bicep) or `integrations/intune/setup.sh --identity
   <identityClientId>`, then set `ALTIWARD_INTUNE_AUTH=managed-identity` and
   `ALTIWARD_INTUNE_CLIENT_ID=<identityClientId>` on the app. The template wants the
   identity's object ID, which `az identity show --name <appName>-identity --resource-group
   <group> --query principalId -o tsv` prints.

## Your own domain

Add it before the agent rolls out. Container Apps gets and renews a free certificate for it.

1. In your DNS, add two records, using the deployment's outputs:
   - `CNAME` from your hostname, such as `altiward.example.com`, to `fqdn`;
   - `TXT` named `asuid.altiward.example.com`, with `customDomainVerificationId` as its value.
2. Bind the hostname and get its certificate:

   ```sh
   az containerapp hostname add --name <appName> --resource-group <group> --hostname altiward.example.com
   az containerapp hostname bind --name <appName> --resource-group <group> --hostname altiward.example.com \
     --environment <prefix>-environment --validation-method CNAME
   ```

3. Point single sign-on at it:

   ```sh
   az containerapp update --name <appName> --resource-group <group> --container-name altiward \
     --set-env-vars ALTIWARD_CONSOLE_URL=https://altiward.example.com
   ```

Then use `https://altiward.example.com` as the agent's `ServerURL`.

## Changing settings

Every setting in the install guide is an environment variable on the app's `altiward`
container, off while it's unset. Changing one starts a new revision, which replaces the
running one in about a minute:

```sh
az containerapp update --name <appName> --resource-group <group> --container-name altiward \
  --set-env-vars ALTIWARD_OIDC_ISSUER=https://login.microsoftonline.com/<directory ID>/v2.0 ALTIWARD_OIDC_CLIENT_ID=<…>
```

Keep secrets, such as `ALTIWARD_OIDC_CLIENT_SECRET` or `ALTIWARD_SPLUNK_HEC_TOKEN`, as app
secrets and refer to them:

```sh
az containerapp secret set --name <appName> --resource-group <group> --secrets oidc-client-secret=<the secret>
az containerapp update --name <appName> --resource-group <group> --container-name altiward \
  --set-env-vars ALTIWARD_OIDC_CLIENT_SECRET=secretref:oidc-client-secret
```

The portal does the same under the app's **Containers** and **Secrets**. Settings that
name a file, such as `ALTIWARD_TRUSTED_CAS_FILE`, need the file mounted from an app secret
as a volume. For Sentinel, the managed identity above needs no file.

**The enrolment limits** are `ALTIWARD_ENROLL_NEW_MACS_PER_HOUR` (default 1000) and
`ALTIWARD_ENROLL_KEYS_PER_MAC_PER_DAY` (default 5) on the `altiward` container. `0` turns
one off. Raise the first before you roll the agent out to more Macs than that in an hour.

**The networks allowed to open the console** are `ALTIWARD_CONSOLE_ALLOW` on the `caddy`
container, space separated:

```sh
az containerapp update --name <appName> --resource-group <group> --container-name caddy \
  --set-env-vars ALTIWARD_CONSOLE_ALLOW="203.0.113.0/24 198.51.100.7/32"
```

## Upgrading

Releases are on [GitHub Releases](https://github.com/Altiward/altiward/releases), and the
console tells admins when one is out. Read the release notes, then change the `altiward`
container's image to the new version:

```sh
az containerapp update --name <appName> --resource-group <group> --container-name altiward \
  --image ghcr.io/altiward/altiward-api:<version>
```

The server updates its database as it starts. Azure keeps point-in-time backups, so
there's nothing to back up first. Going back to an older version isn't supported:
restore the database instead (Backups, under [Running it](#running-it)). To check a release's signature before
you switch to it, see [Checking a release](../../docs/install.md#checking-a-release). Don't
re-run the template to upgrade: it would generate new tokens and drop your settings.

Then roll out the new agent through your MDM as the install guide describes.

## Running it

**Health and logs.** The app's **Revisions and replicas** page shows whether it's running.
Each container's logs, one JSON object per line for Altiward:

```sh
az containerapp logs show --name <appName> --resource-group <group> --container altiward --tail 100
```

The Log Analytics workspace keeps them 30 days, in `ContainerAppConsoleLogs_CL`. They name
Macs by serial, as the bundle's logs do.

**Backups.** Azure keeps 7 days of point-in-time restore for the database; you can raise
it to 35 in the server's **Backup and restore** settings. A restore makes a new server:
put its URL in the key vault's `database-url` secret, then restart the app (below).

**Diagnostics** for a bug report. The image has no shell, so run the binary itself:

```sh
az containerapp exec --name <appName> --resource-group <group> --container altiward \
  --command "/usr/local/bin/altiward-api diagnose"
```

**Changing tokens.** Add a new version of the `agent-tokens` or `console-tokens` secret in
the key vault, as `<organisation>=<new token>`. The app picks it up within 30 minutes, or
at once when you restart it:

```sh
az containerapp revision restart --name <appName> --resource-group <group> \
  --revision "$(az containerapp show --name <appName> --resource-group <group> --query properties.latestRevisionName -o tsv)"
```

Enrolled Macs keep working with a new agent token; new Macs need it in the profile. For
the console token, [The console token](#the-console-token) covers changing it without a
gap, revoking one and turning it off.

**Replicas.** One is enough for most fleets, and more are safe: migrations, SIEM exports,
the silent-Mac alerts and command wake-ups all coordinate through the database. Each
replica adds to the cost:

```sh
az containerapp update --name <appName> --resource-group <group> --min-replicas 2 --max-replicas 2
```

**A bigger database.** Altiward keeps every event for now. Change the server's size or
storage under its **Compute + storage** settings as your fleet grows.

## The console token

The install guide's
[Console token and break-glass](../../docs/install.md#console-token-and-break-glass) says
what the console token is for, what's recorded and what to do after a leak. Here the
tokens are the key vault's `console-tokens` secret, which the app reads as its own secret
of the same name and gives the `altiward` container as `ALTIWARD_CONSOLE_TOKENS`. The app
reads the secret's newest version, so each change is a new version holding every console
token you keep, comma separated. This adds one without the tokens showing on screen or in
your shell history, then restarts the app so it uses the new version at once rather than
within 30 minutes:

```sh
read -rs v    # paste yourcompany=<token>, or several comma separated, then press Enter
az keyvault secret set --vault-name <vaultName> --name console-tokens --value "$v" -o none
unset v
az containerapp revision restart --name <appName> --resource-group <group> \
  --revision "$(az containerapp show --name <appName> --resource-group <group> --query properties.latestRevisionName -o tsv)"
```

**Changing it without a gap:**

1. Add a version holding the old token and the new one,
   `yourcompany=<old>,yourcompany=<new>`, and restart.
2. Sign in with the new token.
3. Add a version holding only the new one, and restart again.
4. Disable every older version, so the old token can't be read from the vault or brought
   back:

   ```sh
   for id in $(az keyvault secret list-versions --vault-name <vaultName> \
       --name console-tokens -o tsv \
       --query "sort_by([?attributes.enabled], &attributes.created)[:-1].id"); do
     az keyvault secret set-attributes --id "$id" --enabled false -o none
   done
   ```

   This keeps the newest version, the one the app reads, enabled. Never disable that one
   while the app uses it: the app could no longer read its tokens, and its next restart
   would fail.

**Revoking one token** is steps 3 and 4, with a version that leaves it out (and a new
token in its place if it was your only way in). `az keyvault secret show`, as in
[Get the tokens](#after-it-deploys), shows what the secret holds now. Then check that its
fingerprint is gone from `tokens` in the diagnostics report ([Running it](#running-it)).
If it's still listed, the app hasn't read the new version yet: restart it again, or wait
up to 30 minutes, and check again.

**Turning it off**, once single sign-on works and gives someone the admin role. First
remove the setting from the `altiward` container, which starts a new revision without it:

```sh
az containerapp update --name <appName> --resource-group <group> --container-name altiward \
  --remove-env-vars ALTIWARD_CONSOLE_TOKENS
```

The server refuses to start without single sign-on and admin groups, and its log says so.
Once the new revision is running and you can sign in through single sign-on, remove the
app's secret and disable every version in the key vault, so that nobody who can read the
vault can use the token, and putting the reference back can't revive it:

```sh
az containerapp secret remove --name <appName> --resource-group <group> \
  --secret-names console-tokens
for id in $(az keyvault secret list-versions --vault-name <vaultName> \
    --name console-tokens --query "[?attributes.enabled].id" -o tsv); do
  az keyvault secret set-attributes --id "$id" --enabled false -o none
done
```

Running the template again over the install brings a token back: it generates a new one
and sets the secret and the setting again.

**Turning it back on**, always with a new token in a new version. Never enable an old
version again: its token may have been read while it was in use.

```sh
read -rs v    # paste yourcompany=<new token>, then press Enter
az keyvault secret set --vault-name <vaultName> --name console-tokens --value "$v" -o none
unset v
identity=$(az identity show --name <appName>-identity --resource-group <group> --query id -o tsv)
az containerapp secret set --name <appName> --resource-group <group> --secrets \
  "console-tokens=keyvaultref:https://<vaultName>.vault.azure.net/secrets/console-tokens,identityref:$identity"
az containerapp update --name <appName> --resource-group <group> --container-name altiward \
  --set-env-vars ALTIWARD_CONSOLE_TOKENS=secretref:console-tokens
```

The reference names no version, as the template's does, so the app reads the newest.

## Deleting it

Delete the resource group. The key vault stays recoverable for 90 days, and its name stays
taken in your tenant until then. To deploy again with the same prefix in the same
resource group sooner, purge it: `az keyvault purge --name <vaultName>`.

## Troubleshooting

- **`LocationIsOfferRestricted`, or Postgres isn't available:** your subscription can't
  create Postgres in that region. Deploy to another region.
- **`AuthorizationFailed` on `roleAssignments/write`:** you need Owner, or Role Based
  Access Control Administrator too ([Before you deploy](#before-you-deploy)).
- **The vault name is already in use, in a deleted state:** purge the old vault, or use
  another prefix ([Deleting it](#deleting-it)).
- **The revision fails with "Unable to get value using Managed identity":** the key vault
  access was granted moments before the app started and hadn't applied yet. Restart the
  revision after a few minutes.
- **403 for the console:** you're outside `ALTIWARD_CONSOLE_ALLOW` on the `caddy` container.
  Macs aren't affected.
