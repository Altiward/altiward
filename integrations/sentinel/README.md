# Microsoft Sentinel

Events go to a custom Log Analytics table, `AltiwardOCSF_CL`, through the Azure Monitor
Logs Ingestion API. Each row carries a few columns for querying, plus the full OCSF record
in `Ocsf`.

## Setup

This takes about 10 minutes in your existing Sentinel workspace. A script creates three
things in Azure, then prints five lines for Altiward's `.env`:

| In Azure | What it's for |
| --- | --- |
| Table `AltiwardOCSF_CL` | Where the events land ([columns](#the-tables-columns)) |
| Data Collection Rule (DCR) `dcr-altiward` | Routes the stream `Custom-AltiwardOCSF` into the table. It has its own ingestion URL, which Altiward sends to |
| App registration `Altiward SIEM export`, with a client secret | How Altiward signs in. It gets *Monitoring Metrics Publisher* on the DCR and nothing else |

If the workspace uses Azure Monitor Private Link, the script also creates a Data
Collection Endpoint (DCE), `dce-altiward`, and Altiward sends to that instead.

You need Contributor and User Access Administrator (or Owner) on the workspace's resource
group, and the right to register apps in Entra ID. The Altiward server needs outbound HTTPS
to `login.microsoftonline.com` and to the rule's `*.ingest.monitor.azure.com` host, which
the script prints.

No Sentinel workspace yet? Create a Log Analytics workspace, then turn Sentinel on for it.
A subscription that has never used Sentinel needs two resource providers registered
first, or turning it on fails with `MissingSubscriptionRegistration`:

```sh
az provider register -n Microsoft.SecurityInsights --wait
az provider register -n Microsoft.OperationsManagement --wait
```

### 1. Run the setup script

The script is `integrations/sentinel/setup.sh` in the server release bundle
(source checkout: `deploy/sentinel/setup.sh`). Open
[Azure Cloud Shell](https://shell.azure.com) in Bash, upload the file with *Manage files* >
*Upload*, and run:

```sh
bash setup.sh --resource-group <the workspace's resource group> --workspace <the workspace's name>
```

Or run it on your own machine with the Azure CLI, after `az login`. It needs no CLI
extensions. Options:

| Option | When |
| --- | --- |
| `--subscription <id or name>` | The workspace isn't in your current subscription |
| `--private-link` | The workspace uses Azure Monitor Private Link |
| `--app-name <name>` | You want the app registration called something else |

The script creates everything in the workspace's resource group and region, and says what
it found and did as it goes. It checks the workspace before it changes anything. If the
table exists with other columns, it stops and names them. It's safe to run again: it
creates only what's missing.

It ends with the five lines for step 2. The secret is shown only this once and isn't saved
to a file, so copy it straight into `.env`. It expires in a year (see
[Rotate the secret](#rotate-the-secret)).

The script creates the app only if no app has its name. An app that exists keeps its
secrets, because creating a new one would delete them and cut off a server that's
already sending. The script then prints four lines, without the secret: keep the secret
you have, or add one as in [Rotate the secret](#rotate-the-secret).

With `--private-link`, add `dce-altiward` to the workspace's Azure Monitor Private Link
Scope afterwards.

### 2. Give Altiward the values

Add the five lines to `.env` in your deployment directory, then run `docker compose up -d`.
They look like this:

```sh
ALTIWARD_SENTINEL_ENDPOINT=https://dcr-altiward-abcd.westeurope-1.ingest.monitor.azure.com
ALTIWARD_SENTINEL_DCR_ID=dcr-0123456789abcdef0123456789abcdef
ALTIWARD_SENTINEL_TENANT_ID=<your tenant ID>
ALTIWARD_SENTINEL_CLIENT_ID=<the app's client ID>
ALTIWARD_SENTINEL_CLIENT_SECRET=<the secret>
```

Check that it started with Sentinel turned on:

```sh
docker compose logs altiward | grep -e listening -e fatal | tail -1
```

The `listening` line should list `sentinel` under `sinks`. If a value is missing, the
server doesn't start, and the line says which.

### 3. Check events arrive

Altiward sends only events that happen after you turn the export on; to send earlier ones
too, see `replay-exports` in the install guide's "Connect your SIEM". To make an event
now, sign in to the console as an admin and choose *Send test event* in Settings, under
SIEM export. After 5 to 15 minutes (a new table is slow to show its first rows), run this
in the workspace's Logs:

```kql
AltiwardOCSF_CL
| sort by TimeGenerated desc
| take 10
```

If nothing arrives, Settings shows the export as *Failing*, with its last error. You can
also run `docker compose exec altiward /usr/local/bin/altiward-api diagnose` and look at
`problems`, or `docker compose logs altiward | grep "export failed"`:

| The error contains | Likely cause |
| --- | --- |
| `sentinel: token: token endpoint HTTP 400` or `401` | Wrong tenant ID, client ID or secret |
| `sentinel: HTTP 403` | The role assignment hasn't taken effect yet (allow 30 minutes), or it's on a different DCR |
| `sentinel: HTTP 404` | Wrong DCR immutable ID or endpoint |
| `sentinel: Post` | The server can't reach the ingestion host: check its firewall, or with private link, that the DCE is in the scope |
| No error, but no rows | You're looking in a different workspace, or the first rows haven't shown yet |

Nothing is lost while it fails: events wait in Postgres and are retried with a backoff of
30 seconds, doubling up to an hour. After a fix, choose *Retry now* in Settings to send
the backlog straight away.

### Rotate the secret

See when it expires with
`az ad app credential list --id <appId> --query "[].endDateTime" -o tsv`. Before then, add
a new secret next to the old one, so the export keeps running:

```sh
az ad app credential reset --id <appId> --append --years 1
```

Put the new `password` in `.env` as `ALTIWARD_SENTINEL_CLIENT_SECRET` and run
`docker compose up -d`. Once events are arriving again, delete the old secret in the app's
*Certificates & secrets* page in the Entra admin center.

### On an Azure VM: no secret

When the server runs on an Azure VM, it can sign in as the VM's managed identity instead
of an app registration. There's no secret to store, and none that expires. Run the script
with the VM's name (and `--vm-resource-group` if the VM is in another resource group):

```sh
bash setup.sh --resource-group <the workspace's resource group> --workspace <the workspace's name> --vm <the VM's name>
```

It creates no app. It gives the VM a system-assigned managed identity, grants that
*Monitoring Metrics Publisher* on the rule, and prints three lines for `.env`:
`ALTIWARD_SENTINEL_ENDPOINT`, `ALTIWARD_SENTINEL_DCR_ID` and
`ALTIWARD_SENTINEL_AUTH=managed-identity`. Leave out the tenant ID, client ID and client
secret. For a user-assigned identity instead, grant it the role yourself and set
`ALTIWARD_SENTINEL_CLIENT_ID` to its client ID.

The server gets its token from the VM's Instance Metadata Service at `169.254.169.254`,
never through a proxy. The example deployment's containers reach it through Compose's
default network; `altiward-api diagnose` checks that they can, as `sentinel-identity`.
A new role assignment can take a few minutes to apply, and until then uploads fail with
HTTP 403 and are retried.

### Setting it up by hand

This does what the script does, if you'd rather run each command yourself. Run it in one
Cloud Shell session: if Cloud Shell reconnects, its variables are gone, so set them again.

```sh
az account set --subscription <the workspace's subscription>
RG=<the workspace's resource group>
LAW=<the workspace's name>
LAW_ID=$(az monitor log-analytics workspace show -g $RG -n $LAW --query id -o tsv)
LOC=$(az monitor log-analytics workspace show -g $RG -n $LAW --query location -o tsv)
DCR_ID=${LAW_ID%%/providers/*}/providers/Microsoft.Insights/dataCollectionRules/dcr-altiward
echo "$LAW_ID in $LOC"
```

**The table.**

```sh
az monitor log-analytics workspace table create -g $RG --workspace-name $LAW -n AltiwardOCSF_CL \
  --columns TimeGenerated=datetime EventUid=string TenantUid=string SessionUid=string \
  ClassUid=int ActivityId=int SeverityId=int DeviceSerial=string UserName=string Message=string Ocsf=dynamic
```

**The rule.** `"kind": "Direct"` gives the rule its own ingestion URL. The command prints
the rule's immutable ID (`ALTIWARD_SENTINEL_DCR_ID`) and that URL
(`ALTIWARD_SENTINEL_ENDPOINT`):

```sh
cat > dcr-altiward.json <<EOF
{ "location": "$LOC", "kind": "Direct", "properties": {
  "streamDeclarations": { "Custom-AltiwardOCSF": { "columns": [
    {"name":"TimeGenerated","type":"datetime"},{"name":"EventUid","type":"string"},
    {"name":"TenantUid","type":"string"},{"name":"SessionUid","type":"string"},
    {"name":"ClassUid","type":"int"},{"name":"ActivityId","type":"int"},
    {"name":"SeverityId","type":"int"},{"name":"DeviceSerial","type":"string"},
    {"name":"UserName","type":"string"},{"name":"Message","type":"string"},
    {"name":"Ocsf","type":"dynamic"} ] } },
  "destinations": { "logAnalytics": [{ "workspaceResourceId": "$LAW_ID", "name": "workspace" }] },
  "dataFlows": [{ "streams": ["Custom-AltiwardOCSF"], "destinations": ["workspace"],
                  "transformKql": "source", "outputStream": "Custom-AltiwardOCSF_CL" }] } }
EOF
az rest --method put --url "$DCR_ID?api-version=2023-03-11" --body @dcr-altiward.json \
  --query "[properties.immutableId, properties.endpoints.logsIngestion]" -o tsv
```

With private link, first create an endpoint and add it to your private link scope:

```sh
DCE_ID=${LAW_ID%%/providers/*}/providers/Microsoft.Insights/dataCollectionEndpoints/dce-altiward
az rest --method put --url "$DCE_ID?api-version=2023-03-11" \
  --body "{\"location\":\"$LOC\",\"properties\":{\"networkAcls\":{\"publicNetworkAccess\":\"Enabled\"}}}" \
  --query properties.logsIngestion.endpoint -o tsv
```

Then add `"dataCollectionEndpointId": "$DCE_ID",` at the start of the rule's
`"properties"`, and use the endpoint's URL, which the command prints, as
`ALTIWARD_SENTINEL_ENDPOINT`.

**The app.** Run this once:

```sh
az ad sp create-for-rbac -n "Altiward SIEM export" --years 1 \
  --role "Monitoring Metrics Publisher" --scopes $DCR_ID
```

It prints `appId` (`ALTIWARD_SENTINEL_CLIENT_ID`), `password`
(`ALTIWARD_SENTINEL_CLIENT_SECRET`) and `tenant` (`ALTIWARD_SENTINEL_TENANT_ID`). The
password is shown only once. Running the command again resets the app's secret, which
cuts off a server that's already sending; if you lose the password, rotate it instead.
Then carry on from [step 2](#2-give-altiward-the-values).

### The table's columns

| Column | Type | |
| --- | --- | --- |
| `TimeGenerated` | datetime | When it happened |
| `EventUid` | string | Event ID, unique per event |
| `TenantUid` | string | Tenant |
| `SessionUid` | string | Elevation session |
| `ClassUid` | int | OCSF class |
| `ActivityId` | int | OCSF activity |
| `SeverityId` | int | OCSF severity |
| `DeviceSerial` | string | The Mac's serial number |
| `UserName` | string | The user, or who acted for a console action |
| `Message` | string | A sentence describing the event |
| `Ocsf` | dynamic | The full OCSF record |

## Workbook

The **Altiward overview** workbook shows the figures from the console's Overview in
Sentinel, built from the events in `AltiwardOCSF_CL`:

- **Now:** who holds admin rights, by where they came from (Privileges or without a
  grant), and what needs a look: rights past their expiry, Macs failing an
  integrity check, Macs not checking in.
- **The period** (7, 30 or 90 days): elevations and how many were without a grant,
  elevations per day, time held against time allowed, the people and Macs that elevate
  most, and the findings raised.
- **Health:** integrity checks failing now, and agent versions.

It's in the server release bundle in two forms. Each of the first two ways installs the
workbook, or updates it in place when you run it again after an upgrade:

- **Azure CLI or Cloud Shell**, with `workbook.arm.json`:

  ```sh
  az deployment group create -g <the workspace's resource group> \
    --template-file workbook.arm.json --parameters workspaceName=<the workspace's name>
  ```

- **Azure portal:** open *Deploy a custom template*, choose *Build your own template in
  the editor*, load `workbook.arm.json` and save. Pick the workspace's resource group, enter
  the workspace's name and create it.
- **In Sentinel:** open *Workbooks*, *Add workbook*, *Edit*, then the Advanced editor
  (`</>`). Replace its content with `workbook.json`, apply, and save. This makes a new
  workbook each time, so delete the old one after an upgrade.

It shows under *Workbooks* > *My workbooks*. Installing needs *Workbook Contributor* (or
Contributor) on the resource group; reading it needs *Microsoft Sentinel Reader* or *Log
Analytics Reader* on the workspace.

What it can't show: *Now* looks back 90 days, or your retention if that's shorter, so
rights granted before then and still held aren't counted. Agent versions list only the Macs
that sent an event in the period, because health check-ins aren't exported. Whether
each SIEM is keeping up is on the console's Overview.

## Analytics rules and hunting queries

Detections for these events are in
[altiward-siem](https://github.com/Altiward/altiward-siem): Sentinel analytics rules you can
deploy to your workspace in one step, and hunting queries. Each says whether it needs the
Altiward server or also works with [altiward-forwarder](https://github.com/Altiward/altiward-forwarder)'s
events.
