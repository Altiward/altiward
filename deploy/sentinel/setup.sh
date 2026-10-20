#!/bin/bash
# Sets up Altiward's export to Microsoft Sentinel in an existing Log Analytics workspace,
# then prints the five lines to add to the Altiward server's .env (README.md, "Setup").
# Run it in Azure Cloud Shell (Bash), or wherever the Azure CLI is signed in.
#
#   ./setup.sh --resource-group <group> --workspace <name> [options]
#
#   --subscription <id or name>  the workspace's subscription, if it isn't your current one
#   --app-name <name>            the app registration's name (default "Altiward SIEM export")
#   --private-link               the workspace uses Azure Monitor Private Link: send through
#                                a data collection endpoint, which you add to the scope
#   --vm <name>                  the Altiward server runs on this Azure VM: sign in as its
#                                managed identity, with no app registration or secret
#   --vm-resource-group <group>  the VM's resource group, if it isn't the workspace's
#
# It creates, in the workspace's resource group and region:
#
#   - the table AltiwardOCSF_CL, unless it exists with the right columns;
#   - the data collection rule dcr-altiward, which has its own ingestion URL ("kind":
#     "Direct"); with --private-link, also the endpoint dce-altiward;
#   - the app registration, with a one-year secret and Monitoring Metrics Publisher on the
#     rule, unless an app of that name exists. Then it leaves the app's secrets alone.
#     With --vm, no app: the VM gets a system-assigned managed identity, and the role.
#
# It's safe to run again. The .env lines go to standard output and everything else to
# standard error. The secret is shown once and never written to a file.
set -euo pipefail

TABLE=AltiwardOCSF_CL
STREAM=Custom-AltiwardOCSF
RULE=dcr-altiward
ENDPOINT=dce-altiward
ROLE="Monitoring Metrics Publisher"
DCR_API=2023-03-11 # rules and endpoints; returns a Direct rule's own ingestion URL
TABLE_API=2022-10-01
# The stream's columns: sentinel.Columns in integrations/sentinel/row.go (schema_test.go checks).
SCHEMA="TimeGenerated:datetime EventUid:string TenantUid:string SessionUid:string ClassUid:int
ActivityId:int SeverityId:int DeviceSerial:string UserName:string Message:string Ocsf:dynamic"

say() { printf '%s\n' "$*" >&2; }
die() { printf 'setup.sh: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '5,14s/^# \{0,1\}//p' "$0" >&2; exit "${1:-2}"; }

RG='' WORKSPACE='' SUBSCRIPTION='' APP_NAME="Altiward SIEM export" PRIVATE_LINK='' VM='' VM_RG=''
while [ $# -gt 0 ]; do
  case "$1" in
  -g|--resource-group|-w|--workspace|-s|--subscription|--app-name|--vm|--vm-resource-group)
    [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"
    case "$1" in
    -g|--resource-group) RG="$2" ;;
    -w|--workspace) WORKSPACE="$2" ;;
    -s|--subscription) SUBSCRIPTION="$2" ;;
    --app-name) APP_NAME="$2" ;;
    --vm) VM="$2" ;;
    --vm-resource-group) VM_RG="$2" ;;
    esac
    shift 2 ;;
  --private-link) PRIVATE_LINK=1; shift ;;
  -h|--help) usage 0 ;;
  *) say "setup.sh: unknown option $1"; usage ;;
  esac
done
[ -n "$RG" ] && [ -n "$WORKSPACE" ] || { say "setup.sh: needs --resource-group and --workspace"; usage; }
[ -z "$VM_RG" ] || [ -n "$VM" ] || die "--vm-resource-group goes with --vm <name>."
VM_RG=${VM_RG:-$RG}
command -v az >/dev/null || die "needs the Azure CLI (az). Azure Cloud Shell has it."

ERRFILE="$(mktemp)"
trap 'rm -f "$ERRFILE"' EXIT

# arm_get <resource ID?api-version> <query>: prints the query's result, or returns 3 if
# the resource doesn't exist. Any other error stops the script.
arm_get() {
  if az rest --method get --url "$1" --query "$2" -o tsv 2>"$ERRFILE"; then return 0; fi
  if grep -Eqi 'not ?found' "$ERRFILE"; then return 3; fi
  cat "$ERRFILE" >&2
  return 1
}
# A tsv value that JMESPath found nothing for comes out as "None".
value() { [ "$1" = None ] || printf '%s' "$1"; }

# 1. Signed in, and the workspace.
if [ -n "$SUBSCRIPTION" ]; then
  SUB_ID=$(az account show --subscription "$SUBSCRIPTION" --query id -o tsv) ||
    die "can't use subscription $SUBSCRIPTION. Check the name, or run az login."
else
  SUB_ID=$(az account show --query id -o tsv) || die "the Azure CLI isn't signed in. Run az login."
fi
TENANT_ID=$(az account show --subscription "$SUB_ID" --query tenantId -o tsv)
LAW_ID=$(az monitor log-analytics workspace show --subscription "$SUB_ID" -g "$RG" -n "$WORKSPACE" --query id -o tsv) ||
  die "can't find the workspace $WORKSPACE in resource group $RG (subscription $SUB_ID)."
LOCATION=$(az monitor log-analytics workspace show --subscription "$SUB_ID" -g "$RG" -n "$WORKSPACE" --query location -o tsv)
say "Workspace $WORKSPACE in $LOCATION (subscription $SUB_ID)."
state=$(az provider show --subscription "$SUB_ID" -n Microsoft.Insights --query registrationState -o tsv)
[ "$state" = Registered ] ||
  die "the subscription can't hold data collection rules yet (Microsoft.Insights is $state). Run az provider register --subscription $SUB_ID -n Microsoft.Insights, wait until it's Registered, and run this again."

# 2. The table.
rc=0
have=$(arm_get "$LAW_ID/tables/$TABLE?api-version=$TABLE_API" \
  "properties.schema.[columns, standardColumns][].[name, type]") || rc=$?
case $rc in
0)
  wrong=
  for c in $SCHEMA; do
    name=${c%%:*} want=${c#*:}
    got=$(printf '%s\n' "$have" | awk -F'\t' -v n="$name" '$1 == n { print tolower($2); exit }')
    [ "$got" = "$want" ] || wrong="$wrong
  $name should be $want, but is ${got:-missing}"
  done
  [ -z "$wrong" ] || die "the table $TABLE exists with other columns:$wrong
Change those columns, or delete the table if nothing else uses it, and run this again."
  say "Table $TABLE: exists with the right columns." ;;
3)
  spec=
  for c in $SCHEMA; do spec="$spec ${c%%:*}=${c#*:}"; done
  # shellcheck disable=SC2086 # one argument per column
  az monitor log-analytics workspace table create --subscription "$SUB_ID" -g "$RG" \
    --workspace-name "$WORKSPACE" -n "$TABLE" --columns $spec -o none
  say "Table $TABLE: created." ;;
*) die "can't read the workspace's tables." ;;
esac

# 3. The endpoint, for private link only, and the rule.
GROUP_ID=${LAW_ID%%/providers/*}
RULE_ID="$GROUP_ID/providers/Microsoft.Insights/dataCollectionRules/$RULE"
dce_property=
if [ -n "$PRIVATE_LINK" ]; then
  DCE_ID="$GROUP_ID/providers/Microsoft.Insights/dataCollectionEndpoints/$ENDPOINT"
  rc=0
  url=$(arm_get "$DCE_ID?api-version=$DCR_API" properties.logsIngestion.endpoint) || rc=$?
  case $rc in
  0) say "Endpoint $ENDPOINT: exists, left as it is." ;;
  3)
    url=$(az rest --method put --url "$DCE_ID?api-version=$DCR_API" \
      --body "{\"location\":\"$LOCATION\",\"properties\":{\"networkAcls\":{\"publicNetworkAccess\":\"Enabled\"}}}" \
      --query properties.logsIngestion.endpoint -o tsv)
    say "Endpoint $ENDPOINT: created." ;;
  *) die "can't read the endpoint $ENDPOINT." ;;
  esac
  INGEST_URL=$(value "$url")
  [ -n "$INGEST_URL" ] || die "the endpoint $ENDPOINT has no logs ingestion URL."
  dce_property="\"dataCollectionEndpointId\":\"$DCE_ID\","
fi

columns=
for c in $SCHEMA; do columns="$columns{\"name\":\"${c%%:*}\",\"type\":\"${c#*:}\"},"; done
body="{\"location\":\"$LOCATION\",\"kind\":\"Direct\",\"properties\":{$dce_property\"streamDeclarations\":{\"$STREAM\":{\"columns\":[${columns%,}]}},\"destinations\":{\"logAnalytics\":[{\"workspaceResourceId\":\"$LAW_ID\",\"name\":\"workspace\"}]},\"dataFlows\":[{\"streams\":[\"$STREAM\"],\"destinations\":[\"workspace\"],\"transformKql\":\"source\",\"outputStream\":\"Custom-${TABLE}\"}]}}"
out=$(az rest --method put --url "$RULE_ID?api-version=$DCR_API" --body "$body" \
  --query "[properties.immutableId, properties.endpoints.logsIngestion]" -o tsv) ||
  die "can't create the rule $RULE. If it's left from setting up by hand, delete it and run this again."
DCR_IMMUTABLE_ID=$(value "$(printf '%s\n' "$out" | sed -n 1p)")
direct_url=$(value "$(printf '%s\n' "$out" | sed -n 2p)")
[ -n "$DCR_IMMUTABLE_ID" ] || die "the rule $RULE came back without an immutable ID."
if [ -z "$PRIVATE_LINK" ]; then
  INGEST_URL=$direct_url
  [ -n "$INGEST_URL" ] || die "the rule $RULE has no ingestion URL of its own: it was made before Azure added them, or without \"kind\": \"Direct\". Delete it and run this again, or run with --private-link."
fi
say "Rule $RULE: ready ($DCR_IMMUTABLE_ID)."

# 4. Who signs in: the VM's managed identity, or an app. Creating credentials for an app
# that exists would delete its secrets and cut off a server that's sending, so an existing
# app keeps them.
SECRET=
if [ -n "$VM" ]; then
  principal=$(az vm identity assign --subscription "$SUB_ID" -g "$VM_RG" -n "$VM" --query systemAssignedIdentity -o tsv) ||
    die "can't give the VM $VM (resource group $VM_RG) a managed identity."
  [ -n "$principal" ] || die "the VM $VM came back without a system-assigned identity."
  if [ -z "$(az role assignment list --assignee "$principal" --role "$ROLE" --scope "$RULE_ID" --query "[].id" -o tsv)" ]; then
    az role assignment create --assignee-object-id "$principal" --assignee-principal-type ServicePrincipal \
      --role "$ROLE" --scope "$RULE_ID" -o none
    say "VM $VM: managed identity given $ROLE on the rule."
  else
    say "VM $VM: managed identity has $ROLE on the rule."
  fi
  say ""
  say "Add these lines to .env in the Altiward deployment directory, then run docker compose up -d."
  say "Leave out ALTIWARD_SENTINEL_TENANT_ID, _CLIENT_ID and _CLIENT_SECRET."
  say ""
  echo "ALTIWARD_SENTINEL_ENDPOINT=$INGEST_URL"
  echo "ALTIWARD_SENTINEL_DCR_ID=$DCR_IMMUTABLE_ID"
  echo "ALTIWARD_SENTINEL_AUTH=managed-identity"
  host=${INGEST_URL#https://}
  say ""
  say "The server needs outbound HTTPS to ${host%%/*}, and its container must reach 169.254.169.254."
  say "A new role assignment can take up to 30 minutes to work; until then the export retries."
  [ -z "$PRIVATE_LINK" ] || say "Add the endpoint $ENDPOINT to the workspace's Azure Monitor private link scope."
  exit 0
fi

apps=$(az ad app list --display-name "$APP_NAME" --query "[].appId" -o tsv)
count=$(printf '%s\n' "$apps" | grep -c . || true)
if [ "$count" -gt 1 ]; then
  die "$count app registrations are named \"$APP_NAME\". Pass --app-name with a name of its own."
elif [ "$count" -eq 1 ]; then
  CLIENT_ID=$apps
  sp=$(az ad sp show --id "$CLIENT_ID" --query id -o tsv) ||
    die "the app \"$APP_NAME\" ($CLIENT_ID) has no service principal."
  if [ -z "$(az role assignment list --assignee "$CLIENT_ID" --role "$ROLE" --scope "$RULE_ID" --query "[].id" -o tsv)" ]; then
    az role assignment create --assignee-object-id "$sp" --assignee-principal-type ServicePrincipal \
      --role "$ROLE" --scope "$RULE_ID" -o none
    say "App \"$APP_NAME\": exists; given $ROLE on the rule."
  else
    say "App \"$APP_NAME\": exists, with $ROLE on the rule."
  fi
else
  out=$(az ad sp create-for-rbac -n "$APP_NAME" --years 1 --role "$ROLE" --scopes "$RULE_ID" \
    --query "[appId, password]" -o tsv --only-show-errors)
  CLIENT_ID=$(printf '%s\n' "$out" | sed -n 1p)
  SECRET=$(printf '%s\n' "$out" | sed -n 2p)
  [ -n "$CLIENT_ID" ] && [ -n "$SECRET" ] || die "creating the app \"$APP_NAME\" returned no secret."
  expires=$(date -u -v+1y +%Y-%m-%d 2>/dev/null || date -u -d '+1 year' +%Y-%m-%d)
  say "App \"$APP_NAME\": created, with $ROLE on the rule."
fi

# 5. The .env lines.
say ""
say "Add these lines to .env in the Altiward deployment directory, then run docker compose up -d:"
say ""
echo "ALTIWARD_SENTINEL_ENDPOINT=$INGEST_URL"
echo "ALTIWARD_SENTINEL_DCR_ID=$DCR_IMMUTABLE_ID"
echo "ALTIWARD_SENTINEL_TENANT_ID=$TENANT_ID"
echo "ALTIWARD_SENTINEL_CLIENT_ID=$CLIENT_ID"
if [ -n "$SECRET" ]; then
  echo "ALTIWARD_SENTINEL_CLIENT_SECRET=$SECRET"
  say ""
  say "The secret is shown only this once. Expires $expires: add a new one before then (README.md, \"Rotate the secret\")."
else
  say ""
  say "The app existed, so its secret is unchanged: keep ALTIWARD_SENTINEL_CLIENT_SECRET from your .env."
  say "If you don't have it, add a secret with az ad app credential reset --id $CLIENT_ID --append --years 1"
  say "and use its password (README.md, \"Rotate the secret\")."
fi
host=${INGEST_URL#https://}
say "The server needs outbound HTTPS to login.microsoftonline.com and ${host%%/*}."
say "A new role assignment can take up to 30 minutes to work; until then the export retries."
if [ -n "$PRIVATE_LINK" ]; then
  say "Add the endpoint $ENDPOINT to the workspace's Azure Monitor private link scope."
fi
