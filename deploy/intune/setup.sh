#!/bin/bash
# Lets the Altiward server read the Macs Microsoft Intune manages, by granting a managed
# identity or an app registration the Microsoft Graph application permission
# DeviceManagementManagedDevices.Read.All, then prints the lines to add to the server's
# .env (README.md). Run it in Azure Cloud Shell (Bash), or wherever the Azure CLI is
# signed in as someone who can grant Graph permissions.
#
#   ./setup.sh --vm <resource group>/<vm name> | --identity <client ID> | --app <name> [--yes]
#
#   --vm <group>/<name>   the Altiward server runs on this Azure VM: give it a system-assigned
#                         managed identity if it has none, and grant that
#   --identity <id>       grant this user-assigned managed identity, by client ID: the Deploy
#                         to Azure template's identityClientId, or one you gave the server
#   --app <name>          make an app registration of this name, with a one-year secret, and
#                         grant it. An app of that name that exists is granted but keeps its
#                         secrets
#   --yes                 don't ask before changing anything
#
# It changes nothing but that one grant (and, with --app, the registration). It is safe to
# run again. The .env lines go to standard output and everything else to standard error.
# An app's secret is shown once and never written to a file.
set -euo pipefail

GRAPH_APP=00000003-0000-0000-c000-000000000000 # Microsoft Graph's well-known application ID
PERMISSION=DeviceManagementManagedDevices.Read.All

say() { printf '%s\n' "$*" >&2; }
die() { printf 'setup.sh: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '8,17s/^# \{0,1\}//p' "$0" >&2; exit "${1:-2}"; }

VM='' IDENTITY='' APP_NAME='' YES=''
while [ $# -gt 0 ]; do
  case "$1" in
  --vm|--identity|--app)
    [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"
    case "$1" in
    --vm) VM="$2" ;;
    --identity) IDENTITY="$2" ;;
    --app) APP_NAME="$2" ;;
    esac
    shift 2 ;;
  -y|--yes) YES=1; shift ;;
  -h|--help) usage 0 ;;
  *) say "setup.sh: unknown option $1"; usage ;;
  esac
done
[ -n "$VM$IDENTITY$APP_NAME" ] || { say "setup.sh: needs --vm, --identity or --app"; usage; }
modes=0
for m in "$VM" "$IDENTITY" "$APP_NAME"; do [ -z "$m" ] || modes=$((modes + 1)); done
[ "$modes" -eq 1 ] || die "--vm, --identity and --app each set up a different sign-in: pass one of them."
VM_RG='' VM_NAME=''
if [ -n "$VM" ]; then
  VM_RG=${VM%%/*} VM_NAME=${VM#*/}
  { [ "$VM_RG" != "$VM" ] && [ -n "$VM_RG" ] && [ -n "$VM_NAME" ] && [[ "$VM_NAME" != */* ]]; } ||
    die "--vm wants <resource group>/<vm name>, such as rg-altiward/vm-altiward."
fi
command -v az >/dev/null || die "needs the Azure CLI (az). Azure Cloud Shell has it."

ERRFILE="$(mktemp)"
trap 'rm -f "$ERRFILE"' EXIT

# 1. Signed in, and Graph's permission in this tenant. Both are read-only.
TENANT_ID=$(az account show --query tenantId -o tsv 2>/dev/null) || die "the Azure CLI isn't signed in. Run az login."
ROLE_ID=$(az ad sp show --id "$GRAPH_APP" \
  --query "appRoles[?value=='$PERMISSION'] | [0].id" -o tsv) ||
  die "can't read Microsoft Graph's permissions in this tenant."
{ [ -n "$ROLE_ID" ] && [ "$ROLE_ID" != None ]; } || die "Microsoft Graph has no application permission $PERMISSION in this tenant."
GRAPH_SP=$(az ad sp show --id "$GRAPH_APP" --query id -o tsv) || die "can't find Microsoft Graph's service principal."
say "Signed in to tenant $TENANT_ID."

# grant <principal object ID> <who>: assigns the permission, or says it's there already.
grant() {
  local principal="$1" who="$2"
  if az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$principal/appRoleAssignments" \
    --body "{\"principalId\":\"$principal\",\"resourceId\":\"$GRAPH_SP\",\"appRoleId\":\"$ROLE_ID\"}" -o none 2>"$ERRFILE"; then
    say "$who: granted $PERMISSION."
  elif grep -qi 'already exists' "$ERRFILE"; then
    say "$who: $PERMISSION is already granted."
  else
    cat "$ERRFILE" >&2
    die "couldn't grant $PERMISSION to $who. Granting a Graph permission takes the Privileged Role Administrator or Global Administrator role."
  fi
}

# confirm <what this will do>: asks, unless --yes. Nothing is asked without a terminal.
confirm() {
  [ -z "$YES" ] || return 0
  [ -t 0 ] || die "this changes your tenant, and nobody can be asked: add --yes to go ahead."
  say "$1"
  read -r -p "Go ahead? [y/N] " answer >&2 || answer=n
  case "$answer" in y|Y|yes|YES) ;; *) die "stopped; nothing was changed." ;; esac
}

# 2. Who gets the permission.
if [ -n "$VM" ] || [ -n "$IDENTITY" ]; then
  if [ -n "$VM" ]; then
    who="VM $VM_NAME"
    confirm "This gives the VM $VM_NAME (resource group $VM_RG) a system-assigned managed identity, if it has none, and lets that identity read the Macs Intune manages ($PERMISSION)."
    principal=$(az vm identity assign -g "$VM_RG" -n "$VM_NAME" --query systemAssignedIdentity -o tsv) ||
      die "can't give the VM $VM_NAME (resource group $VM_RG) a managed identity."
    [ -n "$principal" ] || die "the VM $VM_NAME came back without a system-assigned identity."
  else
    who="Managed identity $IDENTITY"
    principal=$(az ad sp show --id "$IDENTITY" --query id -o tsv 2>"$ERRFILE") ||
      die "can't find a managed identity with client ID $IDENTITY."
    confirm "This lets the managed identity $IDENTITY read the Macs Intune manages ($PERMISSION)."
  fi
  grant "$principal" "$who"
  say ""
  if [ -n "$VM" ]; then
    say "Add this line to .env in the Altiward deployment directory, then run docker compose up -d."
  else
    say "Add these settings to the Altiward server."
    say "On Azure Container Apps: az containerapp update --name <app> --resource-group <group> --container-name altiward --set-env-vars <each line>"
    say "On a VM with this identity assigned: add them to .env and run docker compose up -d."
  fi
  say ""
  echo "ALTIWARD_INTUNE_AUTH=managed-identity"
  [ -z "$IDENTITY" ] || echo "ALTIWARD_INTUNE_CLIENT_ID=$IDENTITY"
  say ""
  say "The server needs outbound HTTPS to graph.microsoft.com. On a VM, its container must also reach 169.254.169.254."
  say "A new permission can take a few minutes to work, and Azure caches a managed identity's tokens, so"
  say "a server that asked just before the grant can take longer. Until then the sync's status shows the error."
  say "All done: the identity can read the Macs Intune manages, and nothing else in Intune."
  exit 0
fi

# An app that exists keeps its secrets: resetting them would cut off a server that's reading.
apps=$(az ad app list --display-name "$APP_NAME" --query "[].appId" -o tsv)
count=$(printf '%s\n' "$apps" | grep -c . || true)
if [ "$count" -gt 1 ]; then
  die "$count app registrations are named \"$APP_NAME\". Pass --app with a name of its own."
fi
SECRET=''
if [ "$count" -eq 1 ]; then
  CLIENT_ID=$apps
  confirm "This lets the app \"$APP_NAME\" ($CLIENT_ID) read the Macs Intune manages ($PERMISSION), with admin consent. Its secrets stay as they are."
  az ad sp show --id "$CLIENT_ID" --query id -o tsv >/dev/null 2>&1 || az ad sp create --id "$CLIENT_ID" -o none
  say "App \"$APP_NAME\": exists."
else
  confirm "This makes an app registration \"$APP_NAME\" in tenant $TENANT_ID, with a one-year secret, and lets it read the Macs Intune manages ($PERMISSION), with admin consent."
  CLIENT_ID=$(az ad app create --display-name "$APP_NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv)
  [ -n "$CLIENT_ID" ] || die "creating the app \"$APP_NAME\" returned no application ID."
  az ad sp create --id "$CLIENT_ID" -o none
  say "App \"$APP_NAME\": created ($CLIENT_ID)."
fi
az ad app permission add --id "$CLIENT_ID" --api "$GRAPH_APP" --api-permissions "$ROLE_ID=Role" -o none --only-show-errors
# A new app takes a few seconds to reach every Entra server, so consent can fail at first.
tries=0
until az ad app permission admin-consent --id "$CLIENT_ID" -o none 2>"$ERRFILE"; do
  tries=$((tries + 1))
  if [ "$tries" -ge 6 ]; then
    cat "$ERRFILE" >&2
    die "couldn't grant admin consent. Granting a Graph permission takes the Privileged Role Administrator or Global Administrator role. Run this again, or give consent in the Entra admin center (API permissions > Grant admin consent)."
  fi
  sleep "${SETUP_RETRY_WAIT:-10}"
done
say "App \"$APP_NAME\": $PERMISSION granted, with admin consent."
if [ "$count" -eq 0 ]; then
  SECRET=$(az ad app credential reset --id "$CLIENT_ID" --years 1 --query password -o tsv --only-show-errors)
  [ -n "$SECRET" ] || die "creating the secret for \"$APP_NAME\" returned nothing. Add one with az ad app credential reset --id $CLIENT_ID --append --years 1"
  expires=$(date -u -v+1y +%Y-%m-%d 2>/dev/null || date -u -d '+1 year' +%Y-%m-%d)
fi

# 3. The .env lines.
say ""
say "Add these lines to .env in the Altiward deployment directory, then run docker compose up -d:"
say ""
echo "ALTIWARD_INTUNE_AUTH=secret"
echo "ALTIWARD_INTUNE_TENANT_ID=$TENANT_ID"
echo "ALTIWARD_INTUNE_CLIENT_ID=$CLIENT_ID"
if [ -n "$SECRET" ]; then
  echo "ALTIWARD_INTUNE_CLIENT_SECRET=$SECRET"
  say ""
  say "The secret is shown only this once. Expires $expires: add a new one before then (install guide, \"Connect Intune\")."
else
  say ""
  say "The app existed, so its secret is unchanged: keep ALTIWARD_INTUNE_CLIENT_SECRET from your .env."
  say "If you don't have it, add a secret with az ad app credential reset --id $CLIENT_ID --append --years 1"
  say "and use its password (install guide, \"Connect Intune\")."
fi
say "The server needs outbound HTTPS to login.microsoftonline.com and graph.microsoft.com."
say "A new permission can take a few minutes to work; until then the sync's status shows the error."
say "All done: the app can read the Macs Intune manages, and nothing else in Intune."
