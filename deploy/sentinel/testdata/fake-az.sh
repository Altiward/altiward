#!/bin/bash
# A stand-in for the Azure CLI, for setup_test.go. It writes each call to $FAKE_AZ_LOG,
# one per line, and answers from canned values. The FAKE_* variables pick the state of
# the pretend tenant:
#
#   FAKE_SIGNED_OUT=1         az account show fails, as before az login
#   FAKE_PROVIDER             Microsoft.Insights' registration state (default Registered)
#   FAKE_TABLE                missing (default), ok, or wrong (Ocsf is a string)
#   FAKE_DCE                  missing (default) or exists
#   FAKE_APPS                 how many apps have the display name (default 0)
#   FAKE_ROLE=1               the existing app has the role on the rule
#   FAKE_NO_DIRECT_URL=1      the rule comes back without its own ingestion URL
#
# Anything else it doesn't expect fails with exit status 99.
set -euo pipefail

printf '%s\n' "$*" >>"$FAKE_AZ_LOG"

SUB=00000000-0000-0000-0000-00000000aaaa
TENANT=00000000-0000-0000-0000-00000000bbbb
LAW_ID=/subscriptions/$SUB/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/law-sec
APP_ID=11111111-0000-0000-0000-000000000001
SP_ID=22222222-0000-0000-0000-000000000002

not_found() {
  echo "ERROR: (ResourceNotFound) The Resource '$1' was not found." >&2
  exit 1
}

case "$*" in
"account show"*"--query id"*)
  [ -z "${FAKE_SIGNED_OUT:-}" ] || { echo "ERROR: Please run 'az login' to setup account." >&2; exit 1; }
  echo "$SUB" ;;
"account show"*"--query tenantId"*) echo "$TENANT" ;;
"provider show"*) echo "${FAKE_PROVIDER:-Registered}" ;;
"monitor log-analytics workspace show"*"-g rg-sec -n law-sec"*"--query id"*) echo "$LAW_ID" ;;
"monitor log-analytics workspace show"*"-g rg-sec -n law-sec"*"--query location"*) echo westeurope ;;
"monitor log-analytics workspace show"*) not_found workspace ;;
"rest --method get --url $LAW_ID/tables/AltiwardOCSF_CL?"*)
  case "${FAKE_TABLE:-missing}" in
  missing) not_found AltiwardOCSF_CL ;;
  ok|wrong)
    ocsf=dynamic
    [ "$FAKE_TABLE" = ok ] || ocsf=string
    printf '%s\t%s\n' TimeGenerated dateTime EventUid string TenantUid string SessionUid string \
      ClassUid int ActivityId int SeverityId int DeviceSerial string UserName string \
      Message string Ocsf "$ocsf" TenantId guid Type string ;;
  esac ;;
"monitor log-analytics workspace table create"*) ;;
"rest --method get --url "*"/dataCollectionEndpoints/dce-altiward?"*)
  [ "${FAKE_DCE:-missing}" = exists ] || not_found dce-altiward
  echo https://dce-altiward-abcd.westeurope-1.ingest.monitor.azure.com ;;
"rest --method put --url "*"/dataCollectionEndpoints/dce-altiward?"*)
  echo https://dce-altiward-abcd.westeurope-1.ingest.monitor.azure.com ;;
"rest --method put --url "*"/dataCollectionRules/dcr-altiward?"*)
  echo dcr-0123456789abcdef0123456789abcdef
  if [ -n "${FAKE_NO_DIRECT_URL:-}" ]; then echo None; else
    echo https://dcr-altiward-wxyz.westeurope-1.ingest.monitor.azure.com
  fi ;;
"ad app list"*)
  n=0
  while [ "$n" -lt "${FAKE_APPS:-0}" ]; do
    n=$((n + 1))
    echo "11111111-0000-0000-0000-00000000000$n"
  done ;;
"ad sp create-for-rbac"*) printf '%s\n' "$APP_ID" 'fake~secret.value-123' ;;
"ad sp show --id $APP_ID"*) echo "$SP_ID" ;;
"vm identity assign"*"--query systemAssignedIdentity"*) echo 33333333-0000-0000-0000-000000000003 ;;
"role assignment list"*) [ -z "${FAKE_ROLE:-}" ] || echo "/fake/roleAssignments/1" ;;
"role assignment create"*) ;;
*)
  echo "fake az: unexpected call: $*" >&2
  exit 99 ;;
esac
