#!/bin/bash
# A stand-in for the Azure CLI, for setup_test.go. It writes each call to $FAKE_AZ_LOG,
# one per line, and answers from canned values. The FAKE_* variables pick the state of
# the pretend tenant:
#
#   FAKE_SIGNED_OUT=1         az account show fails, as before az login
#   FAKE_NO_ROLE=1            Graph's service principal has no such application permission
#   FAKE_ALREADY=1            Graph says the permission is already assigned
#   FAKE_GRAPH_ERROR=1        Graph refuses the assignment for another reason
#   FAKE_NO_IDENTITY=1        no service principal has the managed identity's client ID
#   FAKE_APPS                 how many apps have the display name (default 0)
#   FAKE_CONSENT_FAILS=N      admin-consent fails N times before it works (default 0)
#
# Anything else it doesn't expect fails with exit status 99.
set -euo pipefail

printf '%s\n' "$*" >>"$FAKE_AZ_LOG"

TENANT=00000000-0000-0000-0000-00000000bbbb
GRAPH_APP=00000003-0000-0000-c000-000000000000
GRAPH_SP_ID=66666666-0000-0000-0000-000000000006
ROLE_ID=77777777-0000-0000-0000-000000000007
APP_ID=11111111-0000-0000-0000-000000000001
MI_CLIENT_ID=44444444-0000-0000-0000-000000000004
MI_PRINCIPAL_ID=55555555-0000-0000-0000-000000000005

case "$*" in
"account show"*)
  [ -z "${FAKE_SIGNED_OUT:-}" ] || { echo "ERROR: Please run 'az login' to setup account." >&2; exit 1; }
  echo "$TENANT" ;;
"ad sp show --id $GRAPH_APP"*"appRoles"*)
  if [ -n "${FAKE_NO_ROLE:-}" ]; then echo None; else echo "$ROLE_ID"; fi ;;
"ad sp show --id $GRAPH_APP"*"--query id"*) echo "$GRAPH_SP_ID" ;;
"ad sp show --id $APP_ID"*) echo 88888888-0000-0000-0000-000000000008 ;;
"ad sp show --id $MI_CLIENT_ID"*)
  if [ -n "${FAKE_NO_IDENTITY:-}" ]; then
    echo "ERROR: Resource '$MI_CLIENT_ID' does not exist or one of its queried reference-property objects are not present." >&2
    exit 3
  fi
  echo "$MI_PRINCIPAL_ID" ;;
"vm identity assign"*"--query systemAssignedIdentity"*) echo 33333333-0000-0000-0000-000000000003 ;;
"rest --method POST --url https://graph.microsoft.com/v1.0/servicePrincipals/"*"/appRoleAssignments"*)
  if [ -n "${FAKE_ALREADY:-}" ]; then
    echo "ERROR: Bad Request({\"error\":{\"code\":\"Request_BadRequest\",\"message\":\"Permission being assigned already exists on the object\"}})" >&2
    exit 1
  fi
  if [ -n "${FAKE_GRAPH_ERROR:-}" ]; then
    echo "ERROR: Forbidden({\"error\":{\"code\":\"Authorization_RequestDenied\",\"message\":\"Insufficient privileges to complete the operation.\"}})" >&2
    exit 1
  fi ;;
"ad app list"*)
  n=0
  while [ "$n" -lt "${FAKE_APPS:-0}" ]; do
    n=$((n + 1))
    echo "11111111-0000-0000-0000-00000000000$n"
  done ;;
"ad app create"*) echo "$APP_ID" ;;
"ad sp create --id "*) ;;
"ad app permission add"*) ;;
"ad app permission admin-consent"*)
  # A new app takes a moment to reach every Entra server, so the first tries can fail.
  state="$FAKE_AZ_LOG.consent"
  tries=$(cat "$state" 2>/dev/null || echo 0)
  echo $((tries + 1)) >"$state"
  if [ "$tries" -lt "${FAKE_CONSENT_FAILS:-0}" ]; then
    echo "ERROR: Resource '$APP_ID' does not exist or one of its queried reference-property objects are not present." >&2
    exit 1
  fi ;;
"ad app credential reset"*) echo 'fake~secret.value-123' ;;
*)
  echo "fake az: unexpected call: $*" >&2
  exit 99 ;;
esac
