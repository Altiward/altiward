# Splunk

Events arrive through the HTTP Event Collector with `sourcetype=altiward:ocsf`,
`source=altiward`, `host=<device serial>`, and the OCSF record as the event body. Console
actions arrive the same way with `host=altiward`.

## Setup

1. Create an HEC token (Settings → Data inputs → HTTP Event Collector). Pick an index,
   or let the API set one with `ALTIWARD_SPLUNK_INDEX`.
2. Set `ALTIWARD_SPLUNK_HEC_URL` (e.g. `https://splunk.example.com:8088`) and
   `ALTIWARD_SPLUNK_HEC_TOKEN` on the API.

The URL must reach the HEC service directly. Redirects, including redirects to a sign-in
page, fail delivery and leave the batch queued. A delivery completes only after HTTP 200
with one complete JSON acknowledgement containing an explicit integer `code`: `0`, or
Splunk's accepted capacity warnings `24` and `25`. Missing, null, malformed, oversized or
interrupted acknowledgements are retried. See [Splunk's response code reference](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.2/get-data-with-http-event-collector/troubleshoot-http-event-collector).

## Dashboard

The **Altiward overview** dashboard, `altiward_overview.xml` in the server release bundle,
shows the figures from the console's Overview in Splunk, built from the `altiward:ocsf`
events:

- **Now:** who holds admin rights, by where they came from (Privileges or without a
  grant), and what needs a look: rights past their expiry, Macs failing an
  integrity check, Macs not checking in.
- **The period** (7, 30 or 90 days): elevations and how many were without a grant,
  elevations per day, time held against time allowed, the people and Macs that elevate
  most, and the findings raised.
- **Health:** integrity checks failing now, and agent versions.

Install it either way:

- **Splunk Web:** *Dashboards*, *Create New Dashboard*, choose *Classic Dashboards*, give
  it any title and create it. Then *Edit*, *Source*, replace everything with the file's
  contents and save.
- **REST**, from a machine that can reach the management port (8089). Run the first command
  once; after an upgrade, run the second to update it:

  ```sh
  curl -u admin https://splunk.example.com:8089/servicesNS/nobody/search/data/ui/views \
    -d name=altiward_overview --data-urlencode eai:data@altiward_overview.xml
  curl -u admin https://splunk.example.com:8089/servicesNS/nobody/search/data/ui/views/altiward_overview \
    --data-urlencode eai:data@altiward_overview.xml
  ```

Set *Index* at the top to the index the HEC token writes to (`main` unless you set
`ALTIWARD_SPLUNK_INDEX` or chose another index for the token).

What it can't show: *Now* looks back 90 days, so rights granted before then and still held
aren't counted. Agent versions list only the Macs that sent an event in the period,
because health check-ins aren't exported; the events the server raises about a Mac
(`agent.enrollment` and `agent.silent`) don't count. Whether each SIEM is keeping up is
on the console's Overview.

## Saved searches

Detections for these events are in
[altiward-siem](https://github.com/Altiward/altiward-siem): a `savedsearches.conf` with an
alert for each, and the same searches as `.spl` files to paste into Search. Each says
whether it needs the Altiward server or also works with
[altiward-forwarder](https://github.com/Altiward/altiward-forwarder)'s events.
