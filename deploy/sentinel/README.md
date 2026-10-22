# Provision Microsoft Sentinel

[`setup.sh`](setup.sh) creates the Log Analytics table, Data Collection Rule and export
identity, then prints the settings for Altiward's `.env`. It changes Azure resources;
run it only against the workspace you intend to connect.

The [Sentinel guide](../../integrations/sentinel/README.md) covers permissions, options,
managed identity, certificates, secret rotation and troubleshooting. From a source checkout, run:

```sh
bash deploy/sentinel/setup.sh --resource-group <group> --workspace <workspace>
```

The server release bundle ships the script at `integrations/sentinel/setup.sh`.

Tests are colocated here with `testdata/fake-az.sh`; they use a fake CLI and make no
Azure requests. Run `go test ./deploy/sentinel` from the repository root. The reusable
Logs Ingestion client remains in `integrations/sentinel/`.
