# Let the server read Intune

[`setup.sh`](setup.sh) grants a managed identity, or a new app registration, Microsoft
Graph's `DeviceManagementManagedDevices.Read.All` application permission, then prints the
settings for Altiward's `.env`. That is the only access it gives: read access to the
devices Intune manages, and nothing it could change. It needs someone who can grant Graph
permissions (Privileged Role Administrator or Global Administrator), and it asks before it
changes anything.

The [install guide](../../docs/install.md#7-connect-intune-optional) covers what the
server reads, the three ways to grant the permission, the settings and troubleshooting.
From a source checkout, run one of:

```sh
bash deploy/intune/setup.sh --vm <resource group>/<vm name>
bash deploy/intune/setup.sh --identity <client ID>
bash deploy/intune/setup.sh --app "Altiward Intune"
```

The server release bundle ships the script at `integrations/intune/setup.sh`. The
Deploy to Azure template for the same grant is
[`deploy/azure/intune-read.bicep`](../azure/intune-read.bicep), compiled to
`intune-read.json` by `make azure-template`.

Tests are colocated here with `testdata/fake-az.sh`; they use a fake CLI and make no
Azure requests. Run `go test ./deploy/intune` from the repository root.
