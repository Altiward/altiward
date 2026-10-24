# Releasing

How a maintainer ships a server or agent release. Releases are public: the files go on
[GitHub Releases](https://github.com/Altiward/altiward/releases) and the server image on
the public `ghcr.io/altiward/altiward-api` package, signed, for anyone to download.
Nothing is delivered to anyone in particular.

Releases are built by GitHub Actions from a tag, so the files are the ones the workflow
signed. A tag is the only trigger: `server-vX.Y.Z` (or `server-vX.Y.Z-rc.N`) runs
`.github/workflows/release-server.yml`, and `agent-vX.Y.Z` runs
`.github/workflows/release-agent.yml`.

## Server release

1. **Write the notes.** In `CHANGELOG.md`, fill in the `## Server X.Y.Z` section and
   replace `unreleased` with today's date. Say under "Upgrade order" whether agents need
   anything, and list any security fixes. The workflow refuses a version whose section
   is missing, undated or lacks one of the four headings.
   In the same commit, run `scripts/azure-template.sh X.Y.Z`: it sets the Deploy to Azure
   template's version and points the buttons at the new tag. The workflow refuses a tag
   the template doesn't match.
2. **Check everything passes** on `main`: CI, then locally `make test test-db`.
3. **Tag and push:** `git tag server-vX.Y.Z && git push origin
   server-vX.Y.Z`. The *Release server* workflow waits for a maintainer to approve the
   `release` environment (see [Approval](#approval)), then builds the image for amd64 and
   arm64, pushes it to `ghcr.io/altiward/altiward-api:X.Y.Z`, signs it keylessly with
   cosign, saves it as one tarball per platform, builds the deployment bundle, and signs
   `SHA256SUMS`. There is no `latest` tag.
4. **The release files** are, for each server release:
   - `altiward-server-X.Y.Z.tar.gz`, the deployment bundle
   - `altiward-api-X.Y.Z-linux-amd64.tar.gz` and `…-linux-arm64.tar.gz`, the image
   - `RELEASE_NOTES.md`, from `CHANGELOG.md`
   - `SHA256SUMS` and `SHA256SUMS.sigstore.json`, the signed checksums

   The workflow also keeps them for 90 days as the run's artifact
   `altiward-server-X.Y.Z`.
5. **The GitHub Release** is created by the workflow's last job, `publish`, which runs
   `gh release create server-vX.Y.Z` with those files and `RELEASE_NOTES.md` as the
   notes. It is the only job with permission to write to the repository, and it refuses a
   tag that doesn't exist (`--verify-tag`). Nothing is done by hand.
6. **Check the result** as a user would, from a clean machine: the release page lists
   the files, `docker pull ghcr.io/altiward/altiward-api:X.Y.Z` works without logging
   in, and the cosign commands in [Checking a release](install.md#checking-a-release)
   pass.

The package must be public: on GitHub, under the package's settings, set its visibility
to public once, after its first push. An image that needs a login is a release gone
wrong.

The workflow also copies the official Caddy image that the Deploy to Azure template uses
to `ghcr.io/altiward/caddy`, at the tag `deploy/azure/main.bicep` names, because container
apps pull from shared addresses that Docker Hub limits. Set that package up once too:
make it public, and under *Manage Actions access* give the `altiward` repository the Write
role, so the workflow can push to it.

## Server release candidate

For anyone who wants to test a release before it ships. Candidates get no fixes: the next
candidate or the release replaces them.

1. **Check the notes.** The candidate uses the coming release's `CHANGELOG.md` section,
   which can still say `unreleased`; keep its four headings filled in. Run
   `scripts/azure-template.sh X.Y.Z-rc.N` too: it moves only the template, so the deploy
   check below tries the candidate while the buttons stay on the last release.
2. **Tag and push:** `git tag server-vX.Y.Z-rc.N && git push
   origin server-vX.Y.Z-rc.N`. The same workflow builds, signs and publishes it. Its notes
   are headed as a release candidate.
3. **It is published as a GitHub *pre-release***: the workflow adds `--prerelease` to any
   tag containing `-rc.`, so it isn't shown as the latest release. `upgrade.sh` installs
   it, and the release upgrades over it later.

Agents have no release candidates. The agent's version is also its bundles'
`CFBundleVersion` and the package's version, which MDMs compare as plain numbers, so a
suffix risks the release not replacing its candidate. Test a new agent on your own Macs,
then on an MDM pilot group.

## Versions

Semantic versions, separately for the server and the agent: a patch for fixes
whenever needed, a minor for features about once a quarter, and a major only when
dropping support for something people relied on. Support and agent compatibility count
the last two minors, so more frequent minors shorten the support window. The first
releases are Server 0.1.0 and Agent 0.1.0. When to tag 1.0.0 is open.

## Agent release

1. **Bump the version** in `agent/Sources/AltiwardCore/DeviceIdentity.swift`
   (`AgentVersion.current`), and write the `## Agent X.Y.Z` section of `CHANGELOG.md`
   with today's date.
2. **New minor version only:** freeze the current event fixtures as
   `docs/schema/compat/agent-X.Y/` and prune to the newest two, then update
   `OldestSupportedAgent` (see `docs/schema/compat/README.md`).
3. **Tag and push:** `git tag agent-vX.Y.Z && git push origin
   agent-vX.Y.Z`. The *Release agent* workflow waits for approval of the `release`
   environment, then signs, notarizes and verifies the package, and signs `SHA256SUMS`.
   It needs the Developer ID and notary secrets that `release-agent.yml` lists, which live only
   in the repository's secrets.
4. **The GitHub Release** is created by the workflow's last job, as for the server, with
   the package, the example `corp.sap.privileges.plist`, `RELEASE_NOTES.md`, `SHA256SUMS`
   and its signature (also kept for 90 days as the run's artifact
   `altiward-agent-agent-vX.Y.Z`). Ship a server release first if the agent needs it.

## Approval

Both signing jobs run in the repository's `release` environment. Set it up once under
Settings, Environments: add the maintainers as required reviewers, and restrict it to the
`server-v*` and `agent-v*` tags. A run then pauses until a maintainer approves it, before
anything is built, pushed or signed. The `publish` job that creates the release runs after
it and needs no second approval.

## Deploy to Azure check

After each server release or candidate, the *Azure deploy check* workflow
(`.github/workflows/azure-deploy-check.yml`) deploys `deploy/azure/azuredeploy.json` from
the tag on GitHub, as the Deploy to Azure button does, into `rg-altiward-deploycheck`. It
checks that a Mac can enroll, send a signed event and hold a long poll; that the console
answers only the allowed networks, including against a forged `X-Forwarded-For`; and that
the server runs the release. Then it deletes everything it made. Run it by hand from the
Actions tab, on `main` or with a release tag: the `azure-test` environment allows nothing
else, so branch code never gets the Azure sign-in. Deploy to Azure stays labelled
Preview until this has passed on a release; then take "Preview" out of `README.md`,
`docs/install.md`, `deploy/azure/README.md` and `deploy/azure/createUiDefinition.json`.

Set it up once:

1. Create the resource group `rg-altiward-deploycheck`, and register the resource
   providers listed in [Before you deploy](../deploy/azure/README.md#before-you-deploy) in
   its subscription.
2. Create an Entra app registration with a federated credential for GitHub Actions:
   issuer `https://token.actions.githubusercontent.com`, audience
   `api://AzureADTokenExchange`, and the subject GitHub sends for the `azure-test`
   environment. This repository uses GitHub's immutable subject, which names the
   organisation and repository by ID: `repo:Altiward@344351898/altiward@1427562605:environment:azure-test`.
   `gh api repos/Altiward/altiward/actions/oidc/customization/sub` shows the prefix; a
   failed sign-in's `AADSTS700213` error shows the whole subject. A new credential can
   take a few minutes to work. Give the app **Contributor** and **Role Based Access
   Control Administrator** on that resource group only. The template grants access to its
   key vault, which Contributor alone can't.
3. Create the repository environment `azure-test`, limited to the `main` branch, with
   the variables `AZURE_CLIENT_ID` (the app's), `AZURE_TENANT_ID` and
   `AZURE_SUBSCRIPTION_ID`. They are IDs, not secrets: GitHub's OIDC token is the only
   credential.

Each run leaves a soft-deleted key vault behind, under a name no later run uses, which
Azure removes after 90 days.

## Signing

Nothing is signed with a key anyone holds. The server image and `SHA256SUMS` are signed
keylessly by the release workflow's GitHub identity, which cosign records in Sigstore's
public transparency log; `upgrade.sh` and [Checking a release](install.md#checking-a-release)
check that identity, which names the `Altiward/altiward` repository, the workflow file and
the tag. The agent package is also signed with Apple's Developer ID and notarized. The
Apple signing material is the only secret a release uses.
