# Changelog fragments

Release notes for changes that haven't shipped yet. Each pull request adds its own file
here instead of editing [`CHANGELOG.md`](../CHANGELOG.md), so pull requests never change
the same lines and don't conflict over the changelog. A release folds the files into its
dated section and deletes them.

Name a fragment `<product>/<name>.<heading>.md`, where `<product>` is `server` or
`agent`, and `<name>` is lower-case letters, digits and hyphens saying what changed:

| `<heading>` | Goes under | Holds |
| --- | --- | --- |
| `upgrade-order` | Upgrade order | A paragraph |
| `breaking` | Breaking changes | `- ` bullets |
| `security` | Security | `- ` bullets |
| `changes` | Changes | `- ` bullets |

For example, `server/upgrade-download.changes.md`:

```markdown
- `upgrade.sh` downloads the release when you give it a version: `./upgrade.sh 1.0.2`
  fetches the five files it needs from GitHub.
```

Write it as it should read in the release notes, wrapped at 90 columns, with each
bullet's later lines indented two spaces and no blank lines between bullets. A change
to both the server and the agent gets a fragment in each.

```sh
scripts/changelog.sh check                  # what CI runs
scripts/changelog.sh show server 1.0.1      # the section the fragments make
```

[Releasing](../docs/releasing.md) covers `scripts/changelog.sh release`.
