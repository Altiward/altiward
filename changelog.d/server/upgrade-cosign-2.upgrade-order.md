If the server has cosign 2.4 or older installed, update cosign (to 3, or to 2.5 or later)
before upgrading to this release. The `upgrade.sh` of the release you run checks the
signature before this release's script takes over, and with those versions it reports the
release as not signed by Altiward's release workflow, though it is.
