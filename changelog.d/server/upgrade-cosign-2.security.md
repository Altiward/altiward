- `upgrade.sh` checks a release's signature with cosign 2.4 and later as well as cosign 3.
  Releases are signed in Sigstore's newer bundle format, which cosign 2.4 reads only when
  asked to, so with cosign 2.4 the script reported a genuine release as not signed by
  Altiward's release workflow. It now asks for that format with cosign 2. With a cosign
  older than 2.4, which can't read it, the script says the cosign is too old instead of
  calling the release unsigned, and stops unless you give `--skip-signature`, which still
  checks the checksums. When cosign rejects a release, the script now shows cosign's error.
  Checking a release, in the install guide, says which cosign versions work and how.
