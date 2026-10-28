- Release downloads include signed SLSA build provenance in `provenance.intoto.jsonl`,
  tying every file in `SHA256SUMS` to its source commit and release workflow. The workflow
  verifies each file's provenance before publishing; the install guide shows how to
  check a download with the GitHub CLI.
