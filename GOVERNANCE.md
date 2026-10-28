# Governance

Altiward is maintained by [Phil Chatham (@pchatham)](https://github.com/pchatham).
It currently has one active software maintainer. Contributors and independent reviewers
are welcome; administrative recovery access does not imply that a second person reviews
the code.

## Decisions and responsibilities

The maintainer sets the scope, decides whether changes fit the design, reviews and merges
contributions, responds to security reports, and approves releases. Significant changes
start with an issue or Discussion so contributors can question the design before
implementation. Decisions and their reasons belong in the issue or pull request. Security
reports use the private process below until disclosure is agreed.

Contributors follow [CONTRIBUTING.md](CONTRIBUTING.md), sign off their commits under the
DCO, provide relevant tests, and explain how they verified a change. Reviewers check
correctness, the trust boundaries, compatibility and upgrade behaviour, and test evidence.
The maintainer may ask a contributor to revise or split a change before accepting it.

Release approval uses GitHub's `release` environment. The release workflows build and
verify artifacts, sign them, and publish them; [releasing](docs/releasing.md) describes the
procedure. Main requires pull requests, DCO and passing CI against an up-to-date branch.
Human approval is encouraged but is not a merge requirement while there is only one
active software maintainer.

The organisation's [code of conduct](https://github.com/Altiward/.github/blob/main/CODE_OF_CONDUCT.md)
applies to this project. Conduct reports go to the contact listed there. Vulnerabilities
follow the [security policy](https://github.com/Altiward/.github/blob/main/SECURITY.md).

## Continuity

A trusted person has administrative access for recovery if the maintainer becomes
unavailable. Recovery instructions and identities belong in a private record, never in
the repository. The recovery contact should be able to restore issue administration,
accept changes and release software within a week after the maintainer's unavailability
is confirmed.

Administrative access alone does not establish release capability. The maintainer and
recovery contact must verify that the contact can access the organisation and repositories,
approve release environments, recover registry and domain administration, and recover or
replace the Apple Developer ID and notarization credentials. The private record should
also cover required account recovery and authority to operate the project. Record the
date and result of a recovery exercise privately, without publishing credentials.

The [Silver evidence record](docs/openssf-silver.md) keeps the continuity criterion open
until this scope and the one-week recovery procedure have been verified. Changes to
maintainers, recovery arrangements and release ownership should update this document.
