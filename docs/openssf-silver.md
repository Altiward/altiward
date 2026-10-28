# OpenSSF Silver evidence

Audit date: 28 October 2026. The public [badge assessment](https://www.bestpractices.dev/en/projects/15960)
is Passing, with Silver 15% complete at the start of this audit. This record maps all
55 [Silver criteria](https://www.bestpractices.dev/en/criteria/1) to evidence or remaining
work. It does not claim that Silver has been achieved or update the hosted assessment.

**Evidence** means there is a concrete source to assess. **Verify** means an operational
check or additional review is needed before marking it met. **Open** identifies a known
gap. Evidence added in a pull request should be reviewed and merged before the badge
owner submits links to it. Evidence of tests and coverage must name the source commit
and CI run, rather than rely on a floating badge or a local percentage.

## Governance and documentation

| Criterion | Assessment | Evidence or next action |
| --- | --- | --- |
| `achieve_passing` | Evidence | The existing public assessment is Passing. |
| `contribution_requirements` | Evidence | [Contribution rules](../CONTRIBUTING.md) and [coding standards](testing.md#coding-standards). |
| `dco` | Evidence | DCO sign-off is documented and is a required main-branch check. |
| `governance` | Evidence | [Governance](../GOVERNANCE.md) describes how decisions are made. |
| `code_of_conduct` | Evidence | The [organisation policy](https://github.com/Altiward/.github/blob/main/CODE_OF_CONDUCT.md) applies to this repository and names a reporting contact. |
| `roles_responsibilities` | Evidence | Governance names the active maintainer and separates contributor, reviewer, release and recovery responsibilities. |
| `access_continuity` | Verify | The maintainer confirms a trusted person has access. Verify release approval, Apple credentials, domain/registry recovery, authority and a one-week recovery exercise; keep details private. |
| `bus_factor` | Open | There is one active software maintainer. Administrative recovery access does not prove that another person can maintain the software. |
| `documentation_roadmap` | Evidence | The [roadmap](roadmap.md) covers October 2026 through October 2027, including scope and conditional work. |
| `documentation_architecture` | Evidence | [Architecture](architecture.md), the README diagram and the agent design notes. |
| `documentation_security` | Evidence | [Security assurance](security-assurance.md) states protections, trust boundaries and limits; [data handling](data-handling.md) defines collection and retention. |
| `documentation_quick_start` | Evidence | README quick start and the Docker-only demo; [install guide](install.md) for deployment. |
| `documentation_current` | Verify | Verify release versions and instructions against the next published releases; document known defects in the issue tracker. |
| `documentation_achievements` | Evidence | README links CI, REUSE, the Passing badge and Scorecard. Update displayed achievements when new ones are awarded. |
| `accessibility_best_practices` | Verify | Contrast, words with glyphs, focus and keyboard behaviour are contribution requirements. Record a keyboard/screen-reader assessment of current console and project sites. |
| `internationalization` | Open | The console currently uses English strings. A localisation approach and implementation have not been established; an English-only UI is not N/A. |
| `sites_password_security` | Verify | The app delegates SSO to an identity provider and uses console tokens. Confirm the complete project-site scope, including externally hosted services, before choosing N/A or claiming password-storage compliance. |
| `maintenance_or_update` | Evidence | [Release policy](releasing.md#versions) and the install guide provide supported-version and upgrade paths. |
| `report_tracker` | Evidence | Public GitHub issues track individual reports and proposals. |
| `vulnerability_report_credit` | Verify | The security policy promises credit when desired. Review reports and published advisories from the last 12 months; select N/A only if none were resolved. |
| `vulnerability_response_process` | Evidence | The [security policy](https://github.com/Altiward/.github/blob/main/SECURITY.md) documents acknowledgement, investigation, fixes and coordinated disclosure. |

## Build, dependencies and tests

| Criterion | Assessment | Evidence or next action |
| --- | --- | --- |
| `coding_standards` | Evidence | [Language standards](testing.md#coding-standards) are required by CONTRIBUTING. |
| `coding_standards_enforced` | Open | Go formatting is enforced. Select and enforce Swift and TypeScript formatters before claiming all primary languages are covered. |
| `build_standard_variables` | Verify | Go and Swift are native builds. Audit relevant user-supplied compiler/linker options through Makefile and packaging; do not mark native binaries N/A. |
| `build_preserve_debug` | Verify | Development builds retain debugging data; verify that supported build options preserve requested debug information through packaging. |
| `build_non_recursive` | Evidence | Go and SwiftPM manage their own dependency graphs; the Makefile invokes component builds without a recursive cross-dependent Make hierarchy. |
| `build_repeatable` | Open | The Caddy build checks a reproducible image digest. Establish repeatability evidence for the API, console and agent too, accounting for signing/notarization separately. |
| `installation_common` | Evidence | macOS packages/MDM, Compose and Azure are documented; agent uninstall and server teardown are documented. |
| `installation_standard_variables` | Verify | Assess the applicable conventions for macOS packages, container deployment and development builds; do not assert generic DESTDIR support that is not implemented. |
| `installation_development_quick` | Evidence | CONTRIBUTING and the Makefile document dependencies, installation, local services and test commands. |
| `external_dependencies` | Evidence | Go manifests/checksums, the console lockfile, SwiftPM manifest and SHA/digest-pinned build actions/images. |
| `dependency_monitoring` | Verify | Dependabot, source and binary govulncheck scans and Scorecard run routinely. Track the compiled Caddy go-jose v3 advisory until fixed or shown unexploitable with appropriate evidence; a clean scan alone is insufficient. |
| `updateable_reused_components` | Evidence | Dependencies use their native manifests; the proxy build guide explains rebuilding, scanning and updating deployment pins. |
| `interfaces_current` | Verify | Review deprecated APIs and supported OS/runtime versions in the primary languages; record any justified compatibility exceptions. |
| `automated_integration_testing` | Evidence | CI runs on main and PRs, includes Postgres, proxy and upgrade checks, and publishes results. |
| `regression_tests_added50` | Verify | Inspect bug-fix PRs from the last six months (or all project history if younger), count those with regression tests and record the ratio. A written policy alone does not prove the historical percentage. |
| `test_statement_coverage80` | Open | [CI run 40669218895](https://github.com/Altiward/altiward/actions/runs/40669218895) confirms 82.79% backend and 85.28% integrations statement coverage; the console measures 90.47% (293 tests) and enforces 80%. The agent report contains 27 of 31 production Swift files and measures 84.71% regions/88.36% lines in that subset. It omits `XPCInterface.swift`, the daemon and hook entry points, so it does not establish whole-agent or project-wide statement coverage. |
| `test_policy_mandated` | Evidence | The contribution test policy requires automated tests with new functionality and fixes. |
| `tests_documented_added` | Evidence | CONTRIBUTING and the PR template include test policy and validation evidence. |
| `warnings_strict` | Verify | Go vet, TypeScript checks and Swift concurrency checking run in CI. Review warnings-as-errors and analyser options for all production languages before claiming maximal practical strictness. |

## Security and analysis

| Criterion | Assessment | Evidence or next action |
| --- | --- | --- |
| `implement_secure_design` | Evidence | [Security assurance](security-assurance.md) ties least privilege, boundary checks, idempotence and transactional state changes to code and tests. |
| `crypto_weaknesses` | Verify | Review default algorithm/protocol choices in device signing, SSO, TLS and exports, including all supported configurations. |
| `crypto_algorithm_agility` | Open | Document which protocols negotiate algorithms and which device-signing formats are fixed. A fixed signed-wire algorithm is not automatically algorithm agility. |
| `crypto_credential_agility` | Verify | Device keys and server credentials can rotate without recompilation. Audit the requirement to store credentials separately from other configuration; environment-only mixed configuration may need additional secret-file support. |
| `crypto_used_network` | Verify | Production HTTPS/TLS paths and explicitly permitted local HTTP/syslog modes are documented. Audit defaults for every supported deployment and integration. |
| `crypto_tls12` | Verify | Verify minimum TLS settings in all clients, SIEM sinks and supported proxy configurations. |
| `crypto_certificate_verification` | Verify | Review certificate verification and test custom CA/untrusted certificate rejection across all TLS clients and supported configurations. |
| `crypto_verification_private` | Verify | Confirm private headers and tokens are sent only after certificate verification; retain negative tests as evidence. |
| `signed_releases` | Evidence | Apple signatures, keyless checksum/image signatures, signed provenance and download verification are documented in [releasing](releasing.md) and the install guide. |
| `version_tags_signed` | Verify | Inspect published important tags for cryptographic signatures. Artifact signing and GitHub-verified squash commits do not prove tag signatures. |
| `input_validation` | Evidence | Strict schema decoding, role/CSRF checks, signature checks and fuzz/regression tests; see the assurance argument. |
| `hardening` | Verify | Assess enabled compiler/runtime and deployment hardening with evidence for each shipped component and platform. |
| `assurance_case` | Evidence | [Security assurance](security-assurance.md) records threats, boundaries, enforcement arguments, tests and practical limits. |
| `static_analysis_common_vulnerabilities` | Evidence | GitHub CodeQL analyses the project's languages; CI also runs Go vet, TypeScript checks and vulnerability scans. |
| `dynamic_analysis_unsafe` | Verify | First-party code uses Swift, Go and TypeScript, but review unsafe/FFI and shipped native dependencies before choosing N/A; Go fuzzing alone is not a C/C++ memory-safety analysis. |

## Completing the assessment

Prioritise the mandatory gaps: complete the recovery exercise, enforce language styles,
measure production coverage on CI, audit native build/install conventions and establish
repeatable build evidence. Review the security configuration requirements and historical
regression-test ratio with their actual evidence. Record explanations for unmet SHOULD
criteria rather than calling them N/A to raise a score.

The badge owner can then submit the verified statuses and links in the hosted assessment.
Keep this record consistent with that submission and with changes in maintainership,
supported versions, dependencies and security guarantees.
