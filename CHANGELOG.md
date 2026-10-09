# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-09

### Added

- Eight YARA rules covering PHP and ASPX web shell shapes, PowerShell download cradles and
  encoded-command launchers, certutil download and decode, shadow copy deletion, Run-key
  persistence and LSASS memory dump command lines.
- Eight Sigma rules for Windows process creation, process access and registry set events,
  covering encoded PowerShell, certutil URL download, LSASS memory read access, suspicious Run
  key values, suspicious scheduled task creation, shadow copy deletion, wevtutil log clearing
  and web-server-spawned shells.
- Mapping to Enterprise ATT&CK 19.2 technique IDs, including current identifiers such as
  `T1685.005` (Clear Windows Event Logs).
- Synthetic positive and negative fixtures for every rule, with pytest coverage via yara-python
  and the pySigma SQLite backend.
- ATT&CK coverage generator, GitHub Actions workflow and dual licensing (DRL 1.1 for rules, MIT
  for tooling).

[Unreleased]: https://github.com/bfleming-bitflow/detection-rules/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bfleming-bitflow/detection-rules/releases/tag/v0.1.0
