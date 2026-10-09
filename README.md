# detection-rules

Tested YARA and Sigma detection rules for well-documented Windows behaviours, mapped to
[MITRE ATT&CK](https://attack.mitre.org/) Enterprise techniques.

Each rule ships with synthetic positive and negative fixtures. Continuous integration compiles
the YARA rules, validates the Sigma rules against the Sigma specification, and checks that every
fixture produces the expected result.

## Rules

| Kind | Count | Coverage |
| --- | --- | --- |
| YARA | 8 | File and script content: web shells, PowerShell cradles and launchers, certutil, shadow copy deletion, Run-key persistence, LSASS dump command lines |
| Sigma | 8 | Windows process creation, process access (Sysmon 10) and registry set events for the same behaviours plus scheduled tasks, wevtutil log clearing and web-server-spawned shells |

The generated [ATT&CK coverage table](docs/coverage.md) lists every technique referenced by the
rules. Technique and tactic names follow Enterprise ATT&CK 19.2
(`data/ATTACK_VERSION`), including the current `stealth` and `defense-impairment` tactic
shortnames.

## Repository layout

```text
rules/yara/              YARA rules (one rule per file)
rules/sigma/windows/     Sigma rules by logsource category
tests/fixtures/yara/     Synthetic text fixtures (positive / negative per rule)
tests/fixtures/sigma/    Synthetic JSON event fixtures
tools/                   Coverage generator and Sigma event matcher
data/                    Vendored ATT&CK technique and tactic identifiers
docs/conventions.md      Rule-writing and testing conventions
docs/coverage.md         Generated ATT&CK coverage table
```

## Using the rules

### YARA

```sh
yara rules/yara/webshell_php_eval_request_input.yar /path/to/files
yara -r rules/yara/ /path/to/tree
```

### Sigma

Convert with [sigma-cli](https://github.com/SigmaHQ/sigma-cli) and a backend that matches your
stack:

```sh
sigma convert -t sqlite --without-pipeline rules/sigma/windows/process_creation/
```

Pipeline selection, field mapping and environment-specific filters are left to the consumer. The
rules are written against the standard Sigma taxonomy (`Image`, `CommandLine`, `TargetImage`,
`GrantedAccess`, `TargetObject`, `Details`).

## Testing

Requires Python 3.11 or later.

```sh
make venv     # create .venv and install pinned development dependencies
make check    # lint, sigma check, yara compile, pytest, coverage check
```

What the suite covers:

| Check | Tool | Purpose |
| --- | --- | --- |
| YARA compile | yara-python | Rules are syntactically valid |
| YARA fixtures | pytest | Each rule matches its positive fixtures and not its negative fixtures |
| Sigma validate | sigma-cli, pySigma validators | Rules follow the Sigma specification; ATT&CK tags resolve |
| Sigma fixtures | pytest + pySigma SQLite backend | Each rule matches its positive events and not its negative events |
| Coverage | `tools/coverage.py` | `docs/coverage.md` matches rule metadata |

Fixtures are inert text and JSON. They use reserved documentation names (`example.invalid`) and
documentation address ranges (`192.0.2.0/24`). They are not malware samples.

## Limitations

- The rules detect the behaviours described in their `description` fields. They are not a
  complete ATT&CK coverage set and are not tuned for any specific commercial EDR product.
- Sigma rules assume the fields named in `detection` are populated. Process access rules need
  Sysmon Event ID 10 (or equivalent) with LSASS included as a target.
- Encoded-command and download-cradle detections can match administrative automation. Use the
  `falsepositives` notes and local allowlists.
- Fixture tests prove correctness against synthetic evidence. They do not measure precision or
  recall on production telemetry.

## Licensing

This repository uses two licenses:

| Material | License |
| --- | --- |
| Detection rules under `rules/` and their fixtures under `tests/fixtures/` | [Detection Rule License (DRL) 1.1](LICENSE-DRL) |
| Tooling under `tools/`, `tests/*.py`, build and CI configuration | [MIT](LICENSE) |

DRL 1.1 is the license used by the SigmaHQ rule collections. It is a permissive license with an
attribution condition when rules are shared or when alerts derived from them are presented. See
`LICENSE-DRL` for the full text.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/conventions.md](docs/conventions.md). Security
issues: see [SECURITY.md](SECURITY.md).
