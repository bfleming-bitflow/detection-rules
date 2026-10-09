# Rule-writing conventions

## Shared expectations

- Rules target well-documented behaviours. Each rule must cite at least one public, durable
  reference (vendor documentation, ATT&CK technique page, LOLBAS entry or peer-reviewed
  advisory). Do not cite private reports or social media posts as the sole reference.
- Author is always `bfleming-bitflow`.
- Every rule maps to at least one current Enterprise ATT&CK technique ID. Technique IDs are
  validated against `data/attack-enterprise-techniques.csv`.
- Prefer precision over breadth. A rule that needs a long exclusion list in every environment is
  usually too broad for this repository.
- Fixtures are synthetic and inert. They must not contain live credentials, real victim data or
  executable payloads. YARA fixtures are plain text (or UTF-16LE text) marked with a synthetic
  fixture header. Sigma fixtures are JSON objects with the fields the rule reads.

## YARA

- One rule per `.yar` file. The file stem is the lowercased rule name.
- Required `meta` fields: `id` (UUID), `author`, `date` (`YYYY-MM-DD`), `description`,
  `reference` (additional references as `reference2`, ...), `mitre_attack`, `severity`,
  `false_positives`, `license` (`DRL 1.1`).
- Bound `filesize` on every rule. Prefer strings that describe the behaviour (command shapes,
  API sequences) over fragile hashes or exact malware family names.
- Use `ascii wide nocase` when the same pattern can appear in scripts and UTF-16LE command
  lines.
- Positive fixtures must match; negative fixtures must not. At least two of each.

## Sigma

- Follow the [Sigma rule specification](https://github.com/SigmaHQ/sigma-specification). Required
  fields: `title`, `id` (UUID), `status`, `description`, `references`, `author`, `date`,
  `tags`, `logsource`, `detection`, `falsepositives`, `level`.
- File names are lowercase, descriptive and at least ten characters
  (`proc_creation_win_<behaviour>.yml`).
- Technique tags use `attack.t####` / `attack.t####.###`. Tactic tags use the current ATT&CK
  shortnames from `data/attack-enterprise-tactics.csv` (for example `attack.stealth`,
  `attack.defense-impairment`).
- Prefer field-stable selections (`Image|endswith`, `OriginalFileName`, `CommandLine|contains`)
  over brittle full-path equality. Use `|windash` for Windows command-line switches.
- Filters for known-benign system components use the `filter_main_*` prefix; environment-specific
  filters belong in local pipelines, not in the rule.
- Status starts at `experimental`. Promote to `test` only after the rule has been exercised
  against real telemetry in at least one environment.

## Testing approach

1. `sigma check --fail-on-issues` and `yara.compile` confirm the rules are syntactically valid.
2. Pytest compiles every YARA rule and asserts each positive fixture matches and each negative
   fixture does not.
3. Pytest converts every Sigma rule to SQL with the pySigma SQLite backend and evaluates it
   against the JSON event fixtures.
4. `tools/coverage.py` regenerates the ATT&CK coverage table; CI fails if it is stale.

This suite proves that each rule matches its intended synthetic evidence and rejects the
paired counterexamples. It does not measure detection rates on production telemetry.
