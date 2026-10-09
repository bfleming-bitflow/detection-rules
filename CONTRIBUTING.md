# Contributing

Contributions that add well-tested rules, tighten existing ones or improve the tooling are
welcome.

## Before you start

Read [docs/conventions.md](docs/conventions.md). Rules that do not follow those conventions, or
that ship without positive and negative fixtures, will not be merged.

## Adding a rule

1. Create the rule under `rules/yara/` or `rules/sigma/`, with the metadata required by the
   conventions.
2. Confirm every ATT&CK technique ID exists in `data/attack-enterprise-techniques.csv` for the
   version in `data/ATTACK_VERSION`. Prefer current IDs; do not use revoked techniques
   (for example use `T1685.005` rather than the revoked `T1070.001`).
3. Add synthetic fixtures:
   - YARA: `tests/fixtures/yara/<rule_stem>/{positive,negative}/*.txt`
   - Sigma: `tests/fixtures/sigma/<rule_stem>.{positive,negative}.json`
4. Run `make coverage` and commit `docs/coverage.md`.
5. Run `make check`.
6. Add an entry under "Unreleased" in `CHANGELOG.md`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(yara): ...`,
`feat(sigma): ...`, `fix(sigma): ...`, `test: ...`, `docs: ...`, `build: ...`.

## Licensing of contributions

By contributing, you agree that detection rules are licensed under Detection Rule License (DRL)
1.1 and that tooling is licensed under the MIT License, as described in `README.md`.
