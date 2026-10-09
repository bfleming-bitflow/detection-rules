"""Compile YARA rules and verify them against synthetic fixtures."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yara

from tests.conftest import YARA_DIR, YARA_FIXTURES

RULE_NAME = re.compile(r"^\s*rule\s+(\w+)", re.MULTILINE)
META_AUTHOR = re.compile(r'author\s*=\s*"([^"]+)"')
META_ATTACK = re.compile(r'mitre_attack\s*=\s*"([^"]+)"')
META_ID = re.compile(r'id\s*=\s*"([0-9a-f-]{36})"')


def rule_files() -> list[Path]:
    return sorted(YARA_DIR.glob("*.yar"))


def rule_name(path: Path) -> str:
    match = RULE_NAME.search(path.read_text(encoding="utf-8"))
    assert match, path
    return match.group(1)


@pytest.fixture(scope="module")
def compiled_rules() -> yara.Rules:
    mapping = {path.stem: str(path) for path in rule_files()}
    assert mapping, "no YARA rules found"
    return yara.compile(filepaths=mapping)


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.stem)
def test_rule_has_required_metadata(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert META_AUTHOR.search(text).group(1) == "bfleming-bitflow"
    assert META_ID.search(text), "missing UUID id"
    assert META_ATTACK.search(text), "missing mitre_attack"
    assert 'license = "DRL 1.1"' in text
    assert "false_positives" in text
    assert "description" in text


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.stem)
def test_filename_matches_rule_name(path: Path) -> None:
    # File stem is the snake_case form of the PascalCase / Title_Case rule name.
    name = rule_name(path)
    expected = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    # Rules already use underscores between words (WebShell_PHP_...), so compare lowercased.
    assert path.stem == name.lower() or path.stem == expected


def test_rules_compile(compiled_rules: yara.Rules) -> None:
    assert len(list(compiled_rules)) == len(rule_files())


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.stem)
def test_positive_fixtures_match(path: Path, compiled_rules: yara.Rules) -> None:
    name = rule_name(path)
    folder = YARA_FIXTURES / path.stem / "positive"
    files = sorted(folder.iterdir())
    assert files, f"no positive fixtures for {path.stem}"
    for fixture in files:
        matches = {match.rule for match in compiled_rules.match(str(fixture))}
        assert name in matches, f"{fixture.name} did not match {name}"


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.stem)
def test_negative_fixtures_do_not_match(path: Path, compiled_rules: yara.Rules) -> None:
    name = rule_name(path)
    folder = YARA_FIXTURES / path.stem / "negative"
    files = sorted(folder.iterdir())
    assert files, f"no negative fixtures for {path.stem}"
    for fixture in files:
        matches = {match.rule for match in compiled_rules.match(str(fixture))}
        assert name not in matches, f"{fixture.name} incorrectly matched {name}"


def test_fixtures_are_text_and_marked_synthetic() -> None:
    for path in YARA_FIXTURES.rglob("*"):
        if not path.is_file():
            continue
        assert path.suffix == ".txt", path
        # UTF-16LE fixtures start with the synthetic header as well.
        raw = path.read_bytes()
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = raw.decode("utf-16")
        elif b"\x00" in raw[:64]:
            text = raw.decode("utf-16-le")
        else:
            text = raw.decode("utf-8")
        assert "Synthetic test fixture" in text, path
