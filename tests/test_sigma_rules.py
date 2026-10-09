"""Validate Sigma rules and evaluate them against synthetic JSON events."""

from __future__ import annotations

import re
import subprocess
import uuid
from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.validators.core.condition import DanglingDetectionValidator
from sigma.validators.core.metadata import IdentifierExistenceValidator, IdentifierUniquenessValidator
from sigma.validators.core.tags import ATTACKTagValidator

from tests.conftest import SIGMA_DIR, SIGMA_FIXTURES
from tools.sigma_events import evaluate, load_events

ATTACK_TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$")
ATTACK_TACTIC_TAG = re.compile(r"^attack\.[a-z0-9-]+$")


def rule_files() -> list[Path]:
    return sorted(SIGMA_DIR.rglob("*.yml"))


@pytest.fixture(scope="module")
def all_rules() -> list[tuple[Path, dict]]:
    rules = []
    for path in rule_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.append((path, data))
    return rules


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.stem)
def test_rule_parses_as_sigma(path: Path) -> None:
    SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.stem)
def test_required_fields(path: Path) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    for field in (
        "title",
        "id",
        "status",
        "description",
        "author",
        "date",
        "logsource",
        "detection",
        "level",
    ):
        assert field in data, field
    assert data["author"] == "bfleming-bitflow"
    assert data["status"] in {"experimental", "test", "stable", "deprecated", "unsupported"}
    assert data["level"] in {"informational", "low", "medium", "high", "critical"}
    uuid.UUID(data["id"])
    assert (
        data["logsource"].get("product")
        or data["logsource"].get("service")
        or data["logsource"].get("category")
    )
    assert "condition" in data["detection"]
    assert isinstance(data.get("references"), list) and data["references"]
    assert isinstance(data.get("falsepositives"), list) and data["falsepositives"]
    tags = data.get("tags") or []
    assert any(ATTACK_TECHNIQUE_TAG.match(tag) for tag in tags), "missing attack.t#### technique tag"
    assert any(ATTACK_TACTIC_TAG.match(tag) and not ATTACK_TECHNIQUE_TAG.match(tag) for tag in tags)


def test_rule_ids_are_unique(all_rules: list[tuple[Path, dict]]) -> None:
    ids = [data["id"] for _, data in all_rules]
    assert len(ids) == len(set(ids))


def test_filenames_are_descriptive(all_rules: list[tuple[Path, dict]]) -> None:
    for path, _ in all_rules:
        assert len(path.stem) >= 10
        assert path.stem == path.stem.lower()


def test_sigma_cli_check_passes() -> None:
    import sys

    sigma = Path(sys.executable).with_name("sigma")
    assert sigma.exists(), f"sigma-cli not found next to {sys.executable}"
    result = subprocess.run(
        [str(sigma), "check", "--fail-on-issues", str(SIGMA_DIR)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_sigma_validators(all_rules: list[tuple[Path, dict]]) -> None:
    collection = SigmaCollection.merge(
        [SigmaCollection.from_yaml(path.read_text(encoding="utf-8")) for path, _ in all_rules]
    )
    issues = []
    for validator in (
        IdentifierExistenceValidator(),
        IdentifierUniquenessValidator(),
        DanglingDetectionValidator(),
    ):
        for rule in collection.rules:
            issues.extend(validator.validate(rule))
        issues.extend(validator.finalize())
    attack_validator = ATTACKTagValidator()
    for rule in collection.rules:
        issues.extend(attack_validator.validate(rule))
    issues.extend(attack_validator.finalize())
    assert issues == [], issues


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.stem)
def test_positive_events_match(path: Path) -> None:
    events_path = SIGMA_FIXTURES / f"{path.stem}.positive.json"
    events = load_events(events_path)
    results = evaluate(path, events)
    assert results and all(results), f"unmatched positive events for {path.stem}: {results}"


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.stem)
def test_negative_events_do_not_match(path: Path) -> None:
    events_path = SIGMA_FIXTURES / f"{path.stem}.negative.json"
    events = load_events(events_path)
    results = evaluate(path, events)
    assert results and not any(results), f"false matches for {path.stem}: {results}"
