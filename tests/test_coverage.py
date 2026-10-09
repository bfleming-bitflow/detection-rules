"""Coverage generator and ATT&CK identifier checks."""

from __future__ import annotations

import csv

from tests.conftest import ROOT
from tools import coverage


def test_attack_reference_contains_used_techniques() -> None:
    names = coverage.load_technique_names()
    used = set(coverage.collect())
    assert used
    assert used <= set(names)


def test_coverage_document_is_up_to_date() -> None:
    assert coverage.main(["--check"]) == 0


def test_attack_version_matches_marker() -> None:
    assert (ROOT / "data" / "ATTACK_VERSION").read_text(encoding="utf-8").strip() == "19.2"


def test_tactics_csv_uses_current_shortnames() -> None:
    with (ROOT / "data" / "attack-enterprise-tactics.csv").open(encoding="utf-8", newline="") as handle:
        shortnames = {row["shortname"] for row in csv.DictReader(handle)}
    assert "stealth" in shortnames
    assert "defense-impairment" in shortnames
    assert "defense-evasion" not in shortnames
