"""Generate the ATT&CK coverage table from rule metadata."""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
YARA_DIR = ROOT / "rules" / "yara"
SIGMA_DIR = ROOT / "rules" / "sigma"
TECHNIQUES_CSV = ROOT / "data" / "attack-enterprise-techniques.csv"
TACTICS_CSV = ROOT / "data" / "attack-enterprise-tactics.csv"
OUTPUT = ROOT / "docs" / "coverage.md"

ATTACK_TAG = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
ATTACK_META = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
YARA_RULE = re.compile(r"^\s*rule\s+(\w+)\s*(:.*)?\{", re.MULTILINE)
YARA_META_BLOCK = re.compile(
    r"rule\s+(\w+)\s*(?::[^{]*)?\{.*?meta:\s*(.*?)(?:strings:|condition:)",
    re.DOTALL,
)


def load_technique_names() -> dict[str, str]:
    with TECHNIQUES_CSV.open(encoding="utf-8", newline="") as handle:
        return {row["technique_id"]: row["name"] for row in csv.DictReader(handle)}


def load_tactic_names() -> dict[str, str]:
    with TACTICS_CSV.open(encoding="utf-8", newline="") as handle:
        return {row["shortname"]: row["name"] for row in csv.DictReader(handle)}


def sigma_rules() -> list[tuple[Path, dict]]:
    rules = []
    for path in sorted(SIGMA_DIR.rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "title" in data and "detection" in data:
            rules.append((path, data))
    return rules


def yara_rules() -> list[tuple[Path, str, dict[str, str]]]:
    results = []
    for path in sorted(YARA_DIR.glob("*.yar")):
        text = path.read_text(encoding="utf-8")
        for match in YARA_META_BLOCK.finditer(text):
            name = match.group(1)
            meta: dict[str, str] = {}
            for line in match.group(2).splitlines():
                line = line.strip().rstrip(",")
                if not line or line.startswith("//") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                meta[key.strip()] = value.strip().strip('"')
            results.append((path, name, meta))
    return results


def techniques_from_sigma(data: dict) -> set[str]:
    found: set[str] = set()
    for tag in data.get("tags") or []:
        match = ATTACK_TAG.match(str(tag))
        if match:
            found.add(f"T{match.group(1)}")
    return found


def techniques_from_yara(meta: dict[str, str]) -> set[str]:
    found: set[str] = set()
    for key, value in meta.items():
        if key == "mitre_attack" or key.startswith("mitre_attack"):
            found.update(ATTACK_META.findall(value))
    return normalize_technique_ids(found)


def normalize_technique_ids(values: set[str]) -> set[str]:
    result = set()
    for value in values:
        match = re.fullmatch(r"[Tt](\d{4}(?:\.\d{3})?)", value)
        if match:
            result.add(f"T{match.group(1)}")
    return result


def collect() -> dict[str, dict[str, list[str]]]:
    """technique_id -> {"yara": [...], "sigma": [...]}"""
    coverage: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"yara": [], "sigma": []})
    for path, data in sigma_rules():
        for technique in techniques_from_sigma(data):
            coverage[technique]["sigma"].append(path.stem)
    for _path, name, meta in yara_rules():
        for technique in normalize_technique_ids(techniques_from_yara(meta)):
            coverage[technique]["yara"].append(name)
    return coverage


def render(coverage: dict[str, dict[str, list[str]]], names: dict[str, str]) -> str:
    lines = [
        "# ATT&CK coverage",
        "",
        "<!-- Generated from rule metadata by tools/coverage.py. Do not edit by hand. -->",
        "",
        "Enterprise ATT&CK techniques referenced by rules in this repository. Technique names",
        f"come from ATT&CK v{read_attack_version()} (`data/attack-enterprise-techniques.csv`).",
        "Tactic names follow the current ATT&CK vocabulary (including `stealth` and",
        "`defense-impairment`).",
        "",
        "| Technique | Name | YARA rules | Sigma rules |",
        "| --- | --- | --- | --- |",
    ]
    for technique in sorted(coverage, key=_technique_key):
        entry = coverage[technique]
        yara = ", ".join(f"`{name}`" for name in sorted(set(entry["yara"]))) or "-"
        sigma = ", ".join(f"`{name}`" for name in sorted(set(entry["sigma"]))) or "-"
        url = f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"
        lines.append(f"| [{technique}]({url}) | {names.get(technique, '?')} | {yara} | {sigma} |")
    lines.append("")
    lines.append("| Kind | Rules | Distinct techniques |")
    lines.append("| --- | --- | --- |")
    yara_count = len(list(YARA_DIR.glob("*.yar")))
    sigma_count = len(list(SIGMA_DIR.rglob("*.yml")))
    yara_tech = {t for t, e in coverage.items() if e["yara"]}
    sigma_tech = {t for t, e in coverage.items() if e["sigma"]}
    lines.append(f"| YARA | {yara_count} | {len(yara_tech)} |")
    lines.append(f"| Sigma | {sigma_count} | {len(sigma_tech)} |")
    lines.append(f"| Combined | {yara_count + sigma_count} | {len(coverage)} |")
    lines.append("")
    return "\n".join(lines)


def read_attack_version() -> str:
    marker = ROOT / "data" / "ATTACK_VERSION"
    return marker.read_text(encoding="utf-8").strip() if marker.exists() else "unknown"


def _technique_key(technique: str) -> tuple:
    return tuple(int(part) for part in technique.lstrip("T").split("."))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if docs/coverage.md is stale")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)

    coverage = collect()
    names = load_technique_names()
    unknown = sorted(technique for technique in coverage if technique not in names)
    if unknown:
        print(f"unknown ATT&CK technique IDs: {', '.join(unknown)}", file=sys.stderr)
        return 1
    content = render(coverage, names)
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else None
        if current != content:
            print(f"stale: {args.output}", file=sys.stderr)
            print("run 'python tools/coverage.py' and commit the result", file=sys.stderr)
            return 1
        print("coverage is up to date")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
