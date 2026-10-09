"""Match Sigma rules against synthetic JSON events using the SQLite backend."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from sigma.backends.sqlite import sqlite
from sigma.collection import SigmaCollection
from sigma.conversion.base import Backend

TABLE = "events"
IDENTIFIER_RE = re.compile(r"[^A-Za-z0-9_]")


def load_rule(path: Path) -> SigmaCollection:
    return SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))


def convert_sql(rule_path: Path) -> str:
    backend: Backend = sqlite.sqliteBackend()
    queries = backend.convert(load_rule(rule_path))
    if len(queries) != 1:
        raise ValueError(f"{rule_path}: expected one query, got {len(queries)}")
    return queries[0].replace("FROM logs", f"FROM {TABLE}")


def _columns(events: list[dict]) -> list[str]:
    names: set[str] = set()
    for event in events:
        names.update(event)
    return sorted(names)


def evaluate(rule_path: Path, events: list[dict]) -> list[bool]:
    """Return whether each event matches the rule."""
    if not events:
        return []
    sql = convert_sql(rule_path)
    columns = _columns(events)
    column_sql = ", ".join(f'"{column}" TEXT' for column in columns)
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(f"CREATE TABLE {TABLE} (__row INTEGER PRIMARY KEY, {column_sql})")
        for index, event in enumerate(events):
            values = [
                str(event.get(column, "")) if event.get(column) is not None else None for column in columns
            ]
            placeholders = ", ".join("?" for _ in columns)
            quoted = ", ".join(f'"{column}"' for column in columns)
            connection.execute(
                f"INSERT INTO {TABLE} (__row, {quoted}) VALUES (?, {placeholders})",
                [index, *values],
            )
        # The backend emits SELECT * FROM ... WHERE ...
        # Wrap it to return matching row indexes.
        wrapped = f"SELECT __row FROM ({sql})"
        matched = {row[0] for row in connection.execute(wrapped)}
        return [index in matched for index in range(len(events))]
    finally:
        connection.close()


def load_events(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array of events")
    return data
