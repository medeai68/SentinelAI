"""Validation tests (Part 11): programmatic security and portability checks.

These tests scan the project's own source code (not third-party code)
for unsafe patterns, hard-coded secrets, absolute local paths and
unparameterized SQL. They exist so regressions are caught automatically.
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.validation

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CHECKED_DIRS = ["src", "database", "dashboard", "config"]

FORBIDDEN_PATTERNS = [
    (re.compile(r"\beval\s*\("), "unsafe eval()"),
    (re.compile(r"\bexec\s*\("), "unsafe exec()"),
    (re.compile(r"\bos\.system\s*\("), "shell command execution"),
    (re.compile(r"shell\s*=\s*True"), "shell=True"),
    (re.compile(r"\b__import__\s*\("), "dynamic module imports"),
]

SECRET_PATTERNS = [
    (re.compile(r"password\s*=\s*['\"]"), "hard-coded password"),
    (re.compile(r"api[_-]?key\s*=\s*['\"]"), "hard-coded API key"),
    (re.compile(r"secret\s*=\s*['\"]"), "hard-coded secret"),
    (re.compile(r"token\s*=\s*['\"]"), "hard-coded token"),
]

ABSOLUTE_PATH_PATTERNS = [
    # a drive-letter absolute path literal: the letter must not be part of
    # a longer word (avoids matching "issues:\n" inside string literals)
    re.compile(r"(?<![A-Za-z0-9_])([A-Za-z]):[\\/]"),
]


def _project_python_files():
    files = []
    for dirname in CHECKED_DIRS:
        for path in sorted((PROJECT_ROOT / dirname).rglob("*.py")):
            files.append(path)
    assert files, "no project files found (test broken)"
    return files


def test_no_unsafe_dynamic_execution():
    hits = []
    for path in _project_python_files():
        text = path.read_text(encoding="utf-8")
        for pattern, label in FORBIDDEN_PATTERNS:
            if pattern.search(text):
                hits.append(f"{path}: {label}")
    assert hits == [], f"unsafe patterns found: {hits}"


def test_no_hardcoded_secrets():
    hits = []
    for path in _project_python_files():
        text = path.read_text(encoding="utf-8")
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(text):
                hits.append(f"{path}: {label}")
    assert hits == [], f"secrets found: {hits}"


def test_no_absolute_local_paths():
    """The project must be portable: no drive-letter absolute paths."""
    hits = []
    for path in _project_python_files():
        text = path.read_text(encoding="utf-8")
        for pattern in ABSOLUTE_PATH_PATTERNS:
            if pattern.search(text):
                hits.append(path)
    assert hits == [], f"absolute paths found: {hits}"


def test_sql_is_parameterized():
    """Repository SQL never interpolates values: every statement that
    carries user values (WHERE / VALUES / LIMIT) must use ? placeholders;
    the only allowed interpolations are the constant column list and the
    constant placeholder string (which is built purely from '?' and ', ')."""
    from database import repository as repo_module

    # the placeholder constant itself must contain nothing but ?/,/space
    assert set(repo_module._DETECTION_PLACEHOLDERS) <= {"?", ",", " "}

    text = (PROJECT_ROOT / "database" / "repository.py").read_text(encoding="utf-8")
    calls = re.findall(r"conn\.(?:execute|executemany)\(\s*([^,]+)", text)
    assert calls, "no SQL calls found (test broken)"
    for first_arg in calls:
        interpolated = (
            first_arg.replace("_DETECTION_COLUMNS", "")
            .replace("_DETECTION_PLACEHOLDERS", "")
        )
        assert not re.search(r"\{[^{}]+\}", interpolated), (
            f"value interpolation in SQL: {first_arg}"
        )
        if "VALUES" in first_arg:
            assert "?" in first_arg or "_DETECTION_PLACEHOLDERS" in first_arg, (
                f"unparameterized SQL: {first_arg}"
            )
        if ("WHERE" in first_arg or "LIMIT" in first_arg) and "?" not in first_arg:
            # allowed only for queries whose conditions are literal constants
            assert re.search(r"WHERE \w+ = \d+", first_arg), (
                f"unparameterized SQL: {first_arg}"
            )


def test_target_never_in_feature_list():
    """The saved feature list must never contain label columns."""
    from src.network.feature_extractor import EXTRACTABLE_FEATURES

    for name in ("Label", "binary_label", "multiclass_label"):
        assert name not in EXTRACTABLE_FEATURES


def test_dashboard_contains_no_write_sql():
    """The dashboard is read-only: no INSERT/UPDATE/DELETE/DROP/ALTER may
    appear in dashboard source code — data access goes through the
    repository."""
    write_sql = re.compile(r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE)\b", re.IGNORECASE)
    hits = []
    for path in sorted((PROJECT_ROOT / "dashboard").rglob("*.py")):
        if write_sql.search(path.read_text(encoding="utf-8")):
            hits.append(path.name)
    assert hits == [], f"write SQL found in dashboard: {hits}"


def test_dashboard_has_no_blocking_controls_or_network_calls():
    """The dashboard must provide no control that performs real network
    blocking and must not call out to the network."""
    forbidden = [
        re.compile(r"^\s*(import|from)\s+subprocess\b", re.MULTILINE),
        re.compile(r"\bos\.system\s*\("),
        re.compile(r"^\s*(import|from)\s+socket\b", re.MULTILINE),
        re.compile(r"^\s*(import|from)\s+requests\b", re.MULTILINE),
        re.compile(r"^\s*(import|from)\s+urllib\b", re.MULTILINE),
        re.compile(r"iptables|netsh|\bufw\b|firewall-cmd|pfctl"),
    ]
    hits = []
    for path in sorted((PROJECT_ROOT / "dashboard").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern.search(text):
                hits.append(f"{path.name}: {pattern.pattern}")
    assert hits == [], f"forbidden dashboard content: {hits}"
