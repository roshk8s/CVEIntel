"""CVEIntel input parsing and validation."""

from __future__ import annotations

import csv
import io
import re

from cveintel.core.exceptions import InputError

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def validate_cve(cve_id: str) -> bool:
    """Return True if cve_id matches CVE-YYYY-NNNNN+ format."""
    return bool(CVE_PATTERN.match(cve_id))


def parse_cve_args(args: list[str]) -> list[str]:
    """Parse and validate CVE IDs from CLI arguments (space or comma separated).

    Raises InputError with the invalid identifier in the message.
    """
    cve_ids: list[str] = []
    for arg in args:
        for token in arg.split(","):
            token = token.strip()
            if not token:
                continue
            if not validate_cve(token):
                raise InputError(
                    f"Invalid CVE identifier '{token}'. Expected format: CVE-YYYY-NNNNN"
                )
            cve_ids.append(token)
    return cve_ids


def parse_cve_file(file_path: str) -> tuple[list[str], list[str]]:
    """Parse CVE IDs from a file (CSV or one-per-line).

    Returns (valid_cves, warnings) where warnings list invalid lines.
    Raises InputError with file path and OS error detail if file is
    missing or unreadable.
    """
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    except OSError as exc:
        raise InputError(f"Cannot read file '{file_path}': {exc}") from exc

    valid_cves: list[str] = []
    warnings: list[str] = []

    # Detect CSV by checking if any non-empty line contains a comma
    lines = content.splitlines()
    is_csv = any("," in line for line in lines if line.strip())

    if is_csv:
        reader = csv.reader(io.StringIO(content))
        for row in reader:
            for field in row:
                token = field.strip()
                if not token:
                    continue
                if validate_cve(token):
                    valid_cves.append(token)
                else:
                    warnings.append(token)
    else:
        for line in lines:
            token = line.strip()
            if not token:
                continue
            if validate_cve(token):
                valid_cves.append(token)
            else:
                warnings.append(token)

    return valid_cves, warnings
