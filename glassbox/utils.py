"""Shared pure helpers used across multiple blueprints/modules.

``safe_filename`` is the single source of truth for download-filename
sanitisation (PDFX-07), retroactively applied to CSV, SARIF, and PDF
exporters so all three cannot drift.
"""

import re


def safe_filename(name):
    """Allowlist sanitizer for download filenames (PDFX-07).  Any character
    not in ``[A-Za-z0-9._-]`` is replaced with ``_``.  Leading dots are
    collapsed so a basename like ``.hidden`` does not produce a hidden file
    on POSIX.  Returns ``"scan"`` for an empty/None input."""
    if not name:
        return "scan"
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(name))
    cleaned = cleaned.lstrip(".")
    return cleaned or "scan"
