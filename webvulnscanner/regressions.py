"""Continuous regression tracking (Phase 27 / CONT-01..04).

Pure, deterministic diffing of one completed scan's findings against an
Asset's previous completed scan - no network, no Flask/db imports, matching
the `_score_report` test-isolation discipline (CONT-04).

Matching rule (ROADMAP Phase 27): a finding is the SAME finding across two
scans when its check name AND title agree ("check name + finding title/path"
- titles carry the path for path-scoped findings like sensitive paths or
exposed services, so title equality is path-aware without a dedicated field).
List order never participates: findings are keyed, not zipped. Findings
written before checks grew a `check_name` fall back to matching on category,
so legacy report blobs still diff sensibly.

Semantics:
- previous report missing/unreadable  -> no baseline; current findings are
  passed through UNTOUCHED (no tags) and the summary is None. A scan whose
  predecessor saw zero findings IS a baseline (all current findings "new").
- "new"       - in current, key absent from previous.
- "recurring" - key present in both (even if severity/detail drifted).
- "resolved"  - key in previous, absent from current; surfaced as snapshot
  dicts ({check_name, title, severity}) inside the summary, since there is
  no current finding to hang a tag on.
"""

ALERT_SEVERITIES = frozenset({"high", "critical"})


def finding_key(f):
    """Stable cross-scan identity of a finding dict: (check name-or-category,
    title). The name half is case-folded so a legacy uppercase category
    ("TLS") matches the same issue reported under a lowercase check_name
    ("tls"); titles stay exact - they carry the path, and path casing is
    meaningful. Both halves coerced to str so a None category/check_name
    never poisons hashing."""
    return ((str(f.get("check_name") or f.get("category") or "").lower()),
            str(f.get("title") or ""))


def classify_regressions(previous_report, current_report):
    """Two report dicts in -> (tagged_current_findings, summary) out.

    Every returned finding is the current finding dict copied and given a
    `regression` key of "new" or "recurring"; when there is no baseline
    (previous report is None or carries no findings list at all) the copies
    are returned WITHOUT the tag and summary is None. `summary` is
    {"new": int, "recurring": int, "resolved": [{check_name, title,
    severity}, ...]} with `resolved` deterministically sorted by
    (check_name, title) so two identical inputs always produce byte-equal
    output."""
    current_findings = (current_report or {}).get("findings") or []
    previous_findings = (previous_report or {}).get("findings")

    if previous_findings is None:
        return [dict(f) for f in current_findings], None

    previous_keys = {finding_key(f) for f in previous_findings}

    tagged, new_count, recurring_count = [], 0, 0
    for f in current_findings:
        copy = dict(f)
        if finding_key(f) in previous_keys:
            copy["regression"] = "recurring"
            recurring_count += 1
        else:
            copy["regression"] = "new"
            new_count += 1
        tagged.append(copy)

    current_keys = {finding_key(f) for f in current_findings}
    resolved = sorted(
        (
            {
                # Same case-folded name half as the tag keys, so a resolved
                # snapshot can never disagree with the matching that dropped it.
                "check_name": finding_key(f)[0],
                "title": str(f.get("title") or ""),
                "severity": f.get("severity"),
            }
            for f in previous_findings
            if finding_key(f) not in current_keys
        ),
        key=lambda r: (r["check_name"], r["title"]),
    )

    return tagged, {"new": new_count, "recurring": recurring_count,
                    "resolved": resolved}


def alertable_new(findings):
    """The subset of TAGGED findings that warrant a `finding.regressed`
    webhook: regression == "new" AND severity High/Critical (CONT-03's
    threshold). Recurring and resolved findings never alert."""
    return [
        f for f in (findings or [])
        if f.get("regression") == "new"
        and str(f.get("severity") or "").lower() in ALERT_SEVERITIES
    ]
