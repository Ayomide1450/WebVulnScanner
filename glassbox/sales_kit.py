"""Report-pack generator: turn one finished scan into prospecting drafts.

Given a Glassbox report dict (the same structure build_pdf_report and
build_sarif_report consume), this drafts three editable markdown documents a
security consultant can use to pitch a full manual review off the back of an
automated scan:

  OFFER.md    - a fixed-scope review offer, personalised with the target and
                the headline finding count.
  WRITEUP.md  - a short, de-identified technical note about the single most
                severe finding, for posting publicly to pull inbound.
  OUTREACH.md - a cold email + DM, citing the two or three real issues the
                scan surfaced on that specific site.

AUTHORISED USE. To produce a report at all the operator already had to pass
Glassbox's server-side authorisation checkbox for that scan, so the scan
itself is gated upstream. Drafting is not permission to SEND, though: every
generated document carries a header saying the outreach may only go to a
target the sender is authorised to contact. These are drafts to edit, never
auto-send - the module writes files and returns strings, it never transmits.

Pure functions, no I/O except the thin generate_kit_files() helper and the
__main__ CLI. Deterministic for a given report.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "pass": 5}
_ACTIONABLE = ("critical", "high", "medium", "low")

_AUTHORISED_USE_BANNER = (
    "> **Authorised use only.** These are editable drafts generated from a scan "
    "you ran. Only send outreach to a person or organisation you are authorised "
    "to contact about their site. Scanning or messaging a target without "
    "permission may be unlawful in your jurisdiction.\n"
)


def _hostname(report: dict) -> str:
    return report.get("hostname") or report.get("target") or "the target site"


def _sorted_actionable(report: dict) -> list[dict]:
    """Findings worth citing, most severe first, pass/info dropped."""
    findings = [
        f for f in (report.get("findings") or [])
        if isinstance(f, dict) and f.get("severity") in _ACTIONABLE
    ]
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", ""), 9))


def _counts(report: dict) -> dict:
    counts = report.get("severity_counts")
    if isinstance(counts, dict) and counts:
        return counts
    out: dict[str, int] = {}
    for f in report.get("findings") or []:
        if isinstance(f, dict):
            sev = f.get("severity", "info")
            out[sev] = out.get(sev, 0) + 1
    return out


def _headline(report: dict) -> str:
    counts = _counts(report)
    urgent = counts.get("critical", 0) + counts.get("high", 0)
    actionable = sum(counts.get(s, 0) for s in _ACTIONABLE)
    if urgent:
        return (
            f"{urgent} finding{'s' if urgent != 1 else ''} that need attention now"
            f"{f', plus {actionable - urgent} lower-severity' if actionable > urgent else ''}"
        )
    if actionable:
        return f"{actionable} lower-severity item{'s' if actionable != 1 else ''}"
    return "no issues from the automated pass"


def _finding_line(f: dict) -> str:
    sev = (f.get("severity") or "").upper()
    title = f.get("title") or f.get("category") or "Finding"
    cwe = f.get("cwe")
    return f"- **{sev}** — {title}" + (f" ({cwe})" if cwe else "")


def draft_offer(report: dict) -> str:
    host = _hostname(report)
    grade = report.get("risk_grade") or report.get("grade") or "N/A"
    score = report.get("score", "N/A")
    top = _sorted_actionable(report)[:3]
    top_block = "\n".join(_finding_line(f) for f in top) or "- (no actionable findings surfaced)"
    return f"""{_AUTHORISED_USE_BANNER}
# Application Security Review — {host}

**Prepared from an automated Glassbox scan of {host} (grade {grade}, {score}/100).**

## Why this matters

An automated scan is a first pass. It already surfaced {_headline(report)} on
{host} — for example:

{top_block}

What a scanner *cannot* see is the class of bug that actually leaks customer
data: broken access control (one user reaching another's records),
authentication bypass, and business-logic flaws. Those are found by hand.

## What you get

A **5-business-day manual security review** of {host} and its API:

- Authentication & session handling (login logic, token forgery, rate limiting)
- Access control — horizontal & vertical (IDOR, privilege escalation)
- Injection & output encoding (SQLi, stored/reflected XSS)
- Configuration & transport (the items above, verified and expanded)

**Deliverable:** a severity-ranked report with reproduction steps and fixes
for every finding, a leverage-ordered remediation roadmap, and one re-test
once your fixes land.

## Scope & price

| | |
|---|---|
| Scope | {host} + same-origin API |
| Duration | 5 business days |
| Price | $500 (first 3 clients, testimonial rate) → $1,250 standard |
| Re-test | Included, one round |

Non-destructive, authorised testing only — scope agreed in writing before
anything starts.

**Contact:** web3cipher@intigriti.me
"""


def draft_writeup(report: dict) -> str:
    # Intentionally does not read the hostname: the writeup is de-identified,
    # so the target is never named in it.
    top = _sorted_actionable(report)
    if not top:
        lead = (
            "This scan came back clean on the automated checks — which is a good "
            "sign, and also the perfect moment to talk about what automated checks "
            "*don't* cover."
        )
        focus_title = "Why a clean scan is not a clean bill of health"
        focus_body = (
            "Scanners pattern-match: a missing header, a known-vulnerable library, "
            "a reflected parameter. They do not understand authorisation logic, so "
            "they miss the single most common serious bug in real apps — one user "
            "reaching another user's data by changing an ID."
        )
    else:
        f = top[0]
        sev = (f.get("severity") or "").upper()
        title = f.get("title") or f.get("category") or "the finding"
        cwe = f.get("cwe")
        detail = f.get("detail") or ""
        rec = f.get("recommendation") or ""
        lead = (
            f"A quick automated pass over a live site surfaced a **{sev}** issue "
            f"worth walking through, because it is the kind of thing teams ship "
            f"without noticing."
        )
        focus_title = title + (f" ({cwe})" if cwe else "")
        focus_body = (
            (f"**What was observed:** {detail}\n\n" if detail else "")
            + (f"**How to fix it:** {rec}\n\n" if rec else "")
            + "The point is not this one finding — it is that it was reachable at "
            "all, from the outside, with no special access."
        )
    return f"""{_AUTHORISED_USE_BANNER}
# {focus_title}

*A short, de-identified note from a security pass over a live web application.
The target is not named; the pattern is what matters.*

{lead}

## The finding

{focus_body}

## Why scanners miss the bigger ones

Automated tooling is good at the mechanical: headers, versions, reflected
input. It is bad at the thing that actually leaks data — authorisation logic.
A scanner does not know that record #2 belongs to a different person than
record #1. Only a human testing with two accounts does.

## The takeaway

If you run a web app with user-owned objects — baskets, orders, profiles,
files, messages — the highest-value thing to test is whether one logged-in
user can reach another's by changing an ID. That takes two accounts and a
methodical pass over every `GET /thing/:id` route.

*That pass is what I do. If you want it run against your app:
web3cipher@intigriti.me*
"""


def draft_outreach(report: dict) -> str:
    host = _hostname(report)
    top = _sorted_actionable(report)[:3]
    if top:
        cited = "\n".join(
            f"- {(f.get('severity') or '').upper()}: "
            f"{f.get('title') or f.get('category') or 'an issue'}"
            for f in top
        )
        email_body = f"""Hi [name],

I ran a quick, non-intrusive security pass over {host} and a few things stood
out that are worth a look:

{cited}

None of these are the end of the story — the issues that actually leak
customer data (broken access control, auth bypass) need manual testing to
find. I do fixed-scope 5-day manual reviews for teams your size and deliver a
report your engineers can act on immediately.

Worth a 15-minute call this week? First few clients get a discounted
testimonial rate.

— web3cipher · web3cipher@intigriti.me"""
        dm = (
            f"Hey [name] — ran a quick security pass over {host} and spotted a "
            f"{(top[0].get('severity') or '').lower()}-severity "
            f"{top[0].get('title') or 'issue'} plus a couple more. The ones that "
            f"really matter (access control, auth) need manual testing though. "
            f"I do fixed-scope reviews — worth a 15-min call? Sample report: [link]"
        )
    else:
        email_body = f"""Hi [name],

I ran a quick, non-intrusive security pass over {host}. The automated checks
came back clean — which is good, and also exactly when it's worth a manual
review, because the bugs that leak customer data (broken access control, auth
bypass) don't show up in automated scans at all.

I do fixed-scope 5-day manual reviews and deliver a report your engineers can
act on immediately. Worth a 15-minute call this week?

— web3cipher · web3cipher@intigriti.me"""
        dm = (
            f"Hey [name] — ran a security pass over {host}; automated checks are "
            f"clean, but that's exactly the stuff scanners can't see (access "
            f"control, auth logic). I do manual reviews — worth a quick call? "
            f"Sample report: [link]"
        )
    return f"""{_AUTHORISED_USE_BANNER}
# Outreach drafts — {host}

Edit the bracketed fields before sending. Send only to a contact you are
authorised to approach about this site.

## Cold email

> Subject: quick security note about {host}

{email_body}

## Short DM / LinkedIn message

{dm}
"""


def generate_kit(report: dict) -> dict[str, str]:
    """Return {filename: markdown} for the three prospecting drafts."""
    return {
        "OFFER.md": draft_offer(report),
        "WRITEUP.md": draft_writeup(report),
        "OUTREACH.md": draft_outreach(report),
    }


def generate_kit_files(report: dict, out_dir: str | Path) -> list[Path]:
    """Write the kit to out_dir, returning the paths written."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, content in generate_kit(report).items():
        path = out / name
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written


def _main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m glassbox.sales_kit",
        description="Draft an editable prospecting pack (offer/writeup/outreach) "
        "from a Glassbox scan report JSON.",
    )
    parser.add_argument("report", help="path to a report JSON file (see reports/)")
    parser.add_argument(
        "--out", default="./report-pack", help="output directory (default: ./report-pack)"
    )
    args = parser.parse_args(argv)

    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read report {args.report!r}: {exc}", file=sys.stderr)
        return 1

    written = generate_kit_files(report, args.out)
    print("Drafted (edit before sending; authorised contacts only):")
    for p in written:
        print(f"  {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
