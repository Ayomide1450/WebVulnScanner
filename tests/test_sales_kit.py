"""Report-pack generator: drafts an offer/writeup/outreach from a scan report."""
import json

from glassbox.sales_kit import (
    draft_offer,
    draft_outreach,
    draft_writeup,
    generate_kit,
    generate_kit_files,
)

_REPORT = {
    "hostname": "acme-demo.com",
    "target": "https://acme-demo.com",
    "score": 41,
    "risk_grade": "D",
    "severity_counts": {"critical": 1, "high": 2, "medium": 3, "low": 1, "pass": 9},
    "findings": [
        {"severity": "critical", "title": "SQL injection in login", "category": "sqli_login",
         "cwe": "CWE-89", "detail": "email accepts ' OR 1=1--", "recommendation": "Parameterise."},
        {"severity": "high", "title": "Basket readable across accounts", "category": "idor",
         "cwe": "CWE-639", "detail": "GET /rest/basket/2 leaked.", "recommendation": "Enforce ownership."},
        {"severity": "high", "title": "Missing CSP", "category": "headers", "cwe": "CWE-693"},
        {"severity": "medium", "title": "No rate limit on login", "category": "rate_limit"},
        {"severity": "pass", "title": "TLS valid", "category": "tls"},
    ],
}

_CLEAN = {"hostname": "clean.io", "score": 98, "risk_grade": "A",
          "findings": [{"severity": "pass", "title": "TLS valid"}]}


def test_generate_kit_produces_the_three_documents():
    kit = generate_kit(_REPORT)
    assert set(kit) == {"OFFER.md", "WRITEUP.md", "OUTREACH.md"}
    assert all(isinstance(v, str) and v.strip() for v in kit.values())


def test_every_document_carries_the_authorised_use_banner():
    """The whole point of the gating decision: no draft ships without the
    'authorised contacts only' line, including the clean-scan path."""
    for report in (_REPORT, _CLEAN):
        for body in generate_kit(report).values():
            assert "Authorised use only" in body


def test_outreach_cites_the_real_findings_most_severe_first():
    out = draft_outreach(_REPORT)
    # The critical finding must be cited, before the (lower) high ones.
    assert "SQL injection in login" in out
    assert out.index("SQL injection in login") < out.index("Basket readable across accounts")
    # Only the top 3 are cited, so the medium drops off; pass is never a problem.
    assert "No rate limit on login" not in out
    assert "TLS valid" not in out


def test_outreach_caps_citations_at_three():
    many = dict(_REPORT)
    many["findings"] = [
        {"severity": "high", "title": f"Issue {i}", "category": "x"} for i in range(10)
    ]
    out = draft_outreach(many)
    assert out.count("HIGH: Issue") == 3


def test_offer_and_outreach_are_personalised_to_the_host():
    assert "acme-demo.com" in draft_offer(_REPORT)
    assert "acme-demo.com" in draft_outreach(_REPORT)


def test_writeup_leads_with_the_most_severe_finding():
    wu = draft_writeup(_REPORT)
    assert "SQL injection in login" in wu
    assert "CWE-89" in wu


def test_clean_scan_still_produces_a_sensible_pitch_not_an_empty_doc():
    """A clean automated result is a pitch angle ('scanners miss the real
    bugs'), not a dead end - the outreach must not cite nonexistent issues."""
    out = draft_outreach(_CLEAN)
    assert "clean.io" in out
    assert "came back clean" in out
    wu = draft_writeup(_CLEAN)
    assert "clean" in wu.lower()


def test_is_deterministic():
    assert generate_kit(_REPORT) == generate_kit(_REPORT)


def test_handles_a_thin_report_without_crashing():
    """Older on-disk reports carry only a few keys - must degrade, not raise."""
    thin = {"target": "https://old.example", "findings": [{"severity": "high", "title": "x"}]}
    kit = generate_kit(thin)
    assert set(kit) == {"OFFER.md", "WRITEUP.md", "OUTREACH.md"}
    # falls back to target when hostname is absent
    assert "old.example" in kit["OUTREACH.md"]


def test_generate_kit_files_writes_all_three(tmp_path):
    written = generate_kit_files(_REPORT, tmp_path)
    names = {p.name for p in written}
    assert names == {"OFFER.md", "WRITEUP.md", "OUTREACH.md"}
    for p in written:
        assert p.exists() and p.read_text(encoding="utf-8").strip()


def test_cli_round_trip(tmp_path):
    from glassbox.sales_kit import _main

    report_path = tmp_path / "r.json"
    report_path.write_text(json.dumps(_REPORT), encoding="utf-8")
    out = tmp_path / "pack"
    rc = _main([str(report_path), "--out", str(out)])
    assert rc == 0
    assert (out / "OFFER.md").exists()


def test_cli_bad_path_returns_error_not_traceback(tmp_path, capsys):
    from glassbox.sales_kit import _main

    rc = _main([str(tmp_path / "nope.json")])
    assert rc == 1
    assert "could not read report" in capsys.readouterr().err
