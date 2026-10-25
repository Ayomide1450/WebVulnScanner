"""The /scan/<id>/report-pack.zip route - web delivery of the prospecting
draft pack. Mirrors the ownership-guard tests for the other export routes."""
import io
import zipfile

from glassbox.extensions import db as _db
from glassbox.models import Report, ScanStatus
from tests.conftest import login, make_org, make_scan, make_user


def _attach_report(scan, hostname="example.com"):
    r = Report(
        scan_id=scan.id,
        json_path="unused-for-this-test.json",
        data={
            "hostname": hostname,
            "target": f"https://{hostname}",
            "severity_counts": {"high": 1},
            "findings": [
                {"check_name": "idor", "category": "idor", "cwe": "CWE-639",
                 "title": "Basket readable across accounts", "severity": "high",
                 "detail": "GET /rest/basket/2 leaked.", "recommendation": "Enforce ownership."},
            ],
        },
    )
    _db.session.add(r)


def test_owner_downloads_a_zip_of_three_drafts(client, db):
    org = make_org()
    user = make_user("pack-owner@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_report(scan)
    db.session.commit()

    login(client, "pack-owner@example.com")
    resp = client.get(f"/scan/{scan.id}/report-pack.zip")
    assert resp.status_code == 200
    assert resp.content_type == "application/zip"
    assert "attachment" in resp.headers["Content-Disposition"]
    assert "example.com_scan" in resp.headers["Content-Disposition"]

    with zipfile.ZipFile(io.BytesIO(resp.data)) as zf:
        assert set(zf.namelist()) == {"OFFER.md", "WRITEUP.md", "OUTREACH.md"}
        outreach = zf.read("OUTREACH.md").decode("utf-8")
        assert "Basket readable across accounts" in outreach
        assert "Authorised use only" in outreach


def test_cross_org_user_gets_404_not_the_pack(client, db):
    org_a = make_org(name="A")
    org_b = make_org(name="B")
    owner = make_user("owner@a.com", org=org_a)
    make_user("rival@b.com", org=org_b)  # the cross-org user who must be refused
    scan = make_scan(owner, org=org_a, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_report(scan)
    db.session.commit()

    login(client, "rival@b.com")
    resp = client.get(f"/scan/{scan.id}/report-pack.zip")
    assert resp.status_code == 404
    # nothing of the report leaks in the body
    assert b"Basket readable" not in resp.data


def test_no_report_row_is_404(client, db):
    org = make_org()
    user = make_user("noreport@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()

    login(client, "noreport@example.com")
    assert client.get(f"/scan/{scan.id}/report-pack.zip").status_code == 404
