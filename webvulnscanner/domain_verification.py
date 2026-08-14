"""
Domain-ownership verification (Workstream 6).

Two proof methods, mirroring how `checks.py` already talks to DNS/HTTP:
- DNS TXT: a `webvulnscanner-verify=<token>` TXT record on the domain.
- well-known: an HTTP GET of `/.well-known/<token>.txt` returning the token.

`verify_domain()` tries whichever `dv.method` is set on the row, and - like
every `check_*` function in checks.py - never lets a network failure raise;
it returns `False` instead so a flaky DNS/HTTP lookup can't take down the
route that called it.

Judgment call (re-adding the same domain): `generate_verification()` is
called from the `/org/verify-domain` POST `action=add` handler, and the
`DomainVerification` table has a `UNIQUE(org_id, domain)` constraint. If an
org re-submits a domain it already has a row for (e.g. to retry verification
with a fresh token, or after switching method), inserting a second row would
violate that constraint and raise an IntegrityError. Re-adding the same
domain is a reasonable thing for a user to do, so instead of erroring we
update the existing row in place: new token, new method, and - since the old
token is no longer the one being proven - `verified_at` is reset to `None`
(a previously-verified domain does not stay "verified" against a token it no
longer serves).
"""
import secrets
from datetime import datetime, timezone

import dns.resolver
import requests

from webvulnscanner.extensions import db
from webvulnscanner.models import DomainVerification

# Local timeout for the well-known HTTP check. checks.py's REQUEST_TIMEOUT
# (8s) is the established convention for outbound HTTP in this app; reused
# here rather than inventing a new constant.
VERIFY_HTTP_TIMEOUT = 8
DNS_TIMEOUT = 8


def generate_verification(org_id, domain, method):
    """Creates (or resets) a `DomainVerification` row for `org_id`+`domain`.

    Normalizes `domain` to lowercase. If a row already exists for this
    org+domain (see module docstring), it is updated in place - new token,
    new method, `verified_at` reset to None - rather than raising on the
    UNIQUE(org_id, domain) constraint.
    """
    domain = domain.strip().lower()
    token = secrets.token_hex(16)

    dv = DomainVerification.query.filter_by(org_id=org_id, domain=domain).first()
    if dv is not None:
        dv.token = token
        dv.method = method
        dv.verified_at = None
    else:
        dv = DomainVerification(org_id=org_id, domain=domain, method=method, token=token)
        db.session.add(dv)

    db.session.commit()
    return dv


def txt_record_value(dv):
    return f"webvulnscanner-verify={dv.token}"


def well_known_path_and_content(dv):
    return f"/.well-known/{dv.token}.txt", dv.token


def _verify_dns_txt(dv):
    expected = txt_record_value(dv)
    try:
        answers = dns.resolver.resolve(dv.domain, "TXT", lifetime=DNS_TIMEOUT)
        for rdata in answers:
            txt_value = "".join(s.decode() for s in rdata.strings)
            if txt_value == expected:
                return True
        return False
    except Exception:
        # DNS failures (NXDOMAIN, timeout, no TXT records, etc.) all mean
        # "not verified yet", not "the app is broken" - same ethos as
        # checks.py's check_* functions.
        return False


def _verify_well_known(dv):
    path, token = well_known_path_and_content(dv)
    for scheme in ("https", "http"):
        url = f"{scheme}://{dv.domain}{path}"
        try:
            r = requests.get(url, timeout=VERIFY_HTTP_TIMEOUT)
            if r.status_code == 200 and token in r.text:
                return True
        except requests.RequestException:
            continue
    return False


def verify_domain(dv):
    """Attempts to prove ownership of `dv.domain` via `dv.method`.

    On success, sets `verified_at` and commits, then returns True. On
    failure, returns False and leaves the row unchanged (a retry with a
    fixed record/file will succeed on a later call).
    """
    from webvulnscanner.models import VerifyMethod

    if dv.method == VerifyMethod.DNS_TXT:
        ok = _verify_dns_txt(dv)
    else:
        ok = _verify_well_known(dv)

    if ok:
        dv.verified_at = datetime.now(timezone.utc)
        db.session.commit()

    return ok
