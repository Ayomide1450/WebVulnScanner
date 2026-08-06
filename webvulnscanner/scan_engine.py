"""
Scan orchestrators for WebVulnScanner.

`run_scan`, `run_advanced_scan`, `run_media_scan` relocated verbatim from
`app.py` (Workstream 2 of the auth/entitlement plan). Workstream 3 adds
entitlement-gating (`tier`/`org_verified_for_domain` params) to `run_scan`
and `run_advanced_scan`, plus the `save_report()` helper.

This module stays free of any `current_user`/Flask-Login coupling by design:
`tier` and `org_verified_for_domain` are plain values the caller computes
(via `entitlements.effective_tier()` / `entitlements.domain_is_org_verified()`)
and passes in - the orchestrators never look either up themselves.

`run_media_scan` is deliberately NOT gated here - per the plan, media gating
happens one level up, in the route, before the orchestrator is even called
(`if FEATURE_REQUIREMENTS["media"] > tier: show a locked/upgrade card,
don't call run_media_scan at all`). That route-level gating is Workstream 4
territory. This asymmetry with run_scan/run_advanced_scan is intentional,
not an oversight.
"""
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from webvulnscanner.entitlements import FEATURE_REQUIREMENTS, Tier, allowed_checks
from webvulnscanner.checks import (
    REQUEST_TIMEOUT,
    REPORTS_DIR,  # noqa: F401  (re-exported for callers that import it from here)
    DOWNLOADS_DIR,  # noqa: F401
    SEVERITY_WEIGHT,
    SEVERITY_ORDER,
    _mk_session,
    check_headers,
    check_cookies,
    crawl_same_origin,
    check_tls_cert,
    check_https_redirect,
    check_sensitive_paths,
    check_robots_sitemap,
    check_cors,
    check_http_methods,
    check_open_redirect,
    check_directory_listing,
    check_mixed_content,
    check_dns_email_security,
    check_vulnerable_js,
    check_xss_sqli,
    check_exposed_secrets,
    check_sri,
    check_open_ports,
    check_media,
    check_sqli_login,
    check_bruteforce,
    check_sqli_union,
    check_xss_stored,
    check_idor,
    check_api_schema_exposure,
    check_api_wordlist,
    check_api_js_discovery,
)


def run_media_scan(base_url, download, max_files):
    session = _mk_session()
    data, findings = check_media(session, base_url, download, max_files)

    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, min(100, score))
    risk_grade = ("A" if score >= 90 else "B" if score >= 75 else
                  "C" if score >= 60 else "D" if score >= 40 else "F")

    severity_counts = {s: 0 for s in SEVERITY_WEIGHT}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))

    return {
        "target": base_url,
        "hostname": urlparse(base_url).netloc,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "risk_grade": risk_grade,
        "severity_counts": severity_counts,
        "findings": [asdict(f) for f in findings_sorted],
        "media": data,
    }


def run_api_scan(base_url):
    """Runs all three API-exposure checks against base_url. Uses the same
    Finding/severity/scoring model as the other three orchestrators.

    Not gated here, same as run_media_scan above and for the same reason:
    the api scan type has no sub-groups to partially unlock, so the route
    checks the tier upfront and never calls this at all if it's insufficient
    (see scan_routes.new_scan_api, mirroring new_scan_media's pattern)."""
    session = _mk_session()
    home_r = session.get(base_url + "/", timeout=REQUEST_TIMEOUT)
    home_html = home_r.text

    results = {}
    all_findings = []

    data, findings = check_api_schema_exposure(base_url, session)
    results["schema"] = data
    all_findings.extend(findings)

    data, findings = check_api_wordlist(base_url, session)
    results["wordlist"] = data
    all_findings.extend(findings)

    data, findings = check_api_js_discovery(session, base_url, home_html)
    results["js_discovery"] = data
    all_findings.extend(findings)

    score = 100
    for f in all_findings:
        score -= SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, min(100, score))
    risk_grade = ("A" if score >= 90 else "B" if score >= 75 else
                  "C" if score >= 60 else "D" if score >= 40 else "F")

    severity_counts = {s: 0 for s in SEVERITY_WEIGHT}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    findings_sorted = sorted(all_findings, key=lambda f: SEVERITY_ORDER.index(f.severity))

    return {
        "target": base_url,
        "hostname": urlparse(base_url).netloc,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "risk_grade": risk_grade,
        "severity_counts": severity_counts,
        "findings": [asdict(f) for f in findings_sorted],
        "results": results,
    }


def run_advanced_scan(advanced, tier, org_verified_for_domain):
    """Runs whichever advanced check groups have their required fields
    filled in, independent of the base recon/crawl scan. Uses the same
    Finding/severity/scoring model so reports stay consistent.

    Every advanced check is ORG_VERIFIED-tier (see FEATURE_REQUIREMENTS), so
    in practice: below that tier, or with an unverified domain, every group
    lands in `locked` regardless of form-field completeness.
    """
    session = _mk_session()
    results = {}
    all_findings = []
    targets = []
    locked = []

    has_login_fields = bool(advanced.get("login_url") and advanced.get("user_field")
                             and advanced.get("pass_field") and advanced.get("fail_text"))
    login_allowed = FEATURE_REQUIREMENTS["sqli_login"] <= tier and org_verified_for_domain
    # bruteforce reuses the same login fields (login_url/user_field/pass_field/
    # fail_text) plus its own two, and only ever runs alongside the login
    # check - but its *lock* status is tracked independently of whether the
    # login check executed, since FEATURE_REQUIREMENTS gates it as its own
    # named check and it must land in `locked` whenever its own fields are
    # present and tier/domain gating denies it (even if that denial is the
    # same one that also locked sqli_login).
    has_bruteforce_fields = has_login_fields and bool(advanced.get("bruteforce_username")
                                                        and advanced.get("bruteforce_passwords"))
    bruteforce_allowed = FEATURE_REQUIREMENTS["bruteforce"] <= tier and org_verified_for_domain

    if has_login_fields and login_allowed:
        targets.append(advanced["login_url"])
        data, findings = check_sqli_login(session, advanced["login_url"], advanced["user_field"],
                                           advanced["pass_field"], advanced["fail_text"])
        results["sqli_login"] = data
        all_findings.extend(findings)
    elif has_login_fields:
        locked.append("sqli_login")

    if has_bruteforce_fields and login_allowed and bruteforce_allowed:
        data, findings = check_bruteforce(session, advanced["login_url"], advanced["user_field"],
                                           advanced["pass_field"], advanced["bruteforce_username"],
                                           advanced["bruteforce_passwords"], advanced["fail_text"])
        results["bruteforce"] = data
        all_findings.extend(findings)
    elif has_bruteforce_fields:
        locked.append("bruteforce")

    if advanced.get("sqli_union_url") and advanced.get("sqli_union_param") \
            and FEATURE_REQUIREMENTS["sqli_union"] <= tier and org_verified_for_domain:
        targets.append(advanced["sqli_union_url"])
        data, findings = check_sqli_union(session, advanced["sqli_union_url"], advanced["sqli_union_param"])
        results["sqli_union"] = data
        all_findings.extend(findings)
    elif advanced.get("sqli_union_url") and advanced.get("sqli_union_param"):
        locked.append("sqli_union")

    if advanced.get("stored_xss_submit_url") and advanced.get("stored_xss_field") and \
            advanced.get("stored_xss_view_url") and advanced.get("stored_xss_cookie") \
            and FEATURE_REQUIREMENTS["xss_stored"] <= tier and org_verified_for_domain:
        targets.append(advanced["stored_xss_submit_url"])
        data, findings = check_xss_stored(session, advanced["stored_xss_submit_url"], advanced["stored_xss_field"],
                                           advanced["stored_xss_view_url"], advanced["stored_xss_cookie"])
        results["xss_stored"] = data
        all_findings.extend(findings)
    elif advanced.get("stored_xss_submit_url") and advanced.get("stored_xss_field") and \
            advanced.get("stored_xss_view_url") and advanced.get("stored_xss_cookie"):
        locked.append("xss_stored")

    if advanced.get("idor_url_template") and advanced.get("idor_ids") and \
            advanced.get("idor_cookie_a") and advanced.get("idor_cookie_b") \
            and FEATURE_REQUIREMENTS["idor"] <= tier and org_verified_for_domain:
        targets.append(advanced["idor_url_template"])
        data, findings = check_idor(session, advanced["idor_url_template"], advanced["idor_ids"],
                                     advanced["idor_cookie_a"], advanced["idor_cookie_b"])
        results["idor"] = data
        all_findings.extend(findings)
    elif advanced.get("idor_url_template") and advanced.get("idor_ids") and \
            advanced.get("idor_cookie_a") and advanced.get("idor_cookie_b"):
        locked.append("idor")

    score = 100
    for f in all_findings:
        score -= SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, min(100, score))
    risk_grade = ("A" if score >= 90 else "B" if score >= 75 else
                  "C" if score >= 60 else "D" if score >= 40 else "F")

    severity_counts = {s: 0 for s in SEVERITY_WEIGHT}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    findings_sorted = sorted(all_findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
    hostname = urlparse(targets[0]).netloc if targets else "unspecified-target"

    return {
        "hostname": hostname,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "risk_grade": risk_grade,
        "severity_counts": severity_counts,
        "findings": [asdict(f) for f in findings_sorted],
        "results": results,
        "ran": list(results.keys()),
        "locked_checks": locked,
    }


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def run_scan(base_url, manual_test_url, tier, org_verified_for_domain, progress_cb=None):
    session = _mk_session()
    hostname = urlparse(base_url).netloc

    home_resp = session.get(base_url + "/", timeout=REQUEST_TIMEOUT)
    home_html = home_resp.text

    header_data, f1 = check_headers(home_resp)
    cookie_rows, f2 = check_cookies(home_resp)

    # Only open_redirect (PAID) and xss_sqli (ORG_VERIFIED) consume the crawl
    # output - no FREE-tier check does, so skip the crawl entirely rather
    # than doing paid-tier work for a free-tier caller.
    if tier == Tier.FREE:
        param_urls, forms = [], []
    else:
        param_urls, forms = crawl_same_origin(base_url, home_html)
    if manual_test_url:
        param_urls = [manual_test_url] + [u for u in param_urls if u != manual_test_url]

    jobs = {
        "tls": lambda: check_tls_cert(hostname),
        "https_redirect": lambda: check_https_redirect(base_url, session),
        "sensitive_paths": lambda: check_sensitive_paths(base_url, session),
        "robots_sitemap": lambda: check_robots_sitemap(base_url, session),
        "cors": lambda: check_cors(base_url, session),
        "http_methods": lambda: check_http_methods(base_url, session),
        "open_redirect": lambda: check_open_redirect(base_url, session, [urlparse(u).path for u in param_urls]),
        "directory_listing": lambda: check_directory_listing(base_url, session),
        "mixed_content": lambda: check_mixed_content(base_url, home_html),
        "dns_email": lambda: check_dns_email_security(hostname),
        "vulnerable_js": lambda: check_vulnerable_js(base_url, home_html),
        "xss_sqli": lambda: check_xss_sqli(param_urls, session),
        "secrets": lambda: check_exposed_secrets(session, base_url, home_html),
        "sri": lambda: check_sri(base_url, home_html),
    }

    allowed, locked = allowed_checks(list(jobs.keys()), tier)
    if not org_verified_for_domain:
        # Tier alone is not enough for ORG_VERIFIED-tier checks - the domain
        # must also be verified. Strip those out of `allowed` even if the
        # tier comparison alone would have let them through.
        still_allowed = []
        for name in allowed:
            if FEATURE_REQUIREMENTS[name] == Tier.ORG_VERIFIED:
                locked.append(name)
            else:
                still_allowed.append(name)
        allowed = still_allowed
    jobs = {k: v for k, v in jobs.items() if k in allowed}

    results = {}
    all_findings = list(f1) + list(f2)
    # +3 for headers/cookies/open_ports, which run outside the jobs dict
    # (see below) but should still be represented in the live feed/progress
    # ratio rather than silently skipped, as they were before this signature
    # change (`progress_cb` used to only see `(done, total)`, so headers and
    # cookies never emitted an event at all).
    total = len(jobs) + 3
    done = 0

    # headers/cookies already ran (synchronously, above, before this jobs
    # dict even existed) - their progress_cb events fire here, now that
    # `total` is known, so they land as the live feed's first two rows,
    # ahead of any parallel job's "started" event, matching real execution
    # order even though the calls themselves are deferred.
    done += 1
    if progress_cb:
        progress_cb("headers", "completed", done, total, detail=f"grade {header_data['grade']}")
    done += 1
    if progress_cb:
        progress_cb("cookies", "completed", done, total)

    with ThreadPoolExecutor(max_workers=max(len(jobs), 1)) as pool:
        future_map = {}
        for name, fn in jobs.items():
            if progress_cb:
                progress_cb(name, "started", done, total)
            future_map[pool.submit(fn)] = name
        for fut in as_completed(future_map):
            name = future_map[fut]
            try:
                data, findings = fut.result()
                phase, detail = "completed", None
            except Exception as e:
                data, findings = {"error": str(e)}, []
                phase, detail = "failed", str(e)[:255]
            results[name] = data
            all_findings.extend(findings)
            done += 1
            if progress_cb:
                progress_cb(name, phase, done, total, detail=detail)

    if FEATURE_REQUIREMENTS["open_ports"] <= tier:
        ports, resolved_ip, f_ports = check_open_ports(hostname)
        results["open_ports"] = ports
        all_findings.extend(f_ports)
        open_ports_phase = "completed"
    else:
        ports, resolved_ip, f_ports = [], None, []
        locked.append("open_ports")
        # `open_ports_phase = None` rather than "completed" - the counter
        # bump below is unconditional (preserving the existing behavior of
        # progress_current/progress_total advancing regardless of gating),
        # but a locked check never ran, so it must not get a fabricated
        # ScanEvent row. scan_routes._run_scan_in_background's progress_cb
        # closure treats phase=None as "update counters only, write no
        # ScanEvent" - see its docstring.
        open_ports_phase = None
    done += 1
    if progress_cb:
        progress_cb("open_ports", open_ports_phase, done, total)

    score = 100
    for f in all_findings:
        score -= SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, min(100, score))
    risk_grade = ("A" if score >= 90 else "B" if score >= 75 else
                  "C" if score >= 60 else "D" if score >= 40 else "F")

    severity_counts = {s: 0 for s in SEVERITY_WEIGHT}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    findings_sorted = sorted(all_findings, key=lambda f: SEVERITY_ORDER.index(f.severity))

    return {
        "target": base_url,
        "resolved_ip": resolved_ip,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "risk_grade": risk_grade,
        "severity_counts": severity_counts,
        "findings": [asdict(f) for f in findings_sorted],
        "headers": header_data,
        "cookies": cookie_rows,
        # A check whose name was filtered out of `jobs` above never wrote to
        # `results`, so a direct `results["name"]` index here would raise
        # KeyError once gating actually filters something out. `.get(...,
        # {"locked": True})` is a JSON-serializable placeholder that
        # `templates/results.html` renders without throwing (verified by
        # actually rendering a gated report - see task verification notes).
        "tls": results.get("tls", {"locked": True}),
        "https_redirect": results.get("https_redirect", {"locked": True}),
        "sensitive_paths": results.get("sensitive_paths", {"locked": True}),
        "robots_sitemap": results.get("robots_sitemap", {"locked": True}),
        "open_ports": ports,
        "cors": results.get("cors", {"locked": True}),
        "http_methods": results.get("http_methods", {"locked": True}),
        "open_redirect": results.get("open_redirect", {"locked": True}),
        "directory_listing": results.get("directory_listing", {"locked": True}),
        "mixed_content": results.get("mixed_content", {"locked": True}),
        "dns_email": results.get("dns_email", {"locked": True}),
        "vulnerable_js": results.get("vulnerable_js", {"locked": True}),
        "xss_sqli": results.get("xss_sqli", {"locked": True}),
        "secrets": results.get("secrets", {"locked": True}),
        "sri": results.get("sri", {"locked": True}),
        "crawl": {"discovered_urls": param_urls, "forms": forms},
        "locked_checks": locked,
    }


def save_report(report, prefix, hostname):
    """Writes `report` as timestamped JSON to REPORTS_DIR, consolidating the
    3x-duplicated inline `json.dump` blocks that used to live in app.py's
    route bodies (one per scan type, differing only by filename `prefix`:
    "" for base scans, "advanced_" for advanced scans, "media_" for media
    scans). Returns the filename (not the full path), matching what the
    routes pass to `render_template(..., report_file=fname)`.

    Pre-existing bug, not fixed here (documented in the plan): filenames use
    second-resolution timestamps with no uniqueness guard, so a same-second
    re-scan of the same host silently overwrites the prior JSON file.
    """
    fname = f"{prefix}{hostname.replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(os.path.join(REPORTS_DIR, fname), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return fname
