"""
Scan orchestrators for Glassbox.

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
    READINESS_GATING_CONFIDENCE,
    _mk_session,
    check_headers,
    check_cookies,
    crawl_same_origin,
    crawl_depth2_param_urls,
    check_ssti,
    check_host_header,
    check_cache_deception,
    check_path_traversal,
    check_rate_limit_posture,
    check_jwt_active,
    check_crlf_injection,
    check_csrf_posture,
    check_subdomain_takeover,
    check_graphql_deep,
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
    check_jwt_weakness,
    check_sri,
    check_file_upload,
    check_privacy_exposure,
    check_caching_sensitive_data,
    owasp_category_for,
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


def _score_report(findings):
    """The single scoring implementation shared by all four orchestrators
    (`run_scan`/`run_advanced_scan`/`run_media_scan`/`run_api_scan`) - HARD-04,
    D-09. Prior to this extraction the same block was copy-pasted four times,
    identical except for the local variable name holding the findings list.

    Folds in `findings_sorted` too (one value more than
    `.planning/codebase/CONCERNS.md`'s suggested 3-tuple return), because that
    sort line was ALSO duplicated verbatim at all four call sites immediately
    after the score/grade/severity_counts block (04-RESEARCH.md A1).

    Deliberately lets `SEVERITY_ORDER.index` raise a `ValueError` on a
    `Finding.severity` value it doesn't recognise, rather than degrading
    defensively - a malformed `Finding` is a programming error this suite
    should surface, not silently absorb.
    """
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
    return score, risk_grade, severity_counts, findings_sorted


def _compute_readiness(findings, locked_count=0, total_check_count=None):
    """v1.3 SCORE-03/04: a companion signal to `_score_report()` above, not a
    replacement - deliberately kept as its own function so `_score_report`'s
    battle-tested arithmetic and 4-tuple return (20+ existing tests, a
    source-parsing regression lock) stay completely untouched. This is the
    "extend the scoring formula to weight by confidence and coverage" work
    from SCORE-03, expressed as a verdict + supporting reasons rather than a
    second numeric score, so a user sees *why* readiness landed where it
    did (SCORE-04) instead of just another number next to the risk score.

    Never based on vulnerability count alone (explicit requirement): a
    single low-confidence finding doesn't block readiness, one credible
    critical does, and incomplete check coverage (locked/tier-gated checks)
    always caps the verdict at READY WITH WARNINGS even with zero findings -
    "nothing found" is not the same claim as "nothing to find" when whole
    check categories never ran.

    Returns (verdict, reasons, coverage_pct). `coverage_pct` is None when
    `total_check_count` isn't supplied (media/api scans have no locked-check
    concept - every check that can run, runs, so coverage is definitionally
    irrelevant there, not just unknown).
    """
    credible_critical = [f for f in findings if f.severity == "critical" and f.confidence in READINESS_GATING_CONFIDENCE]
    credible_high = [f for f in findings if f.severity == "high" and f.confidence in READINESS_GATING_CONFIDENCE]
    uncertain_serious = [
        f for f in findings
        if f.severity in ("critical", "high") and f.confidence not in READINESS_GATING_CONFIDENCE
    ]

    coverage_pct = None
    if total_check_count:
        coverage_pct = round(100 * (total_check_count - locked_count) / total_check_count)

    reasons = []
    if credible_critical:
        verdict = "NOT READY"
        reasons.append(
            f"{len(credible_critical)} critical finding(s) with credible evidence "
            f"({', '.join(sorted({f.title for f in credible_critical}))[:200]})"
        )
    elif credible_high:
        verdict = "READY WITH WARNINGS"
        reasons.append(f"{len(credible_high)} high-severity finding(s) with credible evidence")
    else:
        verdict = "READY"

    if uncertain_serious and verdict == "READY":
        verdict = "READY WITH WARNINGS"
    if uncertain_serious:
        reasons.append(
            f"{len(uncertain_serious)} critical/high finding(s) flagged but not yet confidently "
            "confirmed - worth a manual look before treating this as clean"
        )

    if coverage_pct is not None and coverage_pct < 100 and verdict == "READY":
        verdict = "READY WITH WARNINGS"
    if coverage_pct is not None and coverage_pct < 100:
        reasons.append(f"Only {coverage_pct}% of applicable checks ran ({locked_count} locked by tier/verification)")

    if not reasons:
        reasons.append("No credible critical/high findings, and every applicable check ran")

    return verdict, reasons, coverage_pct


def run_media_scan(base_url, download, max_files):
    session = _mk_session()
    data, findings = check_media(session, base_url, download, max_files)
    for f in findings:
        f.check_name = "media"

    score, risk_grade, severity_counts, findings_sorted = _score_report(findings)
    # No locked-check concept for media scans (route-level gating means every
    # check that can run, runs) - coverage_pct stays None, not a fabricated 100.
    readiness_verdict, readiness_reasons, coverage_pct = _compute_readiness(findings)

    return {
        "target": base_url,
        "hostname": urlparse(base_url).netloc,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "risk_grade": risk_grade,
        "severity_counts": severity_counts,
        "findings": _serialize_findings(findings_sorted),
        "media": data,
        "readiness_verdict": readiness_verdict,
        "readiness_reasons": readiness_reasons,
        "check_coverage_pct": coverage_pct,
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
    for f in findings:
        f.check_name = "schema"
    results["schema"] = data
    all_findings.extend(findings)

    data, findings = check_api_wordlist(base_url, session)
    for f in findings:
        f.check_name = "wordlist"
    results["wordlist"] = data
    all_findings.extend(findings)

    data, findings = check_api_js_discovery(session, base_url, home_html)
    for f in findings:
        f.check_name = "js_discovery"
    results["js_discovery"] = data
    all_findings.extend(findings)

    score, risk_grade, severity_counts, findings_sorted = _score_report(all_findings)
    readiness_verdict, readiness_reasons, coverage_pct = _compute_readiness(all_findings)

    return {
        "target": base_url,
        "hostname": urlparse(base_url).netloc,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "risk_grade": risk_grade,
        "severity_counts": severity_counts,
        "findings": _serialize_findings(findings_sorted),
        "results": results,
        "readiness_verdict": readiness_verdict,
        "readiness_reasons": readiness_reasons,
        "check_coverage_pct": coverage_pct,
    }


# No scheduler dispatch path by design: scheduler._fire() only branches on
# "base"/"media"/"api", and Asset stores no credentials for an unattended
# run, so this orchestrator's test coverage is direct-invocation only (D-04).
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
        for f in findings:
            f.check_name = "sqli_login"
        results["sqli_login"] = data
        all_findings.extend(findings)
    elif has_login_fields:
        locked.append("sqli_login")

    if has_bruteforce_fields and login_allowed and bruteforce_allowed:
        data, findings = check_bruteforce(session, advanced["login_url"], advanced["user_field"],
                                           advanced["pass_field"], advanced["bruteforce_username"],
                                           advanced["bruteforce_passwords"], advanced["fail_text"])
        for f in findings:
            f.check_name = "bruteforce"
        results["bruteforce"] = data
        all_findings.extend(findings)
    elif has_bruteforce_fields:
        locked.append("bruteforce")

    if advanced.get("sqli_union_url") and advanced.get("sqli_union_param") \
            and FEATURE_REQUIREMENTS["sqli_union"] <= tier and org_verified_for_domain:
        targets.append(advanced["sqli_union_url"])
        data, findings = check_sqli_union(session, advanced["sqli_union_url"], advanced["sqli_union_param"])
        for f in findings:
            f.check_name = "sqli_union"
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
        for f in findings:
            f.check_name = "xss_stored"
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
        for f in findings:
            f.check_name = "idor"
        results["idor"] = data
        all_findings.extend(findings)
    elif advanced.get("idor_url_template") and advanced.get("idor_ids") and \
            advanced.get("idor_cookie_a") and advanced.get("idor_cookie_b"):
        locked.append("idor")

    score, risk_grade, severity_counts, findings_sorted = _score_report(all_findings)
    hostname = urlparse(targets[0]).netloc if targets else "unspecified-target"
    # Coverage is scoped to check groups the user actually attempted (filled
    # in fields for) - a group nobody filled in was never "applicable" to
    # begin with, so it shouldn't count against readiness the way a
    # tier-locked-but-attempted one does.
    readiness_verdict, readiness_reasons, coverage_pct = _compute_readiness(
        all_findings, locked_count=len(locked), total_check_count=len(results) + len(locked),
    )

    return {
        "hostname": hostname,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "risk_grade": risk_grade,
        "severity_counts": severity_counts,
        "findings": _serialize_findings(findings_sorted),
        "results": results,
        "ran": list(results.keys()),
        "locked_checks": locked,
        "readiness_verdict": readiness_verdict,
        "readiness_reasons": readiness_reasons,
        "check_coverage_pct": coverage_pct,
    }


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def _top_severity(findings):
    """Most severe value present among `findings`, per SEVERITY_ORDER's
    ranking, or None if there are no findings - lets the live scan-progress
    feed show a severity badge as each check resolves ("2 findings, high"),
    not just at the final report."""
    if not findings:
        return None
    return min((f.severity for f in findings), key=SEVERITY_ORDER.index)


def _serialize_findings(findings_sorted):
    """`[asdict(f) for f in findings_sorted]` plus an `owasp_category` key per
    finding, computed from `owasp_category_for(f.category)` - kept as one
    shared helper (rather than repeating the annotation inline) since all
    four orchestrators below build their `findings` report key this way."""
    out = []
    for f in findings_sorted:
        d = asdict(f)
        d["owasp_category"] = owasp_category_for(f.category)
        out.append(d)
    return out


def _extract_detail(name, data):
    """Optional, best-effort enrichment for a completed check's live-feed
    detail line, beyond the pass/fail dot - only checks whose `data` shape
    is known-safe to introspect here get an entry; everything else stays
    None (the row still shows a complete label + status, just no extra
    line). Deliberately conservative: the jobs dict's checks return a mix
    of dicts and lists depending on the check, so guessing at an unlisted
    check's shape here risks an AttributeError mid-scan - the isinstance
    guard is load-bearing, not decorative."""
    if name == "tls" and isinstance(data, dict) and data.get("issuer"):
        return f"{data['issuer']} · {data.get('days_left', '?')}d left"
    return None


def run_scan(base_url, manual_test_url, tier, org_verified_for_domain, progress_cb=None):
    session = _mk_session()
    hostname = urlparse(base_url).netloc

    home_resp = session.get(base_url + "/", timeout=REQUEST_TIMEOUT)
    home_html = home_resp.text

    header_data, f1 = check_headers(home_resp)
    cookie_rows, f2 = check_cookies(home_resp)
    for f in f1:
        f.check_name = "headers"
    for f in f2:
        f.check_name = "cookies"

    # Only open_redirect (PAID) and xss_sqli (ORG_VERIFIED) consume the crawl
    # output - no FREE-tier check does, so skip the crawl entirely rather
    # than doing paid-tier work for a free-tier caller.
    if tier == Tier.FREE:
        param_urls, forms = [], []
    else:
        param_urls, forms = crawl_same_origin(base_url, home_html, session=session)
        # Phase 17 / DEPTH-01 approved extension: one capped hop deeper
        # (same-origin, robots-honored, MAX_CRAWL_PAGES pages) to find
        # param URLs interior pages hide. Runs only for org-verified domains -
        # the extra fetching is justified exactly where the intrusive probes
        # that consume its output are allowed anyway - and merges BEHIND the
        # hop-1 results so the limit=10 probe list (and thus per-scan probe
        # request budget) stays what it was.
        if org_verified_for_domain:
            param_urls = param_urls + [u for u in crawl_depth2_param_urls(session, base_url, home_html)
                                       if u not in param_urls]
            param_urls = param_urls[:10]
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
        "jwt": lambda: check_jwt_weakness(session, base_url, home_html),
        "sri": lambda: check_sri(base_url, home_html),
        "file_upload": lambda: check_file_upload(base_url, home_html),
        "privacy_exposure": lambda: check_privacy_exposure(base_url, home_html),
        "caching_sensitive": lambda: check_caching_sensitive_data(base_url, session),
        # Phase 20 (INTR-01..10)
        "ssti": lambda: check_ssti(param_urls, session),
        "host_header": lambda: check_host_header(base_url, session),
        "cache_deception": lambda: check_cache_deception(base_url, session),
        "crlf": lambda: check_crlf_injection(param_urls, session),
        "csrf_posture": lambda: check_csrf_posture(forms),
        "subdomain_takeover": lambda: check_subdomain_takeover(hostname),
        "path_traversal": lambda: check_path_traversal(param_urls, session),
        "rate_limit": lambda: check_rate_limit_posture(base_url, session),
        "jwt_active": lambda: check_jwt_active(session, base_url, home_html),
        "graphql_deep": lambda: check_graphql_deep(base_url, session),
    }

    # Captured before `jobs` is filtered down to `allowed` below - the base
    # denominator for SCORE-01's coverage_pct is every check that could
    # apply to a base scan (this dict's checks + headers/cookies/open_ports,
    # which run outside the jobs dict - see total_check_count at report-
    # build time), not just the ones this particular tier unlocked.
    total_job_count = len(jobs)
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
        progress_cb("headers", "completed", done, total, detail=f"grade {header_data['grade']}",
                     finding_count=len(f1), top_severity=_top_severity(f1))
    done += 1
    if progress_cb:
        progress_cb("cookies", "completed", done, total,
                     finding_count=len(f2), top_severity=_top_severity(f2))

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
                phase, detail = "completed", _extract_detail(name, data)
            except Exception as e:
                data, findings = {"error": str(e)}, []
                phase, detail = "failed", str(e)[:255]
            for f in findings:
                f.check_name = name
            results[name] = data
            all_findings.extend(findings)
            done += 1
            if progress_cb:
                progress_cb(name, phase, done, total, detail=detail,
                            finding_count=len(findings), top_severity=_top_severity(findings))

    if FEATURE_REQUIREMENTS["open_ports"] <= tier:
        ports, resolved_ip, f_ports = check_open_ports(hostname)
        for f in f_ports:
            f.check_name = "open_ports"
        results["open_ports"] = ports
        all_findings.extend(f_ports)
        open_ports_phase = "completed"
        open_ports_detail = f"{len(ports)} open" + (f" · {resolved_ip}" if resolved_ip else "")
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
        open_ports_detail = None
    done += 1
    if progress_cb:
        progress_cb("open_ports", open_ports_phase, done, total, detail=open_ports_detail,
                     finding_count=len(f_ports) if open_ports_phase else None,
                     top_severity=_top_severity(f_ports) if open_ports_phase else None)

    score, risk_grade, severity_counts, findings_sorted = _score_report(all_findings)
    # +3: headers/cookies (always run, never locked) + open_ports (its own
    # gate, separate from the jobs-dict allowed_checks() call above).
    readiness_verdict, readiness_reasons, coverage_pct = _compute_readiness(
        all_findings, locked_count=len(locked), total_check_count=total_job_count + 3,
    )

    return {
        "target": base_url,
        "resolved_ip": resolved_ip,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "risk_grade": risk_grade,
        "severity_counts": severity_counts,
        "findings": _serialize_findings(findings_sorted),
        "readiness_verdict": readiness_verdict,
        "readiness_reasons": readiness_reasons,
        "check_coverage_pct": coverage_pct,
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
        "jwt": results.get("jwt", {"locked": True}),
        "sri": results.get("sri", {"locked": True}),
        "file_upload": results.get("file_upload", {"locked": True}),
        "privacy_exposure": results.get("privacy_exposure", {"locked": True}),
        "caching_sensitive": results.get("caching_sensitive", {"locked": True}),
        "ssti": results.get("ssti", {"locked": True}),
        "host_header": results.get("host_header", {"locked": True}),
        "cache_deception": results.get("cache_deception", {"locked": True}),
        "crlf": results.get("crlf", {"locked": True}),
        "csrf_posture": results.get("csrf_posture", {"locked": True}),
        "subdomain_takeover": results.get("subdomain_takeover", {"locked": True}),
        "path_traversal": results.get("path_traversal", {"locked": True}),
        "rate_limit": results.get("rate_limit", {"locked": True}),
        "jwt_active": results.get("jwt_active", {"locked": True}),
        "graphql_deep": results.get("graphql_deep", {"locked": True}),
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


def read_report_file(filename):
    """Reads and parses an on-disk report JSON file from REPORTS_DIR given
    its stored filename - `save_report()`'s symmetric counterpart, and the
    one shared reader for what used to be three independent inline
    "open a REPORTS_DIR-joined path" blocks in `scan_routes.py`,
    `api_routes.py` and `asset_routes.py`.

    This exists because those three call sites each independently joined a
    DB-stored filename (`Report.json_path`) onto `REPORTS_DIR` with no
    containment check. Path traversal is NOT reachable today:
    `save_report()` above is the only writer of `Report.json_path` in this
    codebase, and it always builds the filename server-side from a hostname
    and a timestamp - never from a request parameter - so no
    request-controlled value reaches the join. This function is therefore
    defence in depth against a fourth caller with different provenance,
    not a fix for a live vulnerability; do not describe it as one.

    Containment is checked by resolving BOTH sides to real paths before
    comparing - REPORTS_DIR itself is derived from `__file__`
    (`checks.APP_DIR`) and could sit behind a symlink on some hosts, so
    resolving only the candidate side would reject every legitimate read
    the moment that happened. Returns the parsed JSON object, or `None` on
    any of: containment failure, a missing file, an unreadable file,
    invalid JSON, or a filename value that makes path resolution itself
    raise (e.g. an embedded null byte) - the same single failure signal
    every caller here already treats identically to "file not found",
    preserving each call site's own pre-existing not-available branch.
    """
    try:
        reports_root = os.path.realpath(REPORTS_DIR)
        candidate = os.path.realpath(os.path.join(REPORTS_DIR, filename))
        contained = os.path.commonpath([reports_root, candidate]) == reports_root
    except (OSError, ValueError, TypeError):
        return None

    if not contained:
        return None

    try:
        with open(candidate, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None
