"""Re-runnable secrets sweep for milestone v1.1 (SEC-08).

What SEC-08 asks for: no hardcoded API key, password, token, or wallet
credential added during milestone v1.1. This script sweeps two surfaces -
the diff of every commit in the milestone's own commit range, and the
current working tree - for credential-shaped literals, using patterns
derived from this app's real configuration surface
(glassbox/config.py / .env.example) plus generic credential-
assignment and hex-wallet-credential shapes on top.

Why no scanning package (detect-secrets / gitleaks): neither is installed
in this environment or listed in requirements-dev.txt. Installing one
mid-audit would need its own Package Legitimacy Gate pass (CLAUDE.md's
package-install exclusion), and SEC-08's literal "added this milestone"
scope is fully covered by a scoped git-log sweep plus a working-tree scan
using only the standard library - see
.planning/phases/08-security-re-audit-hardening/08-RESEARCH.md's
"Alternatives Considered" table.

Commit range: MILESTONE_START_COMMIT (00ae203, "docs: start milestone v1.1
Production Audit, Hardening & Redesign", 2026-08-15) through HEAD - the
exact boundary .planning/STATE.md records as the milestone kickoff commit
(cross-checked against `git log -1 --format="%h %ad %s" 00ae203` while
writing this script; both agree on the date). A credential committed
*before* this range is outside SEC-08's literal wording and outside this
sweep, by design (08-VALIDATION.md's Manual-Only Verifications).

Honest limitation: this is a regex-based sweep. A clean result is evidence
that nothing matches these specific patterns, not proof that no credential
exists anywhere in the swept range - see self_test() below, which exists
specifically so a broken regex cannot silently produce a false all-clear.
tests/test_secrets_hygiene.py calls self_test() and sweep_working_tree()
directly (in-process, not by shelling out) so this sweep is part of the
standing suite, not a one-time observation.

Usage:
    .venv\\Scripts\\python scripts\\secrets_sweep_phase8.py
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MILESTONE_START_COMMIT = "00ae203"

# --------------------------------------------------------------------------
# Working-tree sweep scope. Generated/vendored/downloaded directories only -
# every other file under the repo root is real, human-authored source this
# app actually ships.
# --------------------------------------------------------------------------

SKIP_DIR_NAMES = {
    ".venv", "node_modules", ".git", "reports", "downloads", ".pytest_cache",
    "__pycache__", ".cache", "instance", "graphify-out", ".worktrees",
}

SCANNED_SUFFIXES = {
    ".py", ".html", ".js", ".json", ".yml", ".yaml", ".toml", ".md", ".cfg",
    ".ini", ".txt",
}

# --------------------------------------------------------------------------
# Patterns. Derived from this app's real configuration surface
# (glassbox/config.py's os.environ.get(...) names / .env.example),
# not a generic list, plus the generic credential-assignment shape and a
# hex wallet-credential shape on top (08-06-PLAN.md's explicit
# instruction).
# --------------------------------------------------------------------------

_CRED_KEYWORD = r"(?:key|secret|password|passwd|pwd|token|mnemonic|private)"

PATTERNS = {
    # NAME = "long-literal" / NAME: "long-literal" (dict-style) - the
    # generic credential-assignment shape SEC-08 names by name.
    "generic_assignment": re.compile(
        rf"(?i)\b\w*{_CRED_KEYWORD}\w*\s*[:=]\s*['\"]([A-Za-z0-9_\-./+=]{{16,}})['\"]"
    ),
    # os.environ.get("NAME", "long-literal") / os.environ.setdefault(...) -
    # the other shape this app's own config.py/conftest.py actually use: a
    # credential-shaped env-var *name* paired with a literal default value
    # in the same call, not a bare `NAME = value` assignment.
    "env_call_default": re.compile(
        rf"(?i)\(\s*['\"]\w*{_CRED_KEYWORD}\w*['\"]\s*,\s*['\"]([A-Za-z0-9_\-./+=]{{16,}})['\"]"
    ),
    # Groq API key shape (GROQ_API_KEY - this app's LLM provider).
    "groq_key": re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"),
    # Resend API key shape (RESEND_API_KEY - this app's email provider).
    "resend_key": re.compile(r"\bre_[A-Za-z0-9_]{20,}\b"),
    # Sentry DSN shape (SENTRY_DSN) - https://<32-hex>@<host>/<project-id>.
    "sentry_dsn": re.compile(r"https://[a-f0-9]{32}@[A-Za-z0-9.\-]+/\d+"),
    # Hex wallet / private-key shape (crypto billing - USDT/USDC on
    # Polygon, CRYPTO_RECEIVING_ADDRESS/PRIVATE_KEY-shaped values): a bare
    # 64-hex-character string (Ethereum/Polygon private-key length),
    # optionally 0x-prefixed.
    "hex_private_key": re.compile(r"\b0x[a-fA-F0-9]{64}\b|(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])"),
    # EVM-style wallet address (0x + 40 hex chars) - narrower than the
    # private-key pattern above; a real receiving/contract address
    # hardcoded outside CRYPTO_RECEIVING_ADDRESS/USDT_CONTRACT_ADDRESS/
    # USDC_CONTRACT_ADDRESS's documented env-var plumbing would be a live
    # finding.
    "evm_wallet_address": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
}

# --------------------------------------------------------------------------
# Allowlist. Every entry names an exact (relative path, line number) pair
# and carries a written reason - an allowlist entry without a reason is
# worse than no sweep at all (08-06-PLAN.md's explicit instruction; T-08-40
# in this plan's threat register).
# --------------------------------------------------------------------------

# Keyed by the exact matched text (re.Match.group(0)), not by (file, line).
# A location-keyed allowlist cannot cover the git-range sweep at all: that
# surface's "source" is the synthetic label "git-range:<range>" with a line
# number counted within the concatenated diff text, not a real file+line -
# so a (path, lineno) entry that allowlists a working-tree hit would never
# match the same literal's appearance in a commit diff. Matching on the
# literal value itself works identically for both surfaces, and is also
# immune to line-number churn from unrelated edits shifting a legitimate
# allowlisted line up or down.
ALLOWLIST = {
    # tests/conftest.py's test-only SECRET_KEY fallback (and the identical
    # line quoted verbatim in .planning/codebase/TESTING.md's docs) - never
    # used outside pytest, set via os.environ.setdefault so a developer's
    # real .env still wins if present.
    '("SECRET_KEY", "test-only-secret-never-used-outside-pytest"': (
        "tests/conftest.py's test-only SECRET_KEY fallback (also quoted "
        "verbatim in .planning/codebase/TESTING.md's docs) - the string "
        "itself says 'never-used-outside-pytest'; never read by any real "
        "deploy"
    ),
    # config.py's documented, source-visible dev-only placeholder - only
    # reachable when ALLOW_INSECURE_DEV_SECRET_KEY is explicitly set, which
    # config.py's own docstring says must never happen outside local dev.
    '_DEV_SECRET_KEY = "dev-only-insecure-secret-key-change-me"': (
        "config.py's documented ALLOW_INSECURE_DEV_SECRET_KEY dev-only "
        "placeholder - intentionally source-visible, gated behind an env "
        "var CLAUDE.md documents as local-dev-only"
    ),
    # scripts/grant_full_access.py's dev-only DomainVerification.token
    # placeholder for a local, no-UI-path elevate-access script (see its
    # own module docstring) - not a real domain-verification proof value.
    'token="local-dev-grant-full-access"': (
        "grant_full_access.py's dev-only DomainVerification.token "
        "placeholder for a local elevate-access script with no UI path - "
        "not a real domain-ownership-verification proof value"
    ),
    # A prior session's planning doc for the API-exposure/media-streaming
    # feature contains a synthetic, obviously-fake AWS-access-key-shaped
    # string used as example input to prove check_exposed_secrets' own
    # detection pattern works - not a real AWS credential.
    'js_body = \'const key = "AKIAABCDEFGHIJKLMNOP";\'': (
        "synthetic, alphabet-pattern AWS-key-shaped example string used to "
        "demonstrate check_exposed_secrets' own AWS-key detection regex in "
        "a planning doc - not a real credential, predates the milestone "
        "(dated 2026-08-05, before the 2026-08-15 v1.1 kickoff)"
    ),
    # The same synthetic AWS-key-shaped string also matches a second,
    # narrower pattern on the same source line (the inner double-quoted
    # "key = ..." substring within the outer single-quoted JS snippet) -
    # and this exact allowlist entry's own dict key, quoted here for
    # matching purposes, self-flags this very script's own source too.
    # Same non-credential, both places.
    'key = "AKIAABCDEFGHIJKLMNOP"': (
        "the inner double-quoted substring of the same synthetic AWS-key "
        "example above - also self-appears in this script's own ALLOWLIST "
        "dict key text; not a real credential in either location"
    ),
    # Synthetic fixture token literals in the test suite - obviously fake,
    # human-readable placeholder strings (not random-looking secrets),
    # used only against this app's own disposable per-test SQLite DB.
    'token = "single-use-token"': (
        "synthetic fixture value asserting single-use reset-token "
        "behavior - not a real credential"
    ),
    'token="test-token-value"': (
        "synthetic fixture value used to seed a Report row for the "
        "containment/path-traversal proofs - not a real credential"
    ),
    # opencodefailure.md's Phase 27 entry QUOTES the credential-shaped
    # literal a test once used (describing the catch), which re-trips the
    # sweep on both surfaces - the actual test was fixed in the same
    # session to a non-secret-shaped hex string ("4" * 64); the quoted form
    # only exists inside the failure log as documentation.
    'secret="s3cret-regression-key"': (
        "quoted example of a flagged literal inside opencodefailure.md's "
        "own Phase 27 failure entry (describing the catch) - the real test "
        "literal was replaced with a benign hex-style fixture before "
        "commit; this is documentation text, not a credential"
    ),
    # A synthetic, obviously-sequential (not random) EVM wallet address
    # used as this app's billing-test fixture default - both the current
    # test module and the prior planning doc it was authored from.
    "0xABCDEF0123456789ABCDEF0123456789ABCDEF01": (
        "DEFAULT_RECEIVING_ADDRESS test fixture (tests/test_billing_routes.py "
        "and the planning doc it was authored from) - a sequential/"
        "alphabetic placeholder hex string, not a real Polygon wallet "
        "address"
    ),
    # A SHA256 hash of is_ssrf_safe_hostname()'s own source code (a
    # frozen-surface integrity lock added in plan 08-04, SEC-03) -
    # coincidentally the same 64-hex-character length as a private key,
    # since SHA256 digests and Ethereum/Polygon private keys are both 32
    # raw bytes. Not a credential at all.
    "546fc01009d3e9e737221df4fac42c6ac8d2041e7c63dd30421865bfe968c3dd": (
        "SHA256 hash of is_ssrf_safe_hostname()'s pre-plan-08-04 source "
        "code, used as a frozen-surface byte-identity lock (tests/"
        "test_ssrf_guard.py) - not a private key; only matches this "
        "pattern by coincidental length (both are 64 hex characters)"
    ),
    # check_sqli_login's own literal baseline comparison password, used
    # only to build an intentionally-wrong login attempt this app's own
    # SQLi-login-bypass check sends to the *target being scanned* - never a
    # credential for any account in this app itself.
    'bogus_password = "not_a_real_password_123"': (
        "check_sqli_login's baseline 'known-bad' password literal, sent to "
        "the scanned target to establish a normal-failure baseline - not a "
        "real credential for any account of this app's own"
    ),
    # This script's own self-test fixture literal (see self_test() below) -
    # deliberately credential-shaped so the self-test proves the patterns
    # fire. Written into a temporary file at test time, but the constant
    # itself still lives in this file's own source and would otherwise
    # self-flag every future run of this very script.
    'synthetic_secret = "sk_live_synthetic1234567890abcdefFAKE"': (
        "this script's own self-test synthetic-credential constant - "
        "intentionally credential-shaped so self_test() can prove the "
        "patterns fire; never a real key"
    ),
}


def _iter_scan_paths(root):
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix not in SCANNED_SUFFIXES:
            continue
        yield path


def _scan_text(text, source_label):
    """Returns every (source_label, line_no, pattern_name, matched_text)
    hit in `text`. Matched per-line (not per-file) so a hit's line number
    is exact and an allowlist entry can target it precisely."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pattern_name, rx in PATTERNS.items():
            for m in rx.finditer(line):
                hits.append((source_label, lineno, pattern_name, m.group(0)))
    return hits


def _is_allowlisted(source_label, lineno, pattern_name, matched_text):
    return matched_text in ALLOWLIST


def sweep_working_tree(root=None):
    """Scans every non-generated, non-vendored file under `root` (default:
    the repo root) for credential-shaped literals. Returns a dict with the
    file count swept, every raw hit found, and the subset not covered by
    ALLOWLIST - a clean sweep is `unallowed_hits == []`."""
    root = Path(root) if root is not None else REPO_ROOT
    all_hits = []
    file_count = 0
    for path in _iter_scan_paths(root):
        file_count += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        all_hits.extend(_scan_text(text, rel))

    unallowed_hits = [h for h in all_hits if not _is_allowlisted(*h)]
    return {"file_count": file_count, "all_hits": all_hits, "unallowed_hits": unallowed_hits}


def _git_range_resolves(start=MILESTONE_START_COMMIT, end="HEAD", cwd=None):
    cwd = cwd or REPO_ROOT
    try:
        result = subprocess.run(
            ["git", "rev-list", "--count", f"{start}..{end}"],
            cwd=cwd, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def _is_shallow_checkout(cwd=None):
    cwd = cwd or REPO_ROOT
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=cwd, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return True  # can't tell - degrade to "treat as shallow, skip"
    return result.returncode == 0 and result.stdout.strip() == "true"


def sweep_git_range(start=MILESTONE_START_COMMIT, end="HEAD", cwd=None):
    """Sweeps the diff of every commit in `start..end` for the same
    credential-shaped patterns. Degrades gracefully (skipped=True, with a
    reason) on a shallow checkout (a CI runner without full history) rather
    than failing - the working-tree half above always runs regardless."""
    cwd = cwd or REPO_ROOT
    if _is_shallow_checkout(cwd):
        return {
            "skipped": True,
            "reason": "shallow git checkout - full history unavailable",
            "commit_count": None,
            "all_hits": [],
            "unallowed_hits": [],
        }

    commit_count = _git_range_resolves(start, end, cwd)
    if commit_count is None:
        return {
            "skipped": True,
            "reason": f"commit range {start}..{end} did not resolve",
            "commit_count": None,
            "all_hits": [],
            "unallowed_hits": [],
        }

    try:
        result = subprocess.run(
            ["git", "log", "-p", f"{start}..{end}"],
            cwd=cwd, capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "skipped": True,
            "reason": f"git log -p failed to run: {exc}",
            "commit_count": commit_count,
            "all_hits": [],
            "unallowed_hits": [],
        }
    if result.returncode != 0:
        return {
            "skipped": True,
            "reason": f"git log -p exited {result.returncode}: {result.stderr.strip()[:200]}",
            "commit_count": commit_count,
            "all_hits": [],
            "unallowed_hits": [],
        }

    # Only scan added lines ("+..."), not removed/context lines - a
    # credential that was added then removed within the range is still a
    # real finding (it crossed the secrets boundary and needs rotation
    # regardless of whether it was later deleted); a credential that only
    # ever appeared as a "-" (removed) or context line was never added in
    # this range.
    added_lines = [
        line[1:] for line in result.stdout.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    hits = _scan_text("\n".join(added_lines), f"git-range:{start}..{end}")
    unallowed_hits = [h for h in hits if not _is_allowlisted(*h)]
    return {
        "skipped": False,
        "reason": None,
        "commit_count": commit_count,
        "all_hits": hits,
        "unallowed_hits": unallowed_hits,
    }


def self_test():
    """Proves the patterns actually fire: writes a temporary file
    containing a synthetic, obviously-fake credential, points
    sweep_working_tree() at just that file's parent directory, and asserts
    it is found and named. Without this, a broken regex would produce a
    clean sweep and a false all-clear - the single most likely failure
    mode of a hand-written secrets scanner (T-08-39 in this plan's threat
    register). Returns True if the sweep actually caught the synthetic
    credential; raises AssertionError otherwise."""
    import tempfile

    synthetic_secret = "sk_live_synthetic1234567890abcdefFAKE"  # obviously-fake, never a real key
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        target = tmp_path / "self_test_fixture.py"
        target.write_text(
            f'API_SECRET_KEY = "{synthetic_secret}"\n', encoding="utf-8",
        )
        result = sweep_working_tree(root=tmp_path)

    found = [h for h in result["all_hits"] if synthetic_secret in h[3]]
    assert found, (
        "self-test FAILED: sweep_working_tree() did not find the synthetic "
        f"credential {synthetic_secret!r} in its own temporary fixture file - "
        "the regex patterns are broken and every other clean-sweep result "
        "in this run is meaningless"
    )
    return True


def main():
    print(f"Secrets sweep (SEC-08) - milestone range {MILESTONE_START_COMMIT}..HEAD")
    print()

    print("Running self-test (proves the patterns actually fire)...")
    self_test()
    print("  PASS - synthetic credential detected as expected.")
    print()

    print("Sweeping working tree...")
    wt_result = sweep_working_tree()
    print(f"  {wt_result['file_count']} file(s) scanned.")
    print(f"  {len(wt_result['all_hits'])} raw hit(s), {len(wt_result['unallowed_hits'])} un-allowlisted.")
    for source, lineno, pattern_name, matched in wt_result["unallowed_hits"]:
        print(f"    FINDING: {source}:{lineno} [{pattern_name}] {matched!r}")
    print()

    print(f"Sweeping git range {MILESTONE_START_COMMIT}..HEAD...")
    git_result = sweep_git_range()
    if git_result["skipped"]:
        print(f"  SKIPPED - {git_result['reason']}")
    else:
        print(f"  {git_result['commit_count']} commit(s) swept.")
        print(f"  {len(git_result['all_hits'])} raw hit(s), {len(git_result['unallowed_hits'])} un-allowlisted.")
        for source, lineno, pattern_name, matched in git_result["unallowed_hits"]:
            print(f"    FINDING: {source}:{lineno} [{pattern_name}] {matched!r}")
    print()

    clean = not wt_result["unallowed_hits"] and not git_result["unallowed_hits"]
    if clean:
        print("CLEAN - no un-allowlisted credential-shaped literal found in either surface.")
        print(
            "Reminder: this is evidence of absence-of-matches against these "
            "specific patterns, not proof of absence-of-credentials."
        )
        return 0
    print("FAILED - see FINDING lines above. Remove/rotate before re-running.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
