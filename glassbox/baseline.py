"""Baseline-diff primitives (detection roadmap #2).

Many checks are only correct when they judge a probe response as a *diff*
against a known-good baseline rather than in isolation - the cache-deception
false positive and check_idor's soft-200 guard were both this lesson learned
the hard way, each with its own ad-hoc copy of "is this response
meaningfully different from the baseline". This module is the one shared
definition every check can call, across the four axes that actually carry
signal:

  - status   : the HTTP status code changed
  - length   : the body length changed beyond a tolerance (small deltas are
               noise - timestamps, CSRF tokens, nonces)
  - timing   : the response took meaningfully longer (time-based blind
               injection)
  - content  : a marker string is reflected in the body (reflected XSS,
               canary-echo confirmation)

Framework-agnostic on purpose (no flask, no requests import): it operates on
any object exposing ``.status_code`` and ``.text``, so unit tests can pass a
tiny fake and checks pass a real ``requests.Response``. checks.py stays the
only place that does network I/O; this just compares what came back.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Defaults chosen to match check_idor's long-standing tolerance, so folding
# that check onto this module is behaviour-preserving: a body is "the same
# length" if within 5% or 32 bytes, whichever is larger. Small dynamic
# differences (a timestamp, a per-request token) stay below this.
DEFAULT_LENGTH_TOLERANCE_PCT = 0.05
DEFAULT_LENGTH_TOLERANCE_ABS = 32

# A time-based payload must add at least this much wall-clock delay over the
# baseline before it counts - absorbs ordinary network jitter. check_sqli_*
# used `baseline + DELAY - 1.5`; expressed here as "extra seconds over
# baseline", the caller passes DELAY - 1.5.
DEFAULT_MIN_EXTRA_SECONDS = 2.5


@dataclass(frozen=True)
class Fingerprint:
    """The comparable shape of one response. `elapsed` is wall-clock seconds
    if the caller timed the request, else None (timing axis unavailable)."""
    status: int
    length: int
    elapsed: float | None = None

    @classmethod
    def of(cls, resp, elapsed: float | None = None) -> Fingerprint:
        return cls(status=resp.status_code, length=len(resp.text or ""), elapsed=elapsed)


@dataclass
class Diff:
    """What changed between a baseline and a candidate response. `reasons`
    is human-readable, for finding detail text."""
    status_changed: bool
    length_delta: int
    length_significant: bool
    slower_by: float | None
    timing_significant: bool
    reasons: list[str] = field(default_factory=list)

    @property
    def distinguishable(self) -> bool:
        """The core predicate check_idor-style checks want: is this response
        provably different from the baseline on status or body size? Timing
        is deliberately NOT folded in here - a slow response with identical
        status+body is a timing finding, not a content-exposure one, and the
        caller decides which it's looking for."""
        return self.status_changed or self.length_significant


def _length_is_significant(baseline_len: int, candidate_len: int,
                           pct: float, abs_floor: int) -> bool:
    tolerance = max(abs_floor, int(baseline_len * pct))
    return abs(candidate_len - baseline_len) > tolerance


def diff(baseline: Fingerprint | None, candidate: Fingerprint, *,
         length_tolerance_pct: float = DEFAULT_LENGTH_TOLERANCE_PCT,
         length_tolerance_abs: int = DEFAULT_LENGTH_TOLERANCE_ABS,
         min_extra_seconds: float = DEFAULT_MIN_EXTRA_SECONDS) -> Diff:
    """Compare two fingerprints across all available axes. A None baseline
    is treated as "no baseline to match", i.e. every axis reads as changed -
    fail-open toward *flagging*, matching check_idor's convention that an
    un-fetchable baseline makes a live 200 look distinguishable rather than
    silently safe."""
    if baseline is None:
        return Diff(status_changed=True, length_delta=candidate.length,
                    length_significant=True, slower_by=None, timing_significant=False,
                    reasons=["no baseline available to compare against"])

    reasons: list[str] = []
    status_changed = candidate.status != baseline.status
    if status_changed:
        reasons.append(f"status {baseline.status} → {candidate.status}")

    length_delta = candidate.length - baseline.length
    length_significant = _length_is_significant(
        baseline.length, candidate.length, length_tolerance_pct, length_tolerance_abs)
    if length_significant:
        reasons.append(f"body length {baseline.length} → {candidate.length} "
                       f"({length_delta:+d} bytes)")

    slower_by = None
    timing_significant = False
    if baseline.elapsed is not None and candidate.elapsed is not None:
        slower_by = candidate.elapsed - baseline.elapsed
        timing_significant = slower_by >= min_extra_seconds
        if timing_significant:
            reasons.append(f"response {slower_by:.1f}s slower than a "
                           f"{baseline.elapsed:.1f}s baseline")

    return Diff(status_changed=status_changed, length_delta=length_delta,
                length_significant=length_significant, slower_by=slower_by,
                timing_significant=timing_significant, reasons=reasons)


def is_distinguishable(baseline: Fingerprint | None, candidate: Fingerprint, **kw) -> bool:
    """True if `candidate` is provably different from `baseline` on status or
    body size. The shared replacement for every hand-rolled
    "not _looks_like_baseline" check."""
    return diff(baseline, candidate, **kw).distinguishable


def is_significantly_slower(baseline: Fingerprint | None, candidate: Fingerprint, *,
                            min_extra_seconds: float = DEFAULT_MIN_EXTRA_SECONDS) -> bool:
    """True if `candidate` took at least `min_extra_seconds` longer than
    `baseline` - the time-based blind-injection signal. False if either side
    wasn't timed."""
    d = diff(baseline, candidate, min_extra_seconds=min_extra_seconds)
    return d.timing_significant


def reflects(resp, marker: str) -> bool:
    """True if `marker` appears verbatim in the response body - reflected-XSS
    / canary-echo confirmation. A thin, named wrapper so the intent reads at
    the call site and the empty-marker guard lives in one place."""
    if not marker:
        return False
    return marker in (resp.text or "")
