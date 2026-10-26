"""glassbox.baseline - the shared baseline-diff primitives (roadmap #2)."""
from glassbox.baseline import (
    DEFAULT_LENGTH_TOLERANCE_ABS,
    Diff,
    Fingerprint,
    diff,
    is_distinguishable,
    is_significantly_slower,
    reflects,
)


class _Resp:
    def __init__(self, status_code=200, text="", ):
        self.status_code = status_code
        self.text = text


def _fp(status=200, length=100, elapsed=None):
    return Fingerprint(status=status, length=length, elapsed=elapsed)


# --------------------------------------------------------------------------
# Fingerprint
# --------------------------------------------------------------------------


def test_fingerprint_of_reads_status_and_length():
    fp = Fingerprint.of(_Resp(200, "hello"))
    assert fp.status == 200
    assert fp.length == 5
    assert fp.elapsed is None


def test_fingerprint_of_handles_none_body():
    assert Fingerprint.of(_Resp(204, None)).length == 0


# --------------------------------------------------------------------------
# status / length diff
# --------------------------------------------------------------------------


def test_identical_responses_are_not_distinguishable():
    base = _fp(200, 1000)
    assert not is_distinguishable(base, _fp(200, 1000))


def test_status_change_is_distinguishable():
    assert is_distinguishable(_fp(200, 1000), _fp(403, 1000))


def test_small_length_delta_is_within_tolerance():
    # 5% of 1000 = 50; a 40-byte delta (timestamp, token) is noise.
    assert not is_distinguishable(_fp(200, 1000), _fp(200, 1040))


def test_large_length_delta_is_significant():
    assert is_distinguishable(_fp(200, 1000), _fp(200, 2000))


def test_abs_floor_applies_on_tiny_bodies():
    # 5% of 10 = 0, so the 32-byte absolute floor governs: a 20-byte delta
    # on a 10-byte baseline is still "the same".
    assert DEFAULT_LENGTH_TOLERANCE_ABS == 32
    assert not is_distinguishable(_fp(200, 10), _fp(200, 30))
    assert is_distinguishable(_fp(200, 10), _fp(200, 100))


def test_none_baseline_reads_as_distinguishable():
    """Fail toward flagging: an un-fetchable baseline must not silently make
    a live 200 look safe (check_idor's original convention)."""
    assert is_distinguishable(None, _fp(200, 500))


def test_diff_reasons_are_human_readable():
    d = diff(_fp(200, 1000), _fp(500, 3000))
    assert d.status_changed and d.length_significant
    joined = " ".join(d.reasons)
    assert "200" in joined and "500" in joined
    assert "1000" in joined and "3000" in joined


# --------------------------------------------------------------------------
# timing axis
# --------------------------------------------------------------------------


def test_timing_not_significant_when_untimed():
    assert not is_significantly_slower(_fp(elapsed=None), _fp(elapsed=5.0))
    assert not is_significantly_slower(_fp(elapsed=1.0), _fp(elapsed=None))


def test_timing_significant_past_threshold():
    # 0.3s baseline, 4.0s candidate, threshold 2.5 -> 3.7s extra, significant.
    assert is_significantly_slower(_fp(elapsed=0.3), _fp(elapsed=4.0), min_extra_seconds=2.5)


def test_timing_jitter_below_threshold_is_not_significant():
    assert not is_significantly_slower(_fp(elapsed=0.3), _fp(elapsed=1.5), min_extra_seconds=2.5)


def test_timing_does_not_make_a_response_distinguishable_on_its_own():
    """A slow response with identical status+body is a TIMING finding, not a
    content-exposure one - .distinguishable must stay False so an IDOR-style
    check doesn't mistake latency for a leak."""
    d = diff(_fp(200, 1000, elapsed=0.2), _fp(200, 1000, elapsed=9.0), min_extra_seconds=2.5)
    assert d.timing_significant
    assert not d.distinguishable


# --------------------------------------------------------------------------
# content reflection
# --------------------------------------------------------------------------


def test_reflects_finds_marker():
    assert reflects(_Resp(200, "...<b>gbxss-canary-42</b>..."), "gbxss-canary-42")


def test_reflects_false_when_absent_or_empty_marker():
    assert not reflects(_Resp(200, "clean page"), "gbxss-canary-42")
    assert not reflects(_Resp(200, "anything"), "")


def test_diff_is_a_dataclass_with_expected_fields():
    d = diff(_fp(200, 100), _fp(200, 100))
    assert isinstance(d, Diff)
    assert d.length_delta == 0
    assert d.slower_by is None
