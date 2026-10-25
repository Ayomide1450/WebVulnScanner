"""Media-scan sophistication (2026-08-26 review, user-requested): document
(PDF/DOCX/XLSX/PPTX) and video (MP4/QuickTime) metadata extraction,
extending the same GPS/device-leak detection EXIF already does for images
to the other file types crawl_media discovers. All three extraction
helpers are pure functions tested directly with synthetic bytes built to
the real documented format (PDF /Info dict literal strings, OOXML
docProps/core.xml, QuickTime user-data atoms) - no fixture files needed.

No new third-party dependency: PDF uses regex on raw bytes, Office docs
use stdlib zipfile + xml.etree.ElementTree, MP4 uses a bounded byte scan
for known atom tags. See checks.py's own module comment above these
functions for why each approach was chosen over adding a library.
"""
import io
import struct
import zipfile

from glassbox.checks import (
    _extract_mp4_metadata,
    _extract_office_metadata,
    _extract_pdf_metadata,
    check_media,
)

# --------------------------------------------------------------------------
# _extract_pdf_metadata
# --------------------------------------------------------------------------

def _fake_pdf(info_dict_body):
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< " + info_dict_body + b" >>\n"
        b"endobj\n"
        b"trailer\n<< /Info 2 0 R >>\n%%EOF"
    )


def test_pdf_extracts_author_and_producer():
    data = _fake_pdf(b"/Author (Jane Smith) /Producer (Acrobat Distiller 20.0)")
    meta = _extract_pdf_metadata(data)
    assert meta == {"Author": "Jane Smith", "Producer": "Acrobat Distiller 20.0"}


def test_pdf_unescapes_parens_and_backslashes():
    data = _fake_pdf(rb"/Title (Report \(Q3\) v1.0 \\ final)")
    meta = _extract_pdf_metadata(data)
    assert meta["Title"] == "Report (Q3) v1.0 \\ final"


def test_pdf_no_info_dict_returns_empty():
    assert _extract_pdf_metadata(b"%PDF-1.4\nnothing interesting here\n%%EOF") == {}


def test_non_pdf_bytes_return_empty_not_a_crash():
    assert _extract_pdf_metadata(b"not a pdf at all, just some bytes \x00\x01\x02") == {}


def test_pdf_empty_field_value_is_dropped():
    data = _fake_pdf(b"/Author () /Producer (Real Producer)")
    meta = _extract_pdf_metadata(data)
    assert "Author" not in meta
    assert meta["Producer"] == "Real Producer"


# --------------------------------------------------------------------------
# _extract_office_metadata (DOCX/XLSX/PPTX share docProps/core.xml)
# --------------------------------------------------------------------------

CORE_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                    xmlns:dc="http://purl.org/dc/elements/1.1/"
                    xmlns:dcterms="http://purl.org/dc/terms/"
                    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:creator>{creator}</dc:creator>
  <cp:lastModifiedBy>{modifier}</cp:lastModifiedBy>
  <dc:title>{title}</dc:title>
</cp:coreProperties>"""


def _fake_docx(creator="Ada Lovelace", modifier="Charles Babbage", title="Quarterly Report"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("docProps/core.xml", CORE_XML_TEMPLATE.format(
            creator=creator, modifier=modifier, title=title,
        ))
    return buf.getvalue()


def test_docx_extracts_creator_and_last_modified_by():
    meta = _extract_office_metadata(_fake_docx())
    assert meta["Author"] == "Ada Lovelace"
    assert meta["LastModifiedBy"] == "Charles Babbage"
    assert meta["Title"] == "Quarterly Report"


def test_not_a_zip_returns_empty_not_a_crash():
    assert _extract_office_metadata(b"not a zip file at all") == {}


def test_zip_without_core_xml_returns_empty():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("some_other_file.txt", "hello")
    assert _extract_office_metadata(buf.getvalue()) == {}


def test_oversized_core_xml_is_skipped_not_parsed():
    """Bomb-guard: a docProps/core.xml far larger than any real document
    would ever produce is skipped outright rather than parsed."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        huge = "<cp:coreProperties xmlns:cp='x'>" + ("A" * 300_000) + "</cp:coreProperties>"
        zf.writestr("docProps/core.xml", huge)
    assert _extract_office_metadata(buf.getvalue()) == {}


def test_malformed_xml_returns_empty_not_a_crash():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("docProps/core.xml", "<not-valid-xml this is broken")
    assert _extract_office_metadata(buf.getvalue()) == {}


def test_empty_creator_field_is_dropped():
    meta = _extract_office_metadata(_fake_docx(creator="", modifier="Someone"))
    assert "Author" not in meta
    assert meta["LastModifiedBy"] == "Someone"


# --------------------------------------------------------------------------
# _extract_mp4_metadata
# --------------------------------------------------------------------------

def _mp4_atom(tag, value):
    """Builds one QuickTime user-data string atom: [size(4)][tag(4)]
    [strlen(2)][lang(2)][value bytes] - the real documented format."""
    body = value.encode("utf-8")
    header = struct.pack(">H", len(body)) + b"\x00\x00"  # strlen, lang=0
    payload = tag + header + body
    size = struct.pack(">I", len(payload) + 4)
    return size + payload


def _fake_mp4(*atoms):
    # Minimal valid-looking ftyp box so the leading sniff check passes,
    # then the requested user-data atoms concatenated after it.
    ftyp = struct.pack(">I", 16) + b"ftyp" + b"isom" + struct.pack(">I", 0)
    return ftyp + b"".join(atoms)


def test_mp4_extracts_gps_iso6709():
    data = _fake_mp4(_mp4_atom(b"\xa9xyz", "+37.3349-122.0090+000.000/"))
    meta = _extract_mp4_metadata(data)
    assert meta["GPS"] == "+37.3349, -122.0090"


def test_mp4_extracts_make_model_software():
    data = _fake_mp4(
        _mp4_atom(b"\xa9mak", "Apple"),
        _mp4_atom(b"\xa9mod", "iPhone 14 Pro"),
        _mp4_atom(b"\xa9swr", "17.1"),
    )
    meta = _extract_mp4_metadata(data)
    assert meta == {"Make": "Apple", "Model": "iPhone 14 Pro", "Software": "17.1"}


def test_non_mp4_bytes_return_empty_not_a_crash():
    assert _extract_mp4_metadata(b"not an mp4 file, random bytes here") == {}


def test_mp4_malformed_gps_string_is_rejected():
    """A ©xyz atom whose content doesn't parse as ISO 6709 must not be
    reported as GPS - only a real, well-formed coordinate string counts."""
    data = _fake_mp4(_mp4_atom(b"\xa9xyz", "not a coordinate"))
    meta = _extract_mp4_metadata(data)
    assert "GPS" not in meta


def test_mp4_truncated_atom_does_not_crash():
    """A tag byte sequence with no valid length-prefixed body after it
    (truncated/malformed data) must degrade gracefully, never raise."""
    data = _fake_mp4() + b"\xa9mak"  # tag with nothing after it
    assert _extract_mp4_metadata(data) == {}


# --------------------------------------------------------------------------
# check_media integration: documents/video wired end-to-end
# --------------------------------------------------------------------------

class _FakeHeadResp:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class _FakeStreamResp:
    def __init__(self, status_code, content_type, body):
        self.status_code = status_code
        self.headers = {"Content-Type": content_type}
        self._body = body

    @property
    def text(self):
        return self._body.decode("utf-8", errors="replace")

    def iter_content(self, chunk_size):
        yield self._body

    def close(self):
        pass


class _FakeMediaSession:
    """Stands in for the scanning session inside check_media - only needs
    .head()/.get() for the URLs check_media actually visits."""

    def __init__(self, home_html, file_responses):
        self.home_html = home_html
        self.file_responses = file_responses  # {url: (content_type, body)}

    def head(self, url, timeout=None, allow_redirects=None):
        raise __import__("requests").RequestException("HEAD not supported by fake")

    def get(self, url, timeout=None, allow_redirects=None, stream=False):
        if url.rstrip("/").endswith("example.com") or url.endswith("example.com/"):
            return _FakeStreamResp(200, "text/html", self.home_html.encode())
        ctype, body = self.file_responses.get(url, ("text/plain", b"not found"))
        status = 200 if url in self.file_responses else 404
        return _FakeStreamResp(status, ctype, body)


def test_check_media_reports_leaked_pdf_author(monkeypatch):
    from glassbox import checks

    pdf_bytes = _fake_pdf(b"/Author (Internal Employee Name)")
    home_html = '<html><body><a href="/reports/q3.pdf">Q3 report</a></body></html>'
    session = _FakeMediaSession(home_html, {"https://example.com/reports/q3.pdf": ("application/pdf", pdf_bytes)})

    # crawl_media does a robots.txt fetch too - stub it out so this test
    # only exercises the document-metadata path, not the full crawler.
    monkeypatch.setattr(checks, "_fetch_robots_disallow_prefixes", lambda *a, **k: [])
    monkeypatch.setattr(checks, "_get_respecting_backoff", lambda sess, url, **kw: sess.get(url, **kw))

    data, findings = check_media(session, "https://example.com", download=False, max_files=5)
    doc_items = [i for i in data["media_items"] if i.get("kind") == "document"]
    assert len(doc_items) == 1
    assert doc_items[0]["document_metadata"] == {"Author": "Internal Employee Name"}
    assert any("Author/software metadata embedded in public document" in f.title for f in findings)


def test_check_media_reports_leaked_video_gps(monkeypatch):
    from glassbox import checks

    video_bytes = _fake_mp4(_mp4_atom(b"\xa9xyz", "+37.3349-122.0090+000.000/"))
    home_html = '<html><body><a href="/videos/clip.mp4">clip</a></body></html>'
    session = _FakeMediaSession(home_html, {"https://example.com/videos/clip.mp4": ("video/mp4", video_bytes)})

    monkeypatch.setattr(checks, "_fetch_robots_disallow_prefixes", lambda *a, **k: [])
    monkeypatch.setattr(checks, "_get_respecting_backoff", lambda sess, url, **kw: sess.get(url, **kw))

    data, findings = check_media(session, "https://example.com", download=False, max_files=5)
    video_items = [i for i in data["media_items"] if i.get("kind") == "video"]
    assert len(video_items) == 1
    assert video_items[0]["video_metadata"]["GPS"] == "+37.3349, -122.0090"
    assert any("GPS location embedded in public video" in f.title and f.severity == "high" for f in findings)
