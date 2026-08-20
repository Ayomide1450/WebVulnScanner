"""
One-off generator for the app's favicon set (SEO-04, 09-01-PLAN.md Task 1).

Draws a simple rounded-square "shield" mark in the app's --accent green
(#22c55e) on the --bg dark navy (#020617) background - close enough to
templates/base.html's existing <symbol id="icon-shield"> sprite mark to be
recognizable as the same brand, without needing to rasterize the actual SVG
path (Pillow has no SVG renderer).

Re-run with:
    .venv\\Scripts\\python scripts\\generate_favicons.py

Writes into webvulnscanner/static/ (Flask's default static folder, since
Flask(__name__) in webvulnscanner/__init__.py resolves relative to the
webvulnscanner/ package directory - see webvulnscanner/__init__.py line 76).
"""
from pathlib import Path

from PIL import Image, ImageDraw

BG = (2, 6, 23, 255)       # --bg #020617
ACCENT = (34, 197, 94, 255)  # --accent #22c55e

STATIC_DIR = Path(__file__).resolve().parent.parent / "webvulnscanner" / "static"


def _draw_mark(size: int) -> Image.Image:
    """Draw a simple shield silhouette (rounded pentagon-ish shape) filled
    with ACCENT on a BG background, echoing base.html's #icon-shield glyph
    (a shield outline) without needing an SVG rasterizer."""
    img = Image.new("RGBA", (size, size), BG)
    draw = ImageDraw.Draw(img)

    # Shield outline scaled to a 24x24 viewBox equivalent of base.html's
    # icon-shield path: M12 2 4 5v6c0 5 3.4 9 8 11 4.6-2 8-6 8-11V5l-8-3Z
    scale = size / 24.0
    points = [
        (12 * scale, 2 * scale),
        (4 * scale, 5 * scale),
        (4 * scale, 11 * scale),
        (7 * scale, 19 * scale),
        (12 * scale, 22 * scale),
        (17 * scale, 19 * scale),
        (20 * scale, 11 * scale),
        (20 * scale, 5 * scale),
    ]
    draw.polygon(points, fill=ACCENT)
    return img


def main() -> None:
    STATIC_DIR.mkdir(parents=True, exist_ok=True)

    img16 = _draw_mark(16)
    img32 = _draw_mark(32)
    img48 = _draw_mark(48)
    img180 = _draw_mark(180)

    img16.save(STATIC_DIR / "favicon-16x16.png", format="PNG")
    img32.save(STATIC_DIR / "favicon-32x32.png", format="PNG")
    img180.save(STATIC_DIR / "apple-touch-icon.png", format="PNG")

    # Multi-size .ico built from the same three raster sizes.
    img16.save(
        STATIC_DIR / "favicon.ico",
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48)],
        append_images=[img32, img48],
    )

    for name in ("favicon.ico", "favicon-16x16.png", "favicon-32x32.png", "apple-touch-icon.png"):
        path = STATIC_DIR / name
        print(f"{path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
