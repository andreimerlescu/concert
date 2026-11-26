#!/usr/bin/env python3
"""Render docs/diagrams/*.svg into 2x Retina true-alpha transparent PNGs.

Uses local headless Google Chrome with transparent default background and
validates every output PNG's dimensions and alpha channel via Pillow.
Optionally generates side-by-side 680px dev.to article-column QA previews
showing real 18px prose above/below each diagram in both Light (#ffffff)
and Dark (#171717) modes.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from PIL import Image

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    shutil.which("google-chrome") or "",
    shutil.which("chromium") or "",
]


def find_chrome() -> str:
    for path in CHROME_CANDIDATES:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise RuntimeError(
        "Google Chrome or Chromium is required to rasterize SVG diagrams; "
        "none found in standard paths."
    )


def parse_svg_size(svg_path: Path) -> tuple[int, int]:
    tree = ET.parse(svg_path)
    root = tree.getroot()
    vb = root.attrib.get("viewBox", "")
    parts = [float(x) for x in re.split(r"[\s,]+", vb.strip()) if x]
    if len(parts) == 4:
        return int(round(parts[2])), int(round(parts[3]))
    w = int(round(float(re.sub(r"[^0-9.]", "", root.attrib.get("width", "720")))))
    h = int(round(float(re.sub(r"[^0-9.]", "", root.attrib.get("height", "760")))))
    return w, h


def render_svg_to_png(chrome: str, svg_path: Path, png_path: Path, scale: int) -> tuple[int, int]:
    w, h = parse_svg_size(svg_path)
    svg_text = svg_path.read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="concert-svg-") as tmpdir:
        tmp = Path(tmpdir)
        profile_dir = tmp / "profile"
        profile_dir.mkdir()
        html_path = tmp / "render.html"
        html_path.write_text(
            f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
  html, body {{
    margin: 0;
    padding: 0;
    width: {w}px;
    height: {h}px;
    overflow: hidden;
    background: transparent !important;
  }}
  svg {{
    display: block;
    width: {w}px;
    height: {h}px;
  }}
</style>
</head>
<body>{svg_text}</body>
</html>
""",
            encoding="utf-8",
        )

        cmd = [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--default-background-color=00000000",
            f"--force-device-scale-factor={scale}",
            f"--window-size={w},{h}",
            f"--user-data-dir={profile_dir}",
            f"--screenshot={png_path}",
            html_path.as_uri(),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode != 0 or not png_path.exists():
            raise RuntimeError(
                f"Chrome failed rendering {svg_path.name} (rc={res.returncode}):\n"
                f"{res.stderr.strip()}"
            )

    with Image.open(png_path) as img:
        rgba = img.convert("RGBA")
        expected = (w * scale, h * scale)
        if rgba.size != expected:
            if rgba.size[0] >= expected[0] and rgba.size[1] >= expected[1]:
                rgba = rgba.crop((0, 0, expected[0], expected[1]))
                rgba.save(png_path, format="PNG", optimize=True)
            else:
                raise RuntimeError(
                    f"{png_path.name}: got size {rgba.size}, want {expected}"
                )
        else:
            rgba.save(png_path, format="PNG", optimize=True)

        corners = [
            rgba.getpixel((0, 0))[3],
            rgba.getpixel((expected[0] - 1, 0))[3],
            rgba.getpixel((0, expected[1] - 1))[3],
            rgba.getpixel((expected[0] - 1, expected[1] - 1))[3],
        ]
        if any(a != 0 for a in corners):
            raise RuntimeError(
                f"{png_path.name}: expected transparent corners (alpha=0), got {corners}"
            )
        alpha_band = rgba.getchannel("A")
        hist = alpha_band.histogram()
        transparent_ratio = hist[0] / float(expected[0] * expected[1])
        print(
            f"[OK] {png_path.name}: {expected[0]}x{expected[1]} RGBA "
            f"({transparent_ratio * 100:.1f}% transparent canvas)"
        )
    return w, h


def make_devto_preview(chrome: str, png_path: Path, logical_size: tuple[int, int], preview_dir: Path) -> Path:
    """Render a side-by-side 680px dev.to article-column Light & Dark mockup."""
    preview_dir.mkdir(parents=True, exist_ok=True)
    lw, lh = logical_size
    col_w = 680
    img_h = int(round(lh * (col_w / float(lw))))
    total_w = 1520
    total_h = img_h + 250
    out_path = preview_dir / f"{png_path.stem}-devto-preview.png"
    title = png_path.stem

    with tempfile.TemporaryDirectory(prefix="concert-prev-") as tmpdir:
        tmp = Path(tmpdir)
        profile_dir = tmp / "profile"
        profile_dir.mkdir()
        html_path = tmp / "preview.html"
        img_uri = png_path.resolve().as_uri()
        html_path.write_text(
            f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; }}
  html, body {{
    margin: 0;
    padding: 0;
    width: {total_w}px;
    height: {total_h}px;
    overflow: hidden;
    background: #64748b;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }}
  .grid {{
    display: flex;
    gap: 20px;
    padding: 20px;
    width: {total_w}px;
    height: {total_h}px;
  }}
  .col {{
    width: 730px;
    padding: 20px 25px;
    border-radius: 10px;
  }}
  .light {{ background: #ffffff; color: #171717; }}
  .dark  {{ background: #171717; color: #f5f5f5; }}
  .badge {{
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    opacity: 0.65;
    margin-bottom: 10px;
  }}
  h2 {{
    font-size: 26px;
    margin: 0 0 10px 0;
    line-height: 1.25;
  }}
  p {{
    font-family: Georgia, Cambria, 'Times New Roman', serif;
    font-size: 18px;
    line-height: 1.55;
    margin: 0 0 16px 0;
  }}
  code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 15px;
    padding: 2px 6px;
    border-radius: 4px;
  }}
  .light code {{ background: #f1f5f9; color: #0f172a; }}
  .dark  code {{ background: #262626; color: #e2e8f0; }}
  .diagram {{
    display: block;
    width: {col_w}px;
    height: auto;
    margin: 14px 0 16px 0;
  }}
</style>
</head>
<body>
  <div class="grid">
    <div class="col light">
      <div class="badge">dev.to Light Mode (#ffffff) · 680px column · {png_path.name}</div>
      <h2>Section Preview ({title})</h2>
      <p>Sample 18px dev.to article prose above <code>concert</code> to verify real reading scale:</p>
      <img class="diagram" src="{img_uri}" />
      <p>Follow-up 18px paragraph text below the diagram for visual weight comparison.</p>
    </div>
    <div class="col dark">
      <div class="badge">dev.to Dark Mode (#171717) · 680px column · {png_path.name}</div>
      <h2>Section Preview ({title})</h2>
      <p>Sample 18px dev.to article prose above <code>concert</code> to verify real reading scale:</p>
      <img class="diagram" src="{img_uri}" />
      <p>Follow-up 18px paragraph text below the diagram for visual weight comparison.</p>
    </div>
  </div>
</body>
</html>
""",
            encoding="utf-8",
        )
        cmd = [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--force-device-scale-factor=1",
            f"--window-size={total_w},{total_h}",
            f"--user-data-dir={profile_dir}",
            f"--screenshot={out_path}",
            html_path.as_uri(),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode != 0 or not out_path.exists():
            raise RuntimeError(f"Preview render failed for {png_path.name}: {res.stderr.strip()}")
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Render Concert SVG diagrams to transparent 2x PNGs.")
    parser.add_argument(
        "--dir",
        default="docs/diagrams",
        help="Directory containing *.svg files (default: docs/diagrams)",
    )
    parser.add_argument(
        "--scale",
        type=int,
        default=2,
        help="Device pixel scale factor (default: 2 -> 1440px wide for 720px SVGs)",
    )
    parser.add_argument(
        "--preview",
        default="",
        help="Optional output directory for 680px dev.to Light/Dark QA mockups",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Optional specific SVG filenames to render (defaults to all *.svg in --dir)",
    )
    args = parser.parse_args()

    diag_dir = Path(args.dir)
    if args.files:
        svgs = [Path(f) if Path(f).is_absolute() else diag_dir / f for f in args.files]
    else:
        svgs = sorted(diag_dir.glob("*.svg"))
    if not svgs:
        print(f"No SVG files found in {diag_dir}", file=sys.stderr)
        return 1

    chrome = find_chrome()
    preview_dir = Path(args.preview) if args.preview else None

    for svg_path in svgs:
        png_path = svg_path.with_suffix(".png")
        logical_size = render_svg_to_png(chrome, svg_path, png_path, args.scale)
        if preview_dir is not None:
            out = make_devto_preview(chrome, png_path, logical_size, preview_dir)
            print(f"     dev.to preview -> {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
