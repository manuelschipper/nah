#!/usr/bin/env python3
"""Assemble the deployable nahguard.ai homepage from fragment.html:
full document head (charset/viewport/title/description/OG/twitter/theme-color),
favicon data URI derived from the hand-lettered word mask, og.png card, and
the current TUI recording spliced in from nah-tui.cast.
Writes dist/index.html and dist/og.png."""
import base64
import io
import json
import os
import re
import shutil
import urllib.request

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
FRAGMENT = f"{HERE}/fragment.html"
OUT_DIR = f"{HERE}/dist"

RED = (0xA5, 0x32, 0x1E)
INK = (0x23, 0x21, 0x1E)
SOFT = (0x6E, 0x67, 0x5B)
PAPER = (0xFA, 0xF6, 0xEC)

DESCRIPTION = (
    "nah is a guard that sits in your coding agent's hook path and reads "
    "tool calls before they run. It blocks the calls it can prove are "
    "disasters — deterministically, in microseconds, with no LLM — and "
    "leaves everything else to your normal approval flow. One Rust binary. "
    "When a guard you need is missing, your agent can write it."
)

os.makedirs(OUT_DIR, exist_ok=True)
frag = open(FRAGMENT, encoding="utf-8").read()

# -- bake the current star count so the page never renders a blank badge;
#    the page refreshes it live on load. Keeps the last baked value if
#    GitHub is unreachable at build time.
STARS_CACHE = f"{HERE}/stars.txt"
try:
    with urllib.request.urlopen(
        "https://api.github.com/repos/manuelschipper/nah", timeout=8
    ) as r:
        n = json.load(r)["stargazers_count"]
    open(STARS_CACHE, "w").write(str(n))
except Exception:
    n = int(open(STARS_CACHE).read().strip())
stars = f"{n / 1000:.1f}".rstrip("0").rstrip(".") + "k" if n >= 1000 else str(n)
assert frag.count("{{STARS}}") == 2, "expected the topbar badge and the CTA"
frag = frag.replace("{{STARS}}", stars)

# -- open issues, baked only. The repo's open_issues_count includes PRs, so
#    ask the search API for issues alone. Not refreshed at runtime: search is
#    rate limited hard, and a stale count here is harmless.
ISSUES_CACHE = f"{HERE}/issues.txt"
try:
    with urllib.request.urlopen(
        "https://api.github.com/search/issues?q=repo:manuelschipper/nah"
        "+type:issue+state:open&per_page=1",
        timeout=8,
    ) as r:
        issues = json.load(r)["total_count"]
    open(ISSUES_CACHE, "w").write(str(issues))
except Exception:
    issues = int(open(ISSUES_CACHE).read().strip())
assert frag.count("{{ISSUES}}") == 1, "expected the issues count"
frag = frag.replace("{{ISSUES}}", str(issues))

# -- splice the TUI recording so a re-record only needs a rebuild ---------
cast = open(f"{HERE}/nah-tui.cast", encoding="utf-8").read()
frag, n = re.subn(
    r"var NAH_TUI_CAST = .*?;\n",
    lambda _: "var NAH_TUI_CAST = " + json.dumps(cast) + ";\n",
    frag,
    count=1,
    flags=re.S,
)
assert n == 1, "expected the NAH_TUI_CAST assignment"

# -- pull the title out of the fragment; it belongs in <head> ------------
m = re.match(r"<title>(.*?)</title>\n?", frag)
title = m.group(1)
body = frag[m.end():]

# -- the hand-lettered "nah." mask (alpha channel = ink) ------------------
m = re.search(r'\.art-word\{[^}]*?base64,([A-Za-z0-9+/=]+)', frag)
word = Image.open(io.BytesIO(base64.b64decode(m.group(1)))).convert("RGBA")
alpha = word.getchannel("A")


def inked(alpha_img, color):
    img = Image.new("RGBA", alpha_img.size, color + (255,))
    img.putalpha(alpha_img)
    return img


# -- favicon: the word on transparent, centered in a square. Two of them:
#    ink for light browser chrome, paper for dark, so the mark never
#    disappears into the tab strip.
def favicon(color):
    side = max(word.size)
    fav = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    fav.paste(inked(alpha, color),
              ((side - word.size[0]) // 2, (side - word.size[1]) // 2))
    fav = fav.resize((64, 64), Image.LANCZOS)
    buf = io.BytesIO()
    fav.save(buf, "PNG", optimize=True)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


fav_light = favicon(INK)
fav_dark = favicon(PAPER)

# -- og card: paper, big red word, tagline underneath --------------------
og = Image.new("RGB", (1200, 630), PAPER)
ww = 470
wh = round(word.size[1] * ww / word.size[0])
big = inked(alpha.resize((ww, wh), Image.LANCZOS), RED)
og.paste(big, ((1200 - ww) // 2, 108), big)
draw = ImageDraw.Draw(og)
mono = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 34)
mono_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 24)
tag = "expensive mistakes stop here"
facts = "microsecond verdicts · no LLM · one Rust binary"
tw = draw.textlength(tag, font=mono)
draw.text(((1200 - tw) / 2, 108 + wh + 66), tag, font=mono, fill=INK)
fw = draw.textlength(facts, font=mono_sm)
draw.text(((1200 - fw) / 2, 108 + wh + 130), facts, font=mono_sm, fill=SOFT)
og.save(f"{OUT_DIR}/og.png", "PNG", optimize=True)

# -- assemble the document ----------------------------------------------
jsonld = json.dumps({
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    "name": "nah",
    "url": "https://nahguard.ai/",
    "description": DESCRIPTION,
    "applicationCategory": "DeveloperApplication",
    "operatingSystem": "macOS, Linux",
    "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
    "author": {"@type": "Person", "name": "Manuel Schipper",
               "url": "https://schipper.ai/"},
    "sameAs": ["https://github.com/manuelschipper/nah"],
}, indent=0)

head = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta name="description" content="{DESCRIPTION}">
<link rel="canonical" href="https://nahguard.ai/">
<meta property="og:type" content="website">
<meta property="og:url" content="https://nahguard.ai/">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{DESCRIPTION}">
<meta property="og:image" content="https://nahguard.ai/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<script type="application/ld+json">{jsonld}</script>
<meta name="theme-color" media="(prefers-color-scheme: light)" content="#FAF6EC">
<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#1A1714">
<link rel="icon" type="image/png" sizes="64x64" href="{fav_light}" media="(prefers-color-scheme: light)">
<link rel="icon" type="image/png" sizes="64x64" href="{fav_dark}" media="(prefers-color-scheme: dark)">
</head>
<body>
"""
doc = head + body + "</body>\n</html>\n"
open(f"{OUT_DIR}/index.html", "w", encoding="utf-8").write(doc)

# -- the install script, served at /install for curl | sh -----------------
shutil.copy(f"{HERE}/install.sh", f"{OUT_DIR}/install")
open(f"{OUT_DIR}/_headers", "w").write("/install\n  Content-Type: text/plain; charset=utf-8\n")

# -- crawler files. A real 404.html also switches Pages out of SPA
#    fallback, so unknown paths stop serving the homepage with a 200.
open(f"{OUT_DIR}/robots.txt", "w").write(
    "User-agent: *\nAllow: /\n\nSitemap: https://nahguard.ai/sitemap.xml\n"
)
open(f"{OUT_DIR}/sitemap.xml", "w").write(
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    "<url><loc>https://nahguard.ai/</loc></url>\n"
    "</urlset>\n"
)
shutil.copy(f"{HERE}/llms.txt", f"{OUT_DIR}/llms.txt")
open(f"{OUT_DIR}/404.html", "w", encoding="utf-8").write(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>404 · {title}</title>
<meta name="robots" content="noindex">
<link rel="icon" type="image/png" sizes="64x64" href="{fav_light}" media="(prefers-color-scheme: light)">
<link rel="icon" type="image/png" sizes="64x64" href="{fav_dark}" media="(prefers-color-scheme: dark)">
<style>
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#FAF6EC;color:#23211E;font:16px/1.6 ui-monospace,Menlo,Consolas,monospace}}
@media(prefers-color-scheme:dark){{body{{background:#1A1714;color:#FAF6EC}}}}
main{{text-align:center;padding:2rem}}
a{{color:#A5321E}}
</style>
</head>
<body><main><p>404 — nothing lives at this path.</p>
<p><a href="/">nahguard.ai</a></p></main></body>
</html>
""")

# -- the try-it engine: the decision pipeline compiled to wasm32 ----------
#    (see wasm/README note in ../README.md). The page works without it —
#    the inline rules stand in — so a missing artifact only warns.
WASM = f"{HERE}/wasm/target/wasm32-wasip1/release/nah_home_wasm.wasm"
if os.path.exists(WASM):
    shutil.copy(WASM, f"{OUT_DIR}/nah.wasm")
    wasm_note = f"nah.wasm {os.path.getsize(WASM)} bytes"
else:
    wasm_note = "NO nah.wasm (build homepage/wasm first)"
print(f"index.html {len(doc)} bytes · og.png · title {title!r} · 2 favicons · {wasm_note}")
