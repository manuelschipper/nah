#!/usr/bin/env python3
"""Assemble the deployable nahguard.ai site from fragment.html:
full document head (charset/viewport/title/description/OG/twitter/theme-color),
favicon data URI derived from the hand-lettered word mask, og.png card, and
the current TUI recording spliced in from nah-tui.cast. Also renders
../docs/*.md and the compiled guard catalog to /docs/ pages, and CHANGELOG.md
to /news/ in the same paper/ink/mono system. Run under a python that has
Pillow and markdown
(on the deploy host: /home/dev/.venvs/nah-homepage/bin/python)."""
import base64
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request

import markdown
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
FRAGMENT = f"{HERE}/fragment.html"
OUT_DIR = f"{HERE}/dist"

INK = (0x23, 0x21, 0x1E)
SOFT = (0x6E, 0x67, 0x5B)
PAPER = (0xFA, 0xF6, 0xEC)

# the dark theme's tokens, used for the share card
DARK_PAPER = (0x1A, 0x17, 0x14)
DARK_INK = (0xEF, 0xE8, 0xDA)
DARK_SOFT = (0xAD, 0xA3, 0x94)

DESCRIPTION = (
    "nah is a guard that sits in your coding agent's hook path and reads "
    "tool calls before they run. It blocks the calls it can prove are "
    "disasters — deterministically, in microseconds, with no LLM — and "
    "leaves everything else to your normal approval flow. One Rust binary. "
    "When a guard you need is missing, your agent can write it."
)

os.makedirs(OUT_DIR, exist_ok=True)
frag = open(FRAGMENT, encoding="utf-8").read()

# -- the docs and news links live on this site now, not on GitHub ---------
NAV_RETARGETS = [
    ('href="https://github.com/manuelschipper/nah/tree/main/docs"', 'href="/docs/"'),
    ('href="https://github.com/manuelschipper/nah/blob/main/CHANGELOG.md"', 'href="/news/"'),
    ('href="https://github.com/manuelschipper/nah/blob/main/docs/threat-model.md"', 'href="/docs/threat-model/"'),
]
for old, new in NAV_RETARGETS:
    assert frag.count(old) >= 1, f"expected {old} in fragment"
    frag = frag.replace(old, new)

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

# -- og card: the dark theme, so the word reads white in a feed. Red is the
#    block stamp's colour and means "something was stopped"; a share card is
#    not a verdict, and the hero mark on the page is inked, not red. ---------
og = Image.new("RGB", (1200, 630), DARK_PAPER)
ww = 470
wh = round(word.size[1] * ww / word.size[0])
big = inked(alpha.resize((ww, wh), Image.LANCZOS), DARK_INK)
og.paste(big, ((1200 - ww) // 2, 108), big)
draw = ImageDraw.Draw(og)
mono = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 34)
mono_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 24)
tag = "expensive mistakes stop here"
facts = "microsecond verdicts · no LLM · one Rust binary"
tw = draw.textlength(tag, font=mono)
draw.text(((1200 - tw) / 2, 108 + wh + 66), tag, font=mono, fill=DARK_INK)
fw = draw.textlength(facts, font=mono_sm)
draw.text(((1200 - fw) / 2, 108 + wh + 130), facts, font=mono_sm, fill=DARK_SOFT)
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
<meta property="og:image" content="https://nahguard.ai/og.png?v=2">
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
# sitemap.xml is written at the end, once the docs pages are known.
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

# ---- docs and news pages ------------------------------------------------
# Hand-written pages are rendered verbatim from ../docs/*.md and
# ../CHANGELOG.md into the same paper/ink/mono system as the landing page.
# The guard page is generated separately from the compiled CLI catalog.
ROOT = os.path.dirname(HERE)
DOCS_SRC = f"{ROOT}/docs"


def generated_guard_docs():
    nah_bin = os.path.abspath(
        os.environ.get("NAH_DOCS_BIN", f"{ROOT}/target/release/nah")
    )
    if not os.path.isfile(nah_bin) or not os.access(nah_bin, os.X_OK):
        raise RuntimeError(
            f"compiled nah not found at {nah_bin}; run "
            "cargo build --release --locked -p nah-cli"
        )

    # Public docs must reflect shipped defaults, not the deploy user's local
    # disabled or custom guards. A temporary HOME gives the CLI fresh state.
    with tempfile.TemporaryDirectory(prefix="nah-homepage-guards-") as home:
        env = os.environ.copy()
        env["HOME"] = home
        result = subprocess.run(
            [nah_bin, "docs", "guards"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"{nah_bin} docs guards failed: {result.stderr.strip()}"
        )

    prefix = "Built-in:\n\n"
    custom_marker = "\nCustom:\n"
    if not result.stdout.startswith(prefix) or custom_marker not in result.stdout:
        raise RuntimeError("nah docs guards returned an unexpected document shape")
    built_in = result.stdout[len(prefix):].split(custom_marker, 1)[0].strip()
    guard_count = len(re.findall(r"(?m)^# [a-z0-9-]+$", built_in))
    if guard_count == 0:
        raise RuntimeError("nah docs guards returned no built-in guards")

    # The CLI renders each guard as a standalone document heading. Demote
    # those headings beneath the website page title.
    built_in = re.sub(r"(?m)^# ", "## ", built_in)
    return f"# Guards\n\n{built_in}\n", guard_count


def word_mark(color, height=40):
    w, h = word.size
    img = inked(alpha.resize((round(w * height / h), height), Image.LANCZOS), color)
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


WORD_INK = word_mark(INK)
WORD_PAPER = word_mark(PAPER)

DOCS_CSS = """
:root{
  --paper:#FAF6EC; --paper-card:#FFFDF7; --ink:#23211E; --ink-soft:#6E675B;
  --rule:#23211E1F; --rule-firm:#23211E; --red:#A5321E;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){
  :root{
    --paper:#1A1714; --paper-card:#221E1A; --ink:#EFE8DA; --ink-soft:#ADA394;
    --rule:#EFE8DA24; --rule-firm:#EFE8DAB8; --red:#C75A41;
  }
}
*{box-sizing:border-box;margin:0;padding:0}
html{font-size:16px}
body{
  font-family:var(--mono); background:var(--paper); color:var(--ink);
  font-size:.85rem; line-height:1.75; -webkit-font-smoothing:antialiased;
}
.wrap{max-width:1020px;margin:0 auto;padding:1.4rem 1.3rem 4rem}
.layout{display:grid;grid-template-columns:172px minmax(0,1fr);gap:2.8rem}
.col{max-width:74ch;min-width:0}
.side{font-size:.72rem;line-height:2}
.side nav{position:sticky;top:1.3rem;display:flex;flex-direction:column;
  max-height:calc(100vh - 2.6rem);overflow-y:auto;scrollbar-width:none}
.side nav::-webkit-scrollbar{display:none}
.side a{color:var(--ink-soft);text-decoration:none;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis}
.side a:hover{color:var(--ink)}
.side a[aria-current]{color:var(--ink)}
.side a[aria-current]::before{content:"▎";color:var(--red)}
.side a.sub{padding-left:1rem}
@media (max-width:900px){
  .wrap{max-width:74ch}
  .layout{display:block}
  .side{display:none}
}
.bar{
  display:flex;justify-content:space-between;align-items:center;gap:1rem;
  padding-bottom:1rem;border-bottom:1px solid var(--rule);margin-bottom:2.2rem;
}
.bar .mark img{height:20px;width:auto;display:block}
.bar .mark .m-paper{display:none}
@media (prefers-color-scheme:dark){
  .bar .mark .m-ink{display:none}
  .bar .mark .m-paper{display:block}
}
.bar nav{display:flex;gap:1.3rem;font-size:.78rem}
.bar nav a{color:var(--ink-soft);text-decoration:none}
.bar nav a:hover{color:var(--ink)}
.bar nav a[aria-current]{color:var(--ink)}
.star{color:var(--red)}
.eyebrow{
  font-size:.68rem;letter-spacing:.14em;color:var(--ink-soft);
  text-transform:uppercase;margin-bottom:1.6rem;
}
main a{color:inherit;text-decoration:underline;text-decoration-color:var(--rule-firm);text-underline-offset:3px}
main a:hover{text-decoration-color:var(--red)}
h1{font-size:1.25rem;line-height:1.35;margin-bottom:1.1rem}
h2{font-size:1rem;margin:2.2rem 0 .7rem}
h3{font-size:.9rem;margin:1.7rem 0 .5rem}
p{margin-bottom:.95rem}
ul,ol{margin:0 0 .95rem 1.4rem}
li{margin-bottom:.3rem}
li::marker{color:var(--ink-soft)}
code{background:var(--paper-card);border:1px solid var(--rule);border-radius:3px;padding:.08em .3em;font-size:.95em}
pre{
  background:var(--paper-card);border:1px solid var(--rule);border-radius:4px;
  padding: .85rem 1rem;overflow-x:auto;margin-bottom:1.1rem;line-height:1.6;
}
pre code{background:none;border:none;padding:0}
table{width:100%;border-collapse:collapse;margin-bottom:1.1rem;font-size:.95em}
th,td{padding:.35rem .6rem;text-align:left;border-bottom:1px solid var(--rule)}
th{color:var(--ink-soft);font-weight:400;font-size:.85em;letter-spacing:.08em;text-transform:uppercase}
blockquote{border-left:2px solid var(--rule-firm);padding-left:1rem;color:var(--ink-soft);margin-bottom:.95rem}
hr{border:none;border-top:1px solid var(--rule);margin:1.6rem 0}
footer{margin-top:3.5rem;padding-top:1rem;border-top:1px solid var(--rule);font-size:.75rem;color:var(--ink-soft)}
footer a{color:inherit}
@media (max-width:600px){.wrap{padding:1rem 1rem 3rem}.bar{flex-wrap:wrap}}
"""


# Sidebar structure comes from the docs' own indexes: topic order and labels
# from README.md plus the generated guard catalog, runtime labels from
# runtimes.md.
_readme_text = open(f"{DOCS_SRC}/README.md", encoding="utf-8").read()
TOPICS = re.findall(r"^- \[([^]]+)\]\(([a-z-]+)\.md\)", _readme_text, re.M)
TOPICS.insert(2, ("Guard catalog", "guards"))
_runtimes_text = open(f"{DOCS_SRC}/runtimes.md", encoding="utf-8").read()
RUNTIME_LABELS = re.findall(r"^- `([a-z0-9-]+)` — (.+)$", _runtimes_text, re.M)


def sidebar_html(path):
    def a(href, label, sub=False):
        cur = ' aria-current="page"' if href == path else ""
        cls = ' class="sub"' if sub else ""
        return f'<a href="{href}"{cur}{cls}>{label}</a>'

    rows = [a("/docs/", "Index")]
    for label, slug in TOPICS:
        rows.append(a(f"/docs/{slug}/", label))
        if slug == "runtimes" and path.startswith("/docs/runtimes"):
            for r, rlabel in RUNTIME_LABELS:
                rows.append(a(f"/docs/runtimes/{r}/", rlabel, sub=True))
    rows.append(a("/news/", "News"))
    return "\n    ".join(rows)


def page_shell(page_title, eyebrow, body_html, description, path, current):
    def nav_a(href, label, key):
        cur = ' aria-current="page"' if key == current else ""
        return f'<a href="{href}"{cur}>{label}</a>'

    nav = "\n      ".join([
        nav_a("/docs/", "docs", "docs"),
        nav_a("/news/", "news", "news"),
        f'<a href="https://github.com/manuelschipper/nah">github <span class="star">★</span> {stars}</a>',
    ])
    side = sidebar_html(path)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{page_title} · nah</title>
<meta name="description" content="{description}">
<link rel="canonical" href="https://nahguard.ai{path}">
<meta property="og:type" content="article">
<meta property="og:url" content="https://nahguard.ai{path}">
<meta property="og:title" content="{page_title} · nah">
<meta property="og:description" content="{description}">
<meta property="og:image" content="https://nahguard.ai/og.png?v=2">
<meta name="twitter:card" content="summary_large_image">
<meta name="theme-color" media="(prefers-color-scheme: light)" content="#FAF6EC">
<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#1A1714">
<link rel="icon" type="image/png" sizes="64x64" href="{fav_light}" media="(prefers-color-scheme: light)">
<link rel="icon" type="image/png" sizes="64x64" href="{fav_dark}" media="(prefers-color-scheme: dark)">
<style>{DOCS_CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="bar">
    <a class="mark" href="/" aria-label="nah home">
      <img class="m-ink" src="{WORD_INK}" alt="nah">
      <img class="m-paper" src="{WORD_PAPER}" alt="nah">
    </a>
    <nav>
      {nav}
    </nav>
  </header>
  <div class="layout">
  <aside class="side"><nav>
    {side}
  </nav></aside>
  <div class="col">
  <p class="eyebrow">{eyebrow}</p>
  <main>
{body_html}
  </main>
  <footer><a href="/docs/">docs index</a> · <a href="/news/">news</a> · <a href="https://github.com/manuelschipper/nah">source</a></footer>
  </div>
  </div>
</div>
</body>
</html>
"""


def rewrite_md_links(html):
    html = html.replace('href="../CHANGELOG.md"', 'href="/news/"')
    html = html.replace('href="README.md"', 'href="/docs/"')
    html = re.sub(r'href="runtimes/([a-z0-9-]+)\.md"', r'href="/docs/runtimes/\1/"', html)
    html = re.sub(r'href="([a-z0-9-]+)\.md"', r'href="/docs/\1/"', html)
    return html


def md_meta(text):
    m = re.match(r"# (.+)\n", text)
    page_title = m.group(1).strip() if m else "nah docs"
    para = ""
    for block in text.split("\n\n")[1:]:
        block = block.strip()
        if block and not block.startswith(("#", "```", "-", "|", ">")):
            para = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", block)
            para = re.sub(r"[`*_]", "", para).replace("\n", " ")
            break
    return page_title, (para[:157] + "…") if len(para) > 160 else para


def render_doc(src_text, out_rel, eyebrow, current):
    page_title, description = md_meta(src_text)
    body = markdown.markdown(src_text, extensions=["fenced_code", "tables"])
    body = rewrite_md_links(body)
    assert out_rel.endswith("/index.html")
    path = "/" + out_rel[: -len("index.html")]
    out = f"{OUT_DIR}/{out_rel}"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, "w", encoding="utf-8").write(
        page_shell(page_title, eyebrow, body, description, path, current)
    )
    return path


PAGES = []

# /docs/ index from the repo docs README
PAGES.append(render_doc(
    open(f"{DOCS_SRC}/README.md", encoding="utf-8").read(),
    "docs/index.html", "NAH(1) · DOCUMENTATION", "docs",
))

# /docs/guards/ from the exact compiled catalog, under fresh default state
guard_docs, guard_count = generated_guard_docs()
PAGES.append(render_doc(
    guard_docs, "docs/guards/index.html", "NAH(1) · GUARDS", "docs",
))

# topic pages
runtime_slugs = sorted(
    f[:-3] for f in os.listdir(f"{DOCS_SRC}/runtimes") if f.endswith(".md")
)
for f in sorted(os.listdir(DOCS_SRC)):
    if not f.endswith(".md") or f == "README.md":
        continue
    slug = f[:-3]
    text = open(f"{DOCS_SRC}/{f}", encoding="utf-8").read()
    body_extra = None
    page_path = f"docs/{slug}/index.html"
    PAGES.append(render_doc(text, page_path, f"NAH(1) · {slug.upper()}", "docs"))
    if slug == "runtimes":
        # linkify the runtime names to their pages (text stays verbatim)
        p = f"{OUT_DIR}/{page_path}"
        html = open(p, encoding="utf-8").read()
        for r in runtime_slugs:
            html = html.replace(
                f"<li><code>{r}</code>",
                f'<li><a href="/docs/runtimes/{r}/"><code>{r}</code></a>',
                1,
            )
        open(p, "w", encoding="utf-8").write(html)

# runtime pages
for r in runtime_slugs:
    text = open(f"{DOCS_SRC}/runtimes/{r}.md", encoding="utf-8").read()
    PAGES.append(render_doc(
        text, f"docs/runtimes/{r}/index.html", f"NAH(1) · RUNTIMES · {r.upper()}", "docs",
    ))

# /news/ from the changelog, without the Unreleased section: unshipped
# work is not news.
news_src = open(f"{ROOT}/CHANGELOG.md", encoding="utf-8").read()
news_src = re.sub(r"## Unreleased\n.*?(?=\n## )", "", news_src, flags=re.S)
PAGES.append(render_doc(news_src, "news/index.html", "NAH(1) · NEWS", "news"))

# sitemap, now that every page is known
open(f"{OUT_DIR}/sitemap.xml", "w").write(
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    + "<url><loc>https://nahguard.ai/</loc></url>\n"
    + "".join(f"<url><loc>https://nahguard.ai{p}</loc></url>\n" for p in PAGES)
    + "</urlset>\n"
)

print(
    f"index.html {len(doc)} bytes · og.png · title {title!r} · 2 favicons · "
    f"{wasm_note} · {guard_count} generated guards · {len(PAGES)} docs/news pages"
)
