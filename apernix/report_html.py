# ruff: noqa: E501  (il CSS è più leggibile su righe lunghe)
"""Report HTML: un'unica pagina autonoma (niente file esterni, niente JavaScript), da aprire con
un doppio clic, leggibile anche da chi non è tecnico. Palette "Muschio e sangue", chiaro e scuro
seguendo le impostazioni del sistema.

Tutto il testo che arriva dall'analisi (titoli, evidenze, URL) è dato non fidato: viene sempre
passato da html.escape, e la pagina vieta script e risorse esterne (Content-Security-Policy).
"""

from __future__ import annotations

import base64
from functools import lru_cache
from html import escape
from pathlib import Path

from apernix.i18n import t
from apernix.models import LEVELS, risk_level
from apernix.palette import DARK, LIGHT

LEVEL_ORDER = ("critical", "high", "medium", "low")


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _vars(p: dict) -> str:
    return ";".join(f"--{k}:{v}" for k, v in p.items())


CSS = """
:root{%(light)s;--line:color-mix(in srgb,var(--muted) 24%%,transparent);--chip:color-mix(in srgb,var(--muted) 12%%,transparent);--shadow:0 1px 2px rgba(0,0,0,.06),0 8px 24px -12px rgba(0,0,0,.18)}
@media (prefers-color-scheme:dark){:root{%(dark)s;--shadow:0 1px 2px rgba(0,0,0,.4),0 10px 28px -14px rgba(0,0,0,.7)}}
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:16px}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.shell{display:grid;grid-template-columns:268px minmax(0,1fr);gap:clamp(20px,3vw,48px);max-width:1760px;margin:0 auto;padding:0 clamp(16px,3vw,56px)}
main{min-width:0;padding:36px 0 72px}
h1,h2,h3{line-height:1.25;font-weight:650;margin:0}
h2{font-size:23px;margin:56px 0 4px;display:flex;align-items:center;gap:10px}
h2::before{content:"";width:5px;height:22px;border-radius:3px;background:var(--primary)}
h2+p.lead{margin:0 0 20px;color:var(--muted)}
a{color:var(--primary)}
code,.mono{font-family:ui-monospace,"JetBrains Mono","DejaVu Sans Mono",monospace;font-size:13.5px}
.small{font-size:13px}
.muted{color:var(--muted)} .ok{color:var(--ok)} .warn{color:var(--medium)}
.side{position:sticky;top:0;align-self:start;height:100vh;overflow:auto;padding:28px 0;display:flex;flex-direction:column;gap:22px}
.brand-block{display:flex;align-items:center;gap:12px}
.brand-block .logo{width:56px;height:56px;object-fit:contain;flex:none}
.brand{font:800 17px/1 ui-monospace,monospace;letter-spacing:.2em;color:var(--primary)}
.toc{display:flex;flex-direction:column;gap:2px}
.toc a{display:flex;justify-content:space-between;align-items:center;gap:8px;color:var(--muted);text-decoration:none;font-size:15px;padding:9px 12px;border-radius:10px;transition:background .12s,color .12s}
.toc a:hover{background:var(--chip);color:var(--text)}
.toc a b{font-size:12px;font-weight:700;background:var(--chip);color:var(--text);border-radius:999px;padding:0 8px;min-width:22px;text-align:center}
.side-meta{margin-top:auto;display:grid;gap:8px;font-size:13px;color:var(--muted);border-top:1px solid var(--line);padding-top:16px}
.side-meta div{display:flex;justify-content:space-between;gap:10px}
.side-meta b{color:var(--text);font-weight:600;text-align:right}
.top{padding-bottom:22px;border-bottom:1px solid var(--line)}
.eyebrow{font-size:12.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--primary);font-weight:700}
.top h1{font-size:clamp(28px,3.2vw,40px);margin-top:6px}
.top .url{color:var(--muted);word-break:break-all;margin-top:4px}
.hero{margin-top:26px;padding:clamp(20px,2.4vw,32px);border-radius:20px;background:var(--surface);box-shadow:var(--shadow);display:grid;grid-template-columns:auto minmax(0,1fr) minmax(260px,360px);gap:clamp(20px,3vw,40px);align-items:center;border:1px solid var(--line);border-top:5px solid var(--vcolor)}
.grade{text-align:center}
.ring{width:148px;height:148px;border-radius:50%;margin:0 auto;display:grid;place-items:center;background:conic-gradient(var(--c) calc(var(--p)*1%%),var(--faint) 0)}
.ring-in{width:116px;height:116px;border-radius:50%;background:var(--surface);display:grid;place-items:center}
.grade .letter{font-size:60px;font-weight:800;color:var(--c);line-height:1}
.grade .pts{margin-top:10px;color:var(--muted);font-size:13px}
.vtext h2{margin:0;font-size:clamp(22px,2.2vw,28px);color:var(--vcolor);display:block}
.vtext h2::before{display:none}
.vtext p{margin:8px 0 0;max-width:62ch}
.insight{display:flex;flex-direction:column;gap:2px;font-weight:600}
.kpis{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.kpi{border-radius:14px;padding:12px 16px;background:color-mix(in srgb,var(--c) 12%%,transparent);border:1px solid color-mix(in srgb,var(--c) 30%%,transparent)}
.kpi b{display:block;font-size:30px;line-height:1.1;color:var(--c)}
.kpi span{font-size:13.5px;color:var(--muted)}
.kpi.zero{--c:var(--muted);opacity:.65}
.plan{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:14px;align-items:start}
.col{background:var(--surface);border-radius:16px;padding:16px 18px;box-shadow:var(--shadow);border:1px solid var(--line)}
.col h3{font-size:16px;display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}
.col h3 span{font-size:12.5px;color:var(--muted);font-weight:400}
.col-now h3{color:var(--critical)} .col-soon h3{color:var(--medium)} .col-later h3{color:var(--muted)} .col-review h3{color:var(--accent)}
.step{display:flex;gap:10px;padding:11px 8px;margin:0 -8px;border-top:1px solid var(--line);color:var(--text);text-decoration:none;line-height:1.45;border-radius:10px}
.step:hover{background:var(--chip)}
.step:hover b{color:var(--primary)}
.box-ck{flex:none;width:16px;height:16px;margin-top:3px;border:2px solid var(--c);border-radius:5px}
.tag{display:inline-block;margin:4px 6px 0 0;font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:0 9px}
ul.good{list-style:none;padding:18px 22px;margin:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:8px 24px;background:var(--surface);border-radius:16px;box-shadow:var(--shadow);border:1px solid var(--line)}
ul.good li{padding-left:28px;position:relative}
ul.good li::before{content:"✔";position:absolute;left:4px;color:var(--ok);font-weight:700}
h3.cat{margin:30px 0 12px;font-size:17px;display:flex;align-items:center;gap:10px}
h3.cat .muted{background:var(--chip);border-radius:999px;padding:0 10px;font-size:13px}
.why{background:color-mix(in srgb,var(--c) 8%%,transparent);border-radius:12px;padding:12px 16px}
.fixbox{border-left:3px solid var(--ok);padding:2px 0 2px 14px}
.cols{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
.pcard h3{font-size:17px}
.badge{display:inline-block;padding:1px 10px;border-radius:999px;font-size:12.5px;font-weight:650;color:var(--c);background:color-mix(in srgb,var(--c) 15%%,transparent);white-space:nowrap}
.badge.full{background:var(--c);color:#fff}
.lv-critical{--c:var(--critical)} .lv-high{--c:var(--high)} .lv-medium{--c:var(--medium)} .lv-low{--c:var(--low)} .lv-ok{--c:var(--ok)}
.matrix{display:grid;grid-template-columns:auto repeat(5,minmax(48px,64px));gap:5px;align-items:center;font-size:13px}
.matrix .cell{height:48px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;background:color-mix(in srgb,var(--c) 14%%,transparent);color:var(--c)}
.matrix .cell.has{background:var(--c);color:#fff;font-size:17px}
.matrix .ax{color:var(--muted);text-align:center}
.mwrap{display:flex;gap:40px;flex-wrap:wrap;align-items:center;background:var(--surface);border-radius:16px;padding:22px 26px;box-shadow:var(--shadow);border:1px solid var(--line)}
.mexp{max-width:480px;color:var(--muted);font-size:15px}
.mexp b{color:var(--text)}
.twrap{overflow-x:auto;border-radius:16px;box-shadow:var(--shadow);border:1px solid var(--line);background:var(--surface)}
table{width:100%%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-weight:650;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em;padding:12px 14px;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--muted) 8%%,transparent);white-space:nowrap}
td{padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:hover td{background:color-mix(in srgb,var(--muted) 6%%,transparent)}
tr:last-child td{border-bottom:0}
td.num{text-align:center;white-space:nowrap}
td .ev{color:var(--muted);font-size:13px;word-break:break-word}
td.el{max-width:240px;word-break:break-all;overflow-wrap:anywhere}
table td:nth-child(3){min-width:220px}
table td:nth-child(4){max-width:340px}
details.f{background:var(--surface);border-radius:16px;margin-bottom:12px;border:1px solid var(--line);border-left:5px solid var(--c);box-shadow:var(--shadow)}
details.f summary{cursor:pointer;list-style:none;padding:15px 20px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
details.f summary::-webkit-details-marker{display:none}
details.f summary::before{content:"▸";color:var(--muted);transition:transform .15s}
details.f[open] summary::before{transform:rotate(90deg)}
details.f summary:hover{background:color-mix(in srgb,var(--muted) 5%%,transparent);border-radius:16px}
details.f summary .t{font-weight:600;flex:1;min-width:240px}
details.f .body{padding:2px 22px 20px 44px;display:grid;gap:14px}
.meter{flex:none;width:72px;height:6px;border-radius:3px;background:var(--faint);overflow:hidden}
.meter i{display:block;height:100%%;background:var(--c)}
.k{color:var(--primary);font-weight:650;font-size:12.5px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}
ul.evl{margin:4px 0 0;padding-left:18px}
ul.evl li{word-break:break-word}
.grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;align-items:start}
.box{background:var(--surface);border-radius:16px;padding:18px 20px;box-shadow:var(--shadow);border:1px solid var(--line)}
.box h3{font-size:14px;margin-bottom:10px;color:var(--primary);text-transform:uppercase;letter-spacing:.05em}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{background:var(--chip);border-radius:999px;padding:2px 11px;font-size:13.5px}
.src{display:flex;justify-content:space-between;border-bottom:1px solid var(--line);padding:7px 0}
.src:last-child{border-bottom:0}
.howto{color:var(--muted)} .howto b{color:var(--text)}
footer{margin-top:64px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:18px;display:flex;gap:12px;align-items:center}
footer .logo{width:28px;height:28px;object-fit:contain}
@media (max-width:1180px){.shell{grid-template-columns:1fr;gap:0}.side{position:static;height:auto;padding:20px 0 0;overflow:visible}.toc{flex-direction:row;flex-wrap:wrap}.side-meta{display:none}.hero{grid-template-columns:auto minmax(0,1fr)}.kpis{grid-column:1/-1;grid-template-columns:repeat(4,minmax(0,1fr))}}
@media (max-width:760px){.hero{grid-template-columns:1fr;text-align:left}.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.cols{grid-template-columns:1fr}.grade{text-align:left}.ring{margin:0}}
@media print{.side{display:none}.shell{display:block;padding:0}body{background:#fff;color:#111}details.f{break-inside:avoid}details.f .body{display:grid}.hero,.col,.box,.twrap,details.f,ul.good,.mwrap{background:#fff;border:1px solid #ddd;box-shadow:none}}
"""


WEB_CHECKS = ("WEB-HTTP-001", "WEB-HDR-HSTS", "WEB-HDR-CSP", "WEB-HDR-XFO", "WEB-HDR-XCTO", "WEB-HDR-REF",
              "WEB-DISC-001", "WEB-CK-HTTPONLY", "WEB-CK-SECURE", "WEB-CK-SAMESITE", "WEB-EXP-GIT", "WEB-EXP-ENV",
              "WEB-EXP-CONF", "WEB-EXP-DUMP", "WEB-EXP-DEBUG", "WEB-EXP-STATUS", "WEB-EXP-DSSTORE", "WEB-ERR-001",
              "WEB-LIST-001", "WEB-CORS-001", "WEB-METH-001")
NET_CHECKS = ("NET-DB-EXPOSED", "NET-DOCKER-API", "NET-CLEARTEXT")
CATEGORIES = (
    ("chain", ("CHAIN-",)),
    ("secrets", ("SEC-", "LOG-SECRETS")),
    ("code", ("SAST-",)),
    ("deps", ("DEP-",)),
    ("host", ("NET-SURFACE", "NUC-ssh-")),
    ("config", ("CFG-", "CTR-", "DB-")),
    ("logs", ("LOG-",)),
    ("exposure", ("WEB-EXP-", "WEB-LIST-", "WEB-ERR-")),
    ("network", ("NET-",)),
    ("known", ("NUC-",)),
    ("transport", ("WEB-HTTP-", "WEB-HDR-HSTS", "WEB-TLS-", "WEB-CK-SECURE")),
    ("session", ("WEB-CK-",)),
    ("browser", ("WEB-HDR-", "WEB-CORS-")),
    ("info", ("WEB-DISC-", "WEB-METH-")),
)
QUICK = ("WEB-HDR-XFO", "WEB-HDR-XCTO", "WEB-HDR-REF", "WEB-HDR-HSTS", "WEB-DISC-", "WEB-CK-", "WEB-EXP-",
         "WEB-LIST-", "WEB-METH-", "NET-DOCKER-API")
LONG = ("NUC-",)
# (penalità per problema, tetto): più problemi dello stesso livello pesano sempre meno.
# Senza critici il voto non scende sotto 40 (D): la F è riservata a chi ha problemi critici.
PENALTY = {"critical": (25, 100), "high": (7, 35), "medium": (2, 20), "low": (0.5, 5)}


def category(check: str) -> str:
    for name, prefixes in CATEGORIES:
        if check.startswith(prefixes):
            return name
    return "other"


def effort(check: str) -> str:
    if check.startswith(QUICK):
        return "quick"
    if check.startswith(LONG):
        return "long"
    return "medium"


def why(f: dict) -> str:
    check = f["check"]
    for key in (f"{check}.why", *(f"{g}.why" for g in ("NUC", "SAST", "DEP", "CFG", "SEC") if check.startswith(g + "-"))):
        text = t(key)
        if text != key:
            return text
    return ""


def score(findings: list[dict]) -> tuple[int, str, str]:
    """Voto da 0 a 100 e lettera, come i voti dei test SSL: aiuta a capire al volo."""
    count = {lvl: sum(1 for f in findings if f["level"] == lvl and f.get("scored", True)) for lvl in PENALTY}
    value = max(0, round(100 - sum(min(n * PENALTY[lvl][0], PENALTY[lvl][1]) for lvl, n in count.items())))
    for limit, letter, role in ((90, "A", "ok"), (75, "B", "ok"), (60, "C", "medium"), (40, "D", "high")):
        if value >= limit:
            return value, letter, role
    return value, "F", "critical"


def passed_checks(doc: dict) -> list[str]:
    """Controlli eseguiti senza trovare problemi: anche questo è un risultato da mostrare."""
    found = {f["check"] for f in doc["findings"]}
    status = {s.get("name"): s.get("status") for s in doc.get("sources", []) if isinstance(s, dict)}
    https = all(str(u).lower().startswith("https://") for u in doc["targets"]) and doc["targets"]
    ok: list[str] = []
    if status.get("apernix-web") == "ok":
        # HTTPS e HSTS si dichiarano "a posto" solo se il bersaglio è davvero in HTTPS
        ok += [c for c in WEB_CHECKS if c not in found and not (c in ("WEB-HDR-HSTS", "WEB-HTTP-001") and not https)]
    if status.get("nmap") == "ok":
        ok += [c for c in NET_CHECKS if c not in found]
    if status.get("nuclei") == "ok" and not any(c.startswith("NUC-") for c in found):
        ok.append("NUC")
    for src, prefixes, label in (("semgrep", ("SAST-",), "SAST"), ("trivy", ("DEP-",), "DEP"),
                                 ("trivy", ("SEC-",), "SEC"), ("docker", ("CTR-",), "CTR"),
                                 ("postgres", ("DB-",), "DB"), ("logs", ("LOG-",), "LOG")):
        if status.get(src) == "ok" and not any(c.startswith(prefixes) for c in found) and label not in ok:
            ok.append(label)
    return ok


def _verdict(doc: dict, letter: str = "") -> tuple[str, str, str]:
    """Titolo e testo seguono il voto: con A o B non si parla di "problemi seri" se i critici/alti non ci sono."""
    s = doc["summary"]
    if letter in ("A", "B") and not (s.get("critical") or s.get("high")):
        if not any(s.get(lvl) for lvl in LEVEL_ORDER):
            return "ok", t("html.verdict.none"), t("html.verdict.none.text")
        k = letter.lower()
        return "ok", t(f"html.verdict.{k}"), t(f"html.verdict.{k}.text")
    for lvl in LEVEL_ORDER:
        if s.get(lvl):
            n = s[lvl]
            what = t(f"plural.{lvl}.{'1' if n == 1 else 'n'}")
            return lvl, t(f"html.verdict.{lvl}", n=n, what=what), t(f"html.verdict.{lvl}.text")
    return "ok", t("html.verdict.none"), t("html.verdict.none.text")


def _badge(f: dict, full: bool = False) -> str:
    cls = "badge full" if full and f["level"] == "critical" else "badge"
    return f'<span class="{cls} lv-{_e(f["level"])}">{_e(f["risk"])} · {_e(t("level." + f["level"]))}</span>'


def _matrix(findings: list[dict]) -> str:
    counts: dict[tuple[int, int], int] = {}
    for f in findings:
        key = (f["impact"], f["probability"])
        counts[key] = counts.get(key, 0) + 1
    rows = []
    for p in range(5, 0, -1):
        cells = [f'<div class="ax">{p}</div>']
        for i in range(1, 6):
            n = counts.get((i, p), 0)
            lvl = risk_level(i * p)
            title = _e(t("html.matrix.cell", i=i, p=p, r=i * p, n=n))
            cells.append(f'<div class="cell lv-{lvl}{" has" if n else ""}" title="{title}">{n or i * p}</div>')
        rows.append("".join(cells))
    axis = '<div class="ax"></div>' + "".join(f'<div class="ax">{i}</div>' for i in range(1, 6))
    return (f'<div><div class="muted small">{_e(t("html.matrix.prob"))} ↑</div>'
            f'<div class="matrix">{"".join(rows)}{axis}</div>'
            f'<div class="muted small" style="text-align:right">{_e(t("html.matrix.impact"))} →</div></div>')


@lru_cache(maxsize=1)
def logo_uri() -> str:
    """Il logo come data URI: il report resta un file unico, senza risorse esterne. Se manca, il report esce senza."""
    try:
        data = (Path(__file__).parent / "assets" / "logo.png").read_bytes()
    except OSError:
        return ""
    return "data:image/png;base64," + base64.b64encode(data).decode("ascii") if data[:8] == b"\x89PNG\r\n\x1a\n" else ""


def _side(doc: dict, name: str, ok_count: int) -> list[str]:
    """Barra laterale fissa: logo, indice con i numeri e i dati della scansione."""
    meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    logo = f'<img class="logo" src="{logo_uri()}" alt="" width="56" height="56">' if logo_uri() else ""
    n = len(doc["findings"])
    nav = [("plan", "html.nav.plan", ""), ("good", "html.nav.good", ok_count or ""), ("topics", "html.nav.topics", n or ""),
           ("matrix", "html.nav.matrix", ""), ("table", "html.nav.table", n or ""), ("scope", "html.nav.scope", "")]
    links = "".join(f'<a href="#{a}"><span>{_e(t(k))}</span>{f"<b>{c}</b>" if c != "" else ""}</a>' for a, k, c in nav)
    rows = [(t("html.date"), doc["generated"].replace("T", " ")[:16] + " UTC")]
    for key, label in (("profile", "html.profile"), ("duration", "html.duration")):
        if meta.get(key):
            rows.append((t(label), str(meta[key])))
    rows.append((t("html.requests"), str(doc.get("requests", 0))))
    info = "".join(f"<div><span>{_e(k)}</span><b>{_e(v)}</b></div>" for k, v in rows)
    return [f'<aside class="side"><div class="brand-block">{logo}<div class="brand">APERNIX</div></div>'
            f'<nav class="toc">{links}</nav><div class="side-meta">{info}</div></aside>']


def _head(doc: dict, name: str) -> list[str]:
    target = (doc["targets"] or ["?"])[0]
    return [f'<header class="top"><div class="eyebrow">{_e(t("html.eyebrow"))}</div><h1>{_e(name)}</h1>'
            f'<div class="url mono">{_e(target)}</div></header>']


def _hero(doc: dict, ok_count: int) -> list[str]:
    findings = doc["findings"]
    value, letter, role = score(findings)
    vlevel, vtitle, vtext = _verdict(doc, letter)
    vcolor = "var(--ok)" if vlevel == "ok" else f"var(--{vlevel})"
    counted = [f for f in findings if f.get("scored", True)]        # solo i problemi che pesano sul voto
    total = sum(f["risk"] for f in counted)
    insight = ""
    if len(counted) >= 3 and total:
        n = min(3, len(counted) - 1)
        pct = round(100 * sum(f["risk"] for f in counted[:n]) / total)
        insight = t("html.insight.top", n=n, pct=pct)
    key = "html.insight.ok.good" if letter in ("A", "B") else "html.insight.ok"
    good = t(key, n=ok_count, total=ok_count + len({f["check"] for f in findings})) if ok_count else ""
    out = [f'<section class="hero" style="--vcolor:{vcolor}"><div class="grade lv-{role}">'
           f'<div class="ring" style="--p:{value}"><div class="ring-in"><div class="letter">{letter}</div></div></div>'
           f'<div class="pts">{value} / 100 · {_e(t("html.score"))}</div></div>'
           f'<div class="vtext"><h2>{_e(vtitle)}</h2><p>{_e(vtext)}</p>']
    if insight or good:
        out.append('<p class="insight">' + "".join(f"<span>{_e(x)}</span>" for x in (insight, good) if x) + "</p>")
    if doc.get("unscored"):
        out.append(f'<p class="muted small">{_e(t("html.unscored", n=doc["unscored"]))}</p>')
    out.append('</div><div class="kpis">')
    for lvl in LEVEL_ORDER:
        n = doc["summary"].get(lvl, 0)
        out.append(f'<div class="kpi lv-{lvl}{"" if n else " zero"}"><b>{n}</b><span>{_e(t("html.count." + lvl))}</span></div>')
    out.append("</div></section>")
    return out


def _unscored_tag(f: dict) -> str:
    return "" if f.get("scored", True) else f'<span class="tag">{_e(t("html.unscored.tag"))}</span>'


def _plan(findings: list[dict]) -> list[str]:
    """Da fare ora / presto / con calma contano solo i problemi che pesano sul voto; il resto va in "Da verificare"."""
    scored = [(i, f) for i, f in enumerate(findings, 1) if f.get("scored", True)]
    review = [(i, f) for i, f in enumerate(findings, 1) if not f.get("scored", True)]
    groups = (("now", [x for x in scored if x[1]["level"] in ("critical", "high")]),
              ("soon", [x for x in scored if x[1]["level"] == "medium"]),
              ("later", [x for x in scored if x[1]["level"] == "low"]),
              ("review", review))
    out = [f'<h2 id="plan">{_e(t("html.plan"))}</h2><p class="lead">{_e(t("html.plan.lead"))}</p><div class="plan">']
    for key, items in groups:
        if key == "review" and not items:
            continue
        out.append(f'<div class="col col-{key}"><h3>{_e(t("html.plan." + key))}'
                   f'<span>{_e(t("html.plan." + key + ".sub"))}</span></h3>')
        if not items:
            out.append(f'<div class="muted small">{_e(t("html.plan.empty"))}</div>')
        for i, f in items:
            out.append(f'<a class="step lv-{_e(f["level"])}" href="#f{i}"><span class="box-ck"></span><span>'
                       f'<b>{_e(f["title"])}</b><br><span class="muted small">{_e(f["remediation"])}</span><br>'
                       f'<span class="tag">{_e(t("effort." + effort(f["check"])))}</span></span></a>')
        out.append("</div>")
    out.append("</div>")
    return out


def _good(ok: list[str]) -> list[str]:
    out = [f'<h2 id="good">{_e(t("html.good"))}</h2><p class="lead">{_e(t("html.good.lead"))}</p>']
    if not ok:
        return out + [f'<div class="box muted">{_e(t("html.not_run"))}</div>']
    items = "".join(f'<li>{_e(t("NUC.ok" if c == "NUC" else c + ".ok"))}</li>' for c in ok)
    return out + [f'<ul class="good">{items}</ul>']


def _topics(findings: list[dict]) -> list[str]:
    out = [f'<h2 id="topics">{_e(t("html.topics"))}</h2><p class="lead">{_e(t("html.topics.lead"))}</p>']
    if not findings:
        return out + [f'<div class="box">{_e(t("report.none"))}</div>']
    order = [c for c, _ in CATEGORIES] + ["other"]
    groups: dict[str, list] = {}
    for i, f in enumerate(findings, 1):
        groups.setdefault(category(f["check"]), []).append((i, f))
    ranked = sorted(groups.items(), key=lambda kv: (-max(f["risk"] for _, f in kv[1]), order.index(kv[0])))
    for cat, items in ranked:
        out.append(f'<h3 class="cat">{_e(t("cat." + cat))} <span class="muted">{len(items)}</span></h3>')
        for i, f in items:
            evl = "".join(f'<li class="mono">{_e(e)}</li>' for e in f["evidence"]) or "<li>-</li>"
            w = why(f)
            out.append(
                f'<details class="f lv-{_e(f["level"])}" id="f{i}"{" open" if f["level"] in ("critical", "high") else ""}>'
                f'<summary>{_badge(f, True)}<span class="meter" aria-hidden="true"><i style="width:{min(100, f["risk"] * 4)}%"></i></span>'
                f'<span class="t">{_e(f["title"])}</span>{_unscored_tag(f)}'
                f'<span class="tag">{_e(t("effort." + effort(f["check"])))}</span></summary><div class="body">'
                + (f'<div class="why"><div class="k">{_e(t("html.why"))}</div>{_e(w)}</div>' if w else "")
                + f'<div class="fixbox"><div class="k">{_e(t("html.todo"))}</div>{_e(f["remediation"])}</div>'
                f'<div class="cols"><div><div class="k">{_e(t("html.where"))}</div>'
                f'<span class="mono">{_e(f["element"])}</span></div>'
                f'<div><div class="k">{_e(t("html.calc"))}</div>{_e(t("table.impact"))} {f["impact"]} × '
                f'{_e(t("table.probability"))} {f["probability"]} = <b>{f["risk"]}</b> '
                f'({_e(t("level." + f["level"]))})</div>'
                f'<div><div class="k">{_e(t("table.pt"))}</div>{_e(t("pt." + f["pt"]))}</div></div>'
                f'<div><div class="k">{_e(t("table.evidence"))}</div><ul class="evl">{evl}</ul></div>'
                f'<div class="muted small">{_e(t("table.source"))}: {_e(f["source"])} · {_e(f["check"])}</div>'
                "</div></details>")
    return out


def _table(findings: list[dict]) -> list[str]:
    out = [f'<h2 id="table">{_e(t("html.table.tech"))}</h2><p class="lead">{_e(t("html.table.tech.lead"))}</p>']
    if not findings:
        return out + [f'<div class="box">{_e(t("report.none"))}</div>']
    heads = ["#", "table.element", "table.problem", "table.evidence", "table.pt", "table.impact",
             "table.probability", "table.risk", "table.source"]
    out.append('<div class="twrap"><table><thead><tr>' +
               "".join(f"<th>{_e(h if h == '#' else t(h))}</th>" for h in heads) + "</tr></thead><tbody>")
    for i, f in enumerate(findings, 1):
        shown = [e if len(e) <= 110 else e[:109] + "…" for e in f["evidence"][:2]]
        ev = "<br>".join(_e(e) for e in shown)
        if len(f["evidence"]) > 2:
            ev += f'<br><a href="#f{i}">{_e(t("html.more", n=len(f["evidence"]) - 2))}</a>'
        out.append(f'<tr><td class="num">{i}</td><td class="mono el" title="{_e(f["element"])}">{_e(f["element"])}</td>'
                   f'<td><a href="#f{i}">{_e(f["title"])}</a>{_unscored_tag(f)}</td><td><div class="ev">{ev}</div></td>'
                   f'<td>{_e(t("pt." + f["pt"]))}</td><td class="num">{f["impact"]}</td>'
                   f'<td class="num">{f["probability"]}</td><td class="num">{_badge(f)}</td>'
                   f'<td class="muted">{_e(f["source"])}</td></tr>')
    return out + ["</tbody></table></div>"]


def _scope(doc: dict) -> list[str]:
    out = [f'<h2 id="scope">{_e(t("html.scope"))}</h2><p class="lead">{_e(t("html.scope.lead"))}</p>'
           '<div class="grid3">']
    tech = []
    for fp in doc.get("fingerprint", []):
        if isinstance(fp, dict):
            tech += [x for x in fp.get("technologies", []) if isinstance(x, str)]
    uniq = {x.replace(" (probabile)", "").lower(): x for x in reversed(tech)}      # "Flask (probabile)" = "flask"
    chips = "".join(f'<span class="chip">{_e(x)}</span>' for x in reversed(list(uniq.values()))) or \
        f'<span class="muted">{_e(t("html.none"))}</span>'
    out.append(f'<div class="box"><h3>{_e(t("report.fingerprint"))}</h3><div class="chips">{chips}</div></div>')
    svc = []
    for host, items in (doc.get("services") or {}).items():
        if isinstance(items, list):
            lines = "".join(f'<span class="chip mono">{_e(x)}</span>' for x in items if isinstance(x, str)) or \
                f'<span class="muted">{_e(t("report.no_ports"))}</span>'
            svc.append(f'<div class="muted mono small">{_e(host)}</div><div class="chips">{lines}</div>')
    out.append(f'<div class="box"><h3>{_e(t("report.services"))}</h3>'
               f'{"".join(svc) or "<span class=muted>" + _e(t("html.not_run")) + "</span>"}</div>')
    srcs = []
    for src in doc.get("sources", []):
        if not isinstance(src, dict):
            continue
        st = str(src.get("status", ""))
        cls = "ok" if st == "ok" else ("muted" if st == "skipped" else "warn")
        label = t("source." + st) if st.replace("_", "").isalpha() else "?"
        srcs.append(f'<div class="src"><span class="mono">{_e(src.get("name", "?"))}</span>'
                    f'<span class="{cls}">{_e(label)}</span></div>')
    out.append(f'<div class="box"><h3>{_e(t("report.sources"))}</h3>{"".join(srcs)}</div>')
    out.append(f'<div class="box howto"><h3>{_e(t("html.howto"))}</h3>{t("html.howto.text")}</div></div>')
    return out


def css() -> str:
    return CSS.replace("%(light)s", _vars(LIGHT)).replace("%(dark)s", _vars(DARK)).replace("%%", "%")


def to_html(doc: dict) -> str:
    findings = doc["findings"]
    meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    name = meta.get("name") or (doc["targets"] or ["?"])[0]
    ok = passed_checks(doc)
    out = [f'<!DOCTYPE html><html lang="it"><head><meta charset="utf-8">'
           f'<meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:">'
           f'<meta name="referrer" content="no-referrer">'
           f'<title>{_e(t("html.title"))} · {_e(name)}</title>'
           f'<style>{css()}</style></head><body><div class="shell">']
    out += _side(doc, name, len(ok))
    out.append('<main>')
    out += _head(doc, name)
    out += _hero(doc, len(ok))
    out += _plan(findings)
    out += _good(ok)
    out += _topics(findings)
    out += [f'<h2 id="matrix">{_e(t("html.matrix"))}</h2><p class="lead">{_e(t("html.matrix.lead"))}</p>'
            f'<div class="mwrap">{_matrix(findings)}<div class="mexp">{t("html.matrix.explain")}</div></div>']
    out += _table(findings)
    out += _scope(doc)
    out.append(f'<footer>{_e(t("html.footer", version=doc.get("version", "?")))}</footer></main></div></body></html>')
    return "".join(out)


assert set(LEVEL_ORDER) == set(LEVELS)
