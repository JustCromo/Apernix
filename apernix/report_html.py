# ruff: noqa: E501  (il CSS è più leggibile su righe lunghe)
"""Report HTML: un'unica pagina autonoma (niente file esterni, niente JavaScript), da aprire con
un doppio clic, leggibile anche da chi non è tecnico. Palette "Muschio e sangue", chiaro e scuro
seguendo le impostazioni del sistema.

Tutto il testo che arriva dall'analisi (titoli, evidenze, URL) è dato non fidato: viene sempre
passato da html.escape, e la pagina vieta script e risorse esterne (Content-Security-Policy).
"""

from __future__ import annotations

from html import escape

from apernix.i18n import t
from apernix.models import LEVELS, risk_level
from apernix.palette import DARK, LIGHT

LEVEL_ORDER = ("critical", "high", "medium", "low")


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _vars(p: dict) -> str:
    return ";".join(f"--{k}:{v}" for k, v in p.items())


CSS = """
:root{%(light)s;--line:color-mix(in srgb,var(--muted) 28%%,transparent);--chip:color-mix(in srgb,var(--muted) 12%%,transparent)}
@media (prefers-color-scheme:dark){:root{%(dark)s}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:32px 24px 64px}
h1,h2,h3{line-height:1.25;font-weight:600;margin:0}
h2{font-size:21px;margin:48px 0 6px}
h2+p.lead{margin:0 0 18px;color:var(--muted)}
a{color:var(--primary)}
code,.mono{font-family:ui-monospace,"JetBrains Mono","DejaVu Sans Mono",monospace;font-size:13.5px}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:18px}
.brand{font:700 15px/1 ui-monospace,monospace;letter-spacing:.18em;color:var(--primary)}
.top h1{font-size:30px;margin-top:10px}
.top .url{color:var(--muted);word-break:break-all}
.meta{display:flex;gap:18px;flex-wrap:wrap;color:var(--muted);font-size:14px}
.meta b{color:var(--text);font-weight:600}
.toc{position:sticky;top:0;z-index:5;display:flex;gap:4px;flex-wrap:wrap;padding:10px 0;background:var(--bg);border-bottom:1px solid var(--line)}
.toc a{color:var(--muted);text-decoration:none;font-size:14px;padding:4px 10px;border-radius:999px}
.toc a:hover{background:var(--chip);color:var(--text)}
.small{font-size:13px}
.hero{margin-top:24px;padding:24px;border-radius:16px;background:var(--surface);display:flex;gap:28px;align-items:center;border-left:6px solid var(--vcolor)}
.grade{min-width:120px;text-align:center}
.grade .letter{width:96px;height:96px;margin:0 auto;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:52px;font-weight:800;color:var(--c);border:6px solid var(--c)}
.grade .pts{margin-top:8px;color:var(--muted);font-size:13px}
.vtext h2{margin:0;font-size:25px;color:var(--vcolor)}
.vtext p{margin:6px 0 0}
.insight{display:flex;flex-direction:column;gap:2px;font-weight:600}
.counts{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.count{padding:3px 12px;border-radius:999px;background:color-mix(in srgb,var(--c) 15%%,transparent);color:var(--c);font-size:14px}
.count.zero{--c:var(--muted);opacity:.7}
.plan{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.col{background:var(--surface);border-radius:12px;padding:14px 16px}
.col h3{font-size:16px;display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}
.col h3 span{font-size:12.5px;color:var(--muted);font-weight:400}
.col-now h3{color:var(--critical)} .col-soon h3{color:var(--medium)} .col-later h3{color:var(--muted)}
.step{display:flex;gap:10px;padding:10px 0;border-top:1px solid var(--line);color:var(--text);text-decoration:none;line-height:1.45}
.step:hover b{color:var(--primary)}
.box-ck{flex:none;width:16px;height:16px;margin-top:3px;border:2px solid var(--c);border-radius:4px}
.tag{display:inline-block;margin-top:4px;font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:0 8px}
ul.good{list-style:none;padding:0;margin:0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px 18px}
ul.good li{padding-left:26px;position:relative}
ul.good li::before{content:"✔";position:absolute;left:4px;color:var(--ok);font-weight:700}
h3.cat{margin:28px 0 10px;font-size:17px}
.why{background:color-mix(in srgb,var(--c) 8%%,transparent);border-radius:10px;padding:10px 14px}
.fixbox{border-left:3px solid var(--ok);padding-left:12px}
.cols{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.verdict{margin-top:28px;padding:26px 28px;border-radius:14px;background:var(--surface);border-left:6px solid var(--vcolor)}
.verdict h2{margin:0;font-size:26px;color:var(--vcolor)}
.verdict p{margin:8px 0 0;max-width:760px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:16px}
.card{background:var(--surface);border-radius:12px;padding:14px 16px;border-top:4px solid var(--c)}
.card .n{font-size:32px;font-weight:700;color:var(--c);line-height:1.1}
.card .l{color:var(--muted);font-size:14px}
.card.zero{--c:var(--line)} .card.zero .n{color:var(--muted)}
.prio{display:grid;gap:12px}
.pcard{background:var(--surface);border-radius:12px;padding:18px 20px;display:grid;grid-template-columns:auto 1fr;gap:4px 16px}
.pcard .num{grid-row:span 3;font-size:28px;font-weight:700;color:var(--c);min-width:44px;text-align:center}
.pcard h3{font-size:17px}
.pcard .why{color:var(--muted);font-size:14.5px}
.pcard .fix{font-size:15px}
.pcard .fix b{color:var(--primary)}
.badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12.5px;font-weight:600;color:var(--c);background:color-mix(in srgb,var(--c) 15%%,transparent);white-space:nowrap}
.badge.full{background:var(--c);color:#fff}
.lv-critical{--c:var(--critical)} .lv-high{--c:var(--high)} .lv-medium{--c:var(--medium)} .lv-low{--c:var(--low)}
.matrix{display:grid;grid-template-columns:auto repeat(5,56px);gap:4px;align-items:center;font-size:13px}
.matrix .cell{height:44px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;background:color-mix(in srgb,var(--c) 14%%,transparent);color:var(--c)}
.matrix .cell.has{background:var(--c);color:#fff;font-size:16px}
.matrix .ax{color:var(--muted);text-align:center}
.mwrap{display:flex;gap:32px;flex-wrap:wrap;align-items:center}
.mexp{max-width:420px;color:var(--muted);font-size:15px}
.mexp b{color:var(--text)}
table{width:100%%;border-collapse:collapse;font-size:14px;background:var(--surface);border-radius:12px;overflow:hidden}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12.5px;text-transform:uppercase;letter-spacing:.04em;padding:10px 12px;border-bottom:1px solid var(--line)}
td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
td.num{text-align:center;white-space:nowrap}
td .ev{color:var(--muted);font-size:13px;word-break:break-word}
.twrap{overflow-x:auto;border-radius:12px}
details.f{background:var(--surface);border-radius:12px;margin-bottom:10px;border-left:4px solid var(--c)}
details.f summary{cursor:pointer;list-style:none;padding:14px 18px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
details.f summary::-webkit-details-marker{display:none}
details.f summary::before{content:"▸";color:var(--muted);transition:transform .15s}
details.f[open] summary::before{transform:rotate(90deg)}
details.f summary .t{font-weight:600;flex:1;min-width:240px}
details.f .body{padding:0 18px 16px 42px;display:grid;gap:10px}
.k{color:var(--primary);font-weight:600;font-size:13px;text-transform:uppercase;letter-spacing:.04em}
ul.evl{margin:4px 0 0;padding-left:18px}
ul.evl li{word-break:break-word}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.box{background:var(--surface);border-radius:12px;padding:16px 18px}
.box h3{font-size:15px;margin-bottom:8px;color:var(--primary)}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{background:var(--chip);border-radius:999px;padding:2px 10px;font-size:13.5px}
.src{display:flex;justify-content:space-between;border-bottom:1px solid var(--line);padding:6px 0}
.src:last-child{border-bottom:0}
.ok{color:var(--ok)} .warn{color:var(--medium)} .muted{color:var(--muted)}
.howto{color:var(--muted)} .howto b{color:var(--text)}
footer{margin-top:56px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:16px}
@media (max-width:760px){.grid2,.plan,.cols,ul.good{grid-template-columns:1fr}.hero{flex-direction:column;align-items:flex-start}}
@media print{.toc{display:none}body{background:#fff;color:#111}details.f{break-inside:avoid}details.f .body{display:grid}.verdict,.card,.pcard,.box,table,details.f{background:#fff;border:1px solid #ddd}}
"""


WEB_CHECKS = ("WEB-HTTP-001", "WEB-HDR-HSTS", "WEB-HDR-CSP", "WEB-HDR-XFO", "WEB-HDR-XCTO", "WEB-HDR-REF",
              "WEB-DISC-001", "WEB-CK-HTTPONLY", "WEB-CK-SECURE", "WEB-CK-SAMESITE", "WEB-EXP-GIT", "WEB-EXP-ENV",
              "WEB-EXP-CONF", "WEB-EXP-DUMP", "WEB-EXP-DEBUG", "WEB-EXP-STATUS", "WEB-EXP-DSSTORE", "WEB-ERR-001",
              "WEB-LIST-001", "WEB-CORS-001", "WEB-METH-001")
NET_CHECKS = ("NET-DB-EXPOSED", "NET-DOCKER-API", "NET-CLEARTEXT")
CATEGORIES = (
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
PENALTY = {"critical": 30, "high": 15, "medium": 6, "low": 2}


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
    key = "NUC.why" if f["check"].startswith("NUC-") else f"{f['check']}.why"
    text = t(key)
    return "" if text == key else text


def score(findings: list[dict]) -> tuple[int, str, str]:
    """Voto da 0 a 100 e lettera, come i voti dei test SSL: aiuta a capire al volo."""
    value = max(0, 100 - sum(PENALTY[f["level"]] for f in findings))
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
    return ok


def _verdict(doc: dict) -> tuple[str, str, str]:
    s = doc["summary"]
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


def _head(doc: dict, name: str) -> list[str]:
    target = (doc["targets"] or ["?"])[0]
    meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    out = [f'<header class="top"><div><div class="brand">APERNIX</div><h1>{_e(name)}</h1>'
           f'<div class="url mono">{_e(target)}</div></div><div class="meta">'
           f'<span>{_e(t("html.date"))} <b>{_e(doc["generated"].replace("T", " ")[:16])} UTC</b></span>']
    for key, label in (("profile", "html.profile"), ("duration", "html.duration")):
        if meta.get(key):
            out.append(f'<span>{_e(t(label))} <b>{_e(meta[key])}</b></span>')
    out.append(f'<span>{_e(t("html.requests"))} <b>{_e(doc.get("requests", 0))}</b></span></div></header>')
    nav = [("plan", "html.nav.plan"), ("good", "html.nav.good"), ("topics", "html.nav.topics"),
           ("matrix", "html.nav.matrix"), ("table", "html.nav.table"), ("scope", "html.nav.scope")]
    out.append('<nav class="toc">' + "".join(f'<a href="#{a}">{_e(t(k))}</a>' for a, k in nav) + "</nav>")
    return out


def _hero(doc: dict, ok_count: int) -> list[str]:
    findings = doc["findings"]
    vlevel, vtitle, vtext = _verdict(doc)
    value, letter, role = score(findings)
    vcolor = "var(--ok)" if vlevel == "ok" else f"var(--{vlevel})"
    total = sum(f["risk"] for f in findings)
    insight = ""
    if len(findings) >= 3 and total:
        # quanto rischio si toglie sistemando i primi problemi: dice dove conviene mettere le mani
        n = min(3, len(findings) - 1)
        pct = round(100 * sum(f["risk"] for f in findings[:n]) / total)
        insight = t("html.insight.top", n=n, pct=pct)
    key = "html.insight.ok.good" if letter in ("A", "B") else "html.insight.ok"
    good = t(key, n=ok_count, total=ok_count + len({f["check"] for f in findings})) if ok_count else ""
    out = [f'<section class="hero" style="--vcolor:{vcolor}"><div class="grade lv-{role}" style="--c:var(--{role})">'
           f'<div class="letter">{letter}</div><div class="pts">{value} {_e(t("html.score"))}</div></div>'
           f'<div class="vtext"><h2>{_e(vtitle)}</h2><p>{_e(vtext)}</p>']
    if insight or good:
        out.append('<p class="insight">' + " ".join(f"<span>{_e(x)}</span>" for x in (insight, good) if x) + "</p>")
    out.append('<div class="counts">')
    for lvl in LEVEL_ORDER:
        n = doc["summary"].get(lvl, 0)
        out.append(f'<span class="count lv-{lvl}{"" if n else " zero"}"><b>{n}</b> {_e(t("html.count." + lvl))}</span>')
    out.append("</div></div></section>")
    return out


def _plan(findings: list[dict]) -> list[str]:
    groups = (("now", ("critical", "high")), ("soon", ("medium",)), ("later", ("low",)))
    out = [f'<h2 id="plan">{_e(t("html.plan"))}</h2><p class="lead">{_e(t("html.plan.lead"))}</p><div class="plan">']
    for key, levels in groups:
        items = [(i, f) for i, f in enumerate(findings, 1) if f["level"] in levels]
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
                f'<summary>{_badge(f, True)}<span class="t">{_e(f["title"])}</span>'
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
        ev = "<br>".join(_e(e) for e in f["evidence"])
        out.append(f'<tr><td class="num">{i}</td><td class="mono">{_e(f["element"])}</td>'
                   f'<td><a href="#f{i}">{_e(f["title"])}</a></td><td><div class="ev">{ev}</div></td>'
                   f'<td>{_e(t("pt." + f["pt"]))}</td><td class="num">{f["impact"]}</td>'
                   f'<td class="num">{f["probability"]}</td><td class="num">{_badge(f)}</td>'
                   f'<td class="muted">{_e(f["source"])}</td></tr>')
    return out + ["</tbody></table></div>"]


def _scope(doc: dict) -> list[str]:
    out = [f'<h2 id="scope">{_e(t("html.scope"))}</h2><p class="lead">{_e(t("html.scope.lead"))}</p>'
           '<div class="grid2">']
    tech = []
    for fp in doc.get("fingerprint", []):
        if isinstance(fp, dict):
            tech += [x for x in fp.get("technologies", []) if isinstance(x, str)]
    chips = "".join(f'<span class="chip">{_e(x)}</span>' for x in dict.fromkeys(tech)) or \
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
           f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
           f'<meta name="referrer" content="no-referrer">'
           f'<title>{_e(t("html.title"))} · {_e(name)}</title>'
           f'<style>{css()}</style></head><body><main>']
    out += _head(doc, name)
    out += _hero(doc, len(ok))
    out += _plan(findings)
    out += _good(ok)
    out += _topics(findings)
    out += [f'<h2 id="matrix">{_e(t("html.matrix"))}</h2><p class="lead">{_e(t("html.matrix.lead"))}</p>'
            f'<div class="mwrap">{_matrix(findings)}<div class="mexp">{t("html.matrix.explain")}</div></div>']
    out += _table(findings)
    out += _scope(doc)
    out.append(f'<footer>{_e(t("html.footer", version=doc.get("version", "?")))}</footer></main></body></html>')
    return "".join(out)


assert set(LEVEL_ORDER) == set(LEVELS)
