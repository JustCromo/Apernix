"""Disegno della dashboard su una "tela" astratta (curses nella realtà, una griglia nei test).

Regole di leggibilità: un colore per ogni tipo di informazione (etichette in rosa chiaro, valori
in avorio, metadati spenti, livelli di rischio con il loro colore), barre sottili, un solo
pannello evidenziato alla volta.
"""

from __future__ import annotations

import textwrap

from apernix import __version__
from apernix.dashboard.state import LEVEL_ROLE, P_FINDINGS, P_LIVE, P_PHASES, P_SURFACE, P_TARGETS, PANELS, DashState
from apernix.engine import FLOW, mmss
from apernix.i18n import t
from apernix.term import clean

MIN_W, MIN_H = 80, 22
STATE_ROLE = {"done": "ok", "run": "brand", "fail": "alert", "skip": "faint", "wait": "muted"}


class Glyphs:
    def __init__(self, unicode: bool) -> None:
        u = unicode
        self.h, self.v = ("─", "│") if u else ("-", "|")
        self.tl, self.tr, self.bl, self.br = ("╭", "╮", "╰", "╯") if u else ("+", "+", "+", "+")
        self.full, self.empty = ("━", "─") if u else ("=", "-")
        self.link = "──" if u else "--"
        self.state = ({"wait": "·", "run": "◆", "done": "✔", "skip": "–", "fail": "✖"} if u else
                      {"wait": ".", "run": "*", "done": "+", "skip": "-", "fail": "x"})
        self.sel, self.dot, self.ring = ("▸", "●", "○") if u else (">", "*", "o")


class Canvas:
    """Interfaccia minima: chi disegna davvero implementa put()."""

    def __init__(self, width: int, height: int) -> None:
        self.w, self.h = width, height

    def put(self, y: int, x: int, text: str, role: str = "text") -> None:
        raise NotImplementedError

    def text(self, y: int, x: int, text: str, role: str = "text", maxw: int | None = None) -> int:
        if y < 0 or y >= self.h or x >= self.w or x < 0:
            return x
        room = self.w - x if maxw is None else min(maxw, self.w - x)
        s = clean(text, 2000)[: max(0, room)]
        if s:
            self.put(y, x, s, role)
        return x + len(s)

    def segs(self, y: int, x: int, segments, maxw: int) -> int:
        end = x + maxw
        for text, role in segments:
            if x >= end:
                break
            x = self.text(y, x, text, role, end - x)
        return x


def box(c: Canvas, g: Glyphs, y: int, x: int, h: int, w: int, title: str, focused: bool, count=None) -> None:
    role = "brand" if focused else "faint"
    c.text(y, x, g.tl + g.h * (w - 2) + g.tr, role)
    for i in range(1, h - 1):
        c.text(y + i, x, g.v, role)
        c.text(y + i, x + w - 1, g.v, role)
    c.text(y + h - 1, x, g.bl + g.h * (w - 2) + g.br, role)
    xx = c.text(y, x + 2, f" {title}", "title" if focused else "muted", w - 4)
    if count is not None:
        xx = c.text(y, xx, f" {count}", "accent", x + w - xx - 2)
    c.text(y, xx, " ", role)


def bar(c: Canvas, g: Glyphs, y: int, x: int, frac: float, width: int, role: str) -> int:
    n = int(round(max(0.0, min(1.0, frac)) * width))
    x = c.text(y, x, g.full * n, role)
    return c.text(y, x, g.empty * (width - n), "faint")


# ---------------------------------------------------------------------------- disegno principale
def draw(c: Canvas, s: DashState, g: Glyphs) -> None:
    if c.w < MIN_W or c.h < MIN_H:
        c.text(0, 0, t("dash.too_small", w=MIN_W, h=MIN_H), "warn")
        return
    _header(c, s, g)
    top, bottom = 4, c.h - 2
    if s.detail:
        _detail(c, s, g, top, bottom - top)
    elif s.zoom is not None:
        PANEL_DRAW[s.zoom](c, s, g, top, 0, bottom - top, c.w, True)
    else:
        _overview(c, s, g, top, bottom)
    _footer(c, s)
    if s.modal:
        _modal(c, s, g)


def _overview(c, s, g, top, bottom) -> None:
    left_w = max(38, int(c.w * 0.45))
    rw = c.w - left_w
    targets_h = max(5, min(len(s.targets) + 2, 9))
    _targets(c, s, g, top, 0, targets_h, left_w, False)
    _live(c, s, g, top + targets_h, 0, bottom - top - targets_h, left_w, False)
    phases_h = len(FLOW) + 2
    surf_h = 5
    find_h = bottom - top - phases_h - surf_h
    _phases(c, s, g, top, left_w, phases_h, rw, False)
    _findings(c, s, g, top + phases_h, left_w, find_h, rw, False)
    _surface(c, s, g, top + phases_h + find_h, left_w, surf_h, rw, False)


def _header(c: Canvas, s: DashState, g: Glyphs) -> None:
    x = c.text(0, 0, "apernix", "brand")
    x = c.text(0, x, " · ", "faint")
    if s.running:
        x = c.text(0, x, t("dash.status.hunting") + " ", "brand")
        c.text(0, x, s.current, "title", c.w - x - 10)
    else:
        status = s.status or t("dash.status.idle")
        c.text(0, x, status, s.status_role if s.status else "text", c.w - x - 10)
    c.text(0, c.w - len(__version__) - 1, f"v{__version__}", "faint")
    n = s.counts()
    x = 0
    for lvl in ("critical", "high", "medium", "low"):
        x = c.text(1, x, str(n[lvl]), LEVEL_ROLE[lvl] if n[lvl] else "faint")
        x = c.text(1, x, f" {t('dash.count.' + lvl)}   ", "muted")
    x = c.text(1, x, str(s.requests), "text")
    x = c.text(1, x, f" {t('dash.requests')}   ", "muted")
    x = c.text(1, x, mmss(s.elapsed()), "text")
    x = c.text(1, x, f"   {t('dash.profile')} ", "muted")
    c.text(1, x, t("dash.profile." + ("full" if s.profile else "quick")), "accent")
    # flusso a fasi + barra totale
    x = 0
    for i, p in enumerate(FLOW):
        ph = s.phases[p]
        role = STATE_ROLE[ph.state]
        x = c.text(2, x, f"{g.state[ph.state]} ", role)
        x = c.text(2, x, t(f"dash.phase.{p}.short"), "title" if ph.state == "run" else role)
        if i < len(FLOW) - 1:
            x = c.text(2, x, f" {g.link} ", "faint")
    frac = s.overall() if (s.running or s.finished) else 0.0
    width = min(30, c.w - x - 10)
    if width >= 8:
        xx = bar(c, g, 2, x + 3, frac, width, "brand" if s.running else ("ok" if frac >= 1 else "muted"))
        c.text(2, xx + 1, f"{int(frac * 100):>3}%", "text")
    # tab dei pannelli, come in Erinix
    x = 0
    current = s.zoom if s.zoom is not None else s.focus
    for i, name in enumerate(PANELS):
        x = c.text(3, x, f"{i + 1} ", "accent")
        x = c.text(3, x, t(f"dash.panel.{name}"), "title" if i == current else "muted")
        x = c.text(3, x, "   ", "muted")


# ---------------------------------------------------------------------------- pannelli
def _scroll_window(sel: int, total: int, rows: int) -> int:
    return max(0, min(sel - rows // 2, total - rows))


def _targets(c, s, g, y, x, h, w, zoomed) -> None:
    focused = s.focus == P_TARGETS
    box(c, g, y, x, h, w, f"1 {t('dash.panel.targets')}", focused, len(s.targets) or None)
    if not s.targets:
        msg = t("dash.discovering") if s.discovering else t("dash.no_targets")
        c.text(y + 1, x + 2, msg, "muted", w - 4)
        return
    rows = h - 2
    start = _scroll_window(s.selected, len(s.targets), rows)
    for i, tg in enumerate(s.targets[start:start + rows]):
        idx = start + i
        yy = y + 1 + i
        is_sel = idx == s.selected and focused
        xx = c.text(yy, x + 1, g.sel if is_sel else " ", "brand")
        xx = c.text(yy, xx, f"{g.dot if tg.authorized else g.ring} ", "brand" if tg.authorized else "muted")
        name_w = 28 if zoomed else 22
        xx = c.text(yy, xx, (tg.name or tg.url)[:name_w].ljust(name_w), "title" if is_sel else "text")
        label = "" if tg.authorized else t("dash.not_authorized")
        room = x + w - xx - 3 - (len(label) + 2 if label else 0)
        xx = c.text(yy, xx + 1, tg.url, "muted", max(0, room))
        if label:
            c.text(yy, xx + 2, label, "accent", x + w - xx - 4)
        elif zoomed and tg.via:
            c.text(yy, xx + 2, tg.via, "faint", x + w - xx - 4)


def _live(c, s, g, y, x, h, w, zoomed) -> None:
    focused = s.focus == P_LIVE
    title = f"2 {t('dash.panel.live')}"
    if s.live_scroll:
        title += f"  ↑{s.live_scroll}"
    box(c, g, y, x, h, w, title, focused)
    rows = h - 2
    items = list(s.live)
    end = len(items) - s.live_scroll
    view = items[max(0, end - rows):end]
    if not view:
        c.text(y + 1, x + 2, t("dash.live.empty"), "muted", w - 4)
    for i, (ts, segs) in enumerate(view):
        xx = c.text(y + 1 + i, x + 2, ts + " ", "faint")
        c.segs(y + 1 + i, xx, segs, x + w - xx - 2)


def _phases(c, s, g, y, x, h, w, zoomed) -> None:
    focused = s.focus == P_PHASES
    box(c, g, y, x, h, w, f"3 {t('dash.panel.phases')}", focused)
    name_w = 20
    bar_w = max(8, min(30 if zoomed else 16, w - name_w - 26))
    for i, p in enumerate(FLOW):
        ph = s.phases[p]
        yy = y + 1 + i
        is_sel = focused and i == s.phase_sel
        role = STATE_ROLE[ph.state]
        xx = c.text(yy, x + 1, g.sel if is_sel else " ", "brand")
        xx = c.text(yy, xx, f"{g.state[ph.state]} ", role)
        c.text(yy, xx, t(f"dash.phase.{p}"), "title" if is_sel or ph.state == "run" else
               ("faint" if ph.state == "skip" else "text"), name_w)
        xx = xx + name_w + 1
        if ph.state == "skip":
            c.text(yy, xx, ph.note or t("dash.phase.skipped"), "faint", x + w - xx - 2)
            continue
        frac = 1.0 if ph.state == "done" else ph.frac
        xx = bar(c, g, yy, xx, frac, bar_w, role)
        xx = c.text(yy, xx + 1, f"{int(frac * 100):>3}% ", "text")
        c.text(yy, xx, ph.label if ph.state == "run" else ph.note, "muted", x + w - xx - 2)


def _findings(c, s, g, y, x, h, w, zoomed) -> None:
    focused = s.focus == P_FINDINGS
    box(c, g, y, x, h, w, f"4 {t('dash.panel.findings')}", focused, len(s.findings))
    rows = h - 2
    if not s.findings:
        key = "dash.findings.running" if s.running else ("dash.findings.none" if s.finished else "dash.findings.idle")
        c.text(y + 1, x + 2, t(key), "muted", w - 4)
        return
    start = _scroll_window(s.finding_sel, len(s.findings), rows)
    for i, f in enumerate(s.findings[start:start + rows]):
        idx = start + i
        yy = y + 1 + i
        is_sel = focused and idx == s.finding_sel
        xx = c.text(yy, x + 1, g.sel if is_sel else " ", "brand")
        xx = level_badge(c, yy, xx, f)
        xx = c.text(yy, xx, f.title, "title" if is_sel else "text", x + w - xx - 3)
        if zoomed:
            c.text(yy, xx + 2, f.element, "muted", x + w - xx - 4)


def level_badge(c: Canvas, y: int, x: int, f) -> int:
    """'25 critico' con il colore del livello; gli spazi fuori dal colore, così il critico pieno non si
    attacca al titolo."""
    role = LEVEL_ROLE[f.level]
    label = t("level." + f.level)
    x = c.text(y, x, f"{f.risk:>2} {label}", role)
    return c.text(y, x, " " * (10 - len(label)), "text")


def _surface(c, s, g, y, x, h, w, zoomed) -> None:
    focused = s.focus == P_SURFACE
    box(c, g, y, x, h, w, f"5 {t('dash.panel.surface')}", focused)
    lines = surface_lines(s)
    for i, segs in enumerate(lines[: h - 2]):
        c.segs(y + 1 + i, x + 2, segs, w - 4)


def surface_lines(s: DashState) -> list:
    tech = ", ".join(s.tech) if s.tech else "-"
    services = "; ".join(f"{host}: {', '.join(items) or t('report.no_ports')}"
                         for host, items in s.services.items()) or "-"
    lines = [[(f"{t('dash.tech')}: ", "accent"), (tech, "text")],
             [(f"{t('dash.services')}: ", "accent"), (services, "text")]]
    if s.report:
        lines.append([(f"{t('dash.report')}: ", "accent"), (s.report, "ok")])
    return lines


PANEL_DRAW = {P_TARGETS: _targets, P_LIVE: _live, P_PHASES: _phases, P_FINDINGS: _findings, P_SURFACE: _surface}


# ---------------------------------------------------------------------------- dettaglio, piede, finestrelle
def _detail(c, s, g, y, h) -> None:
    d = s.detail
    box(c, g, y, 0, h, c.w, d.title, True)
    width = c.w - 4
    flat: list = []
    for line in d.lines:
        if isinstance(line, list):
            flat.append(line)
            continue
        text, role = line
        for part in textwrap.wrap(clean(text, 4000), width, subsequent_indent="  ") or [""]:
            flat.append([(part, role)])
    rows = h - 2
    d.scroll = max(0, min(d.scroll, max(0, len(flat) - rows)))
    for i, segs in enumerate(flat[d.scroll:d.scroll + rows]):
        c.segs(y + 1 + i, 2, segs, width)


def _footer(c: Canvas, s: DashState) -> None:
    y = c.h - 2
    xx = c.text(y, 0, f"{t('dash.now')}: ", "accent")
    if s.running and s.action:
        c.segs(y, xx, s.action, c.w - xx)
    else:
        c.text(y, xx, t("dash.now.finished") if s.finished else t("dash.now.idle"), "muted")
    x = 0
    for k, label in footer_keys(s):
        if x + len(k) + len(label) + 3 > c.w:
            break
        x = c.text(c.h - 1, x, k, "accent")
        x = c.text(c.h - 1, x, f" {label}   ", "muted")


def footer_keys(s: DashState) -> list[tuple[str, str]]:
    """Tasti mostrati in basso: cambiano con il pannello e con quello che sta succedendo."""
    if s.modal:
        return []
    if s.detail:
        return [("Esc", t("dash.k.back")), ("↑↓", t("dash.k.scroll"))]
    keys: list[tuple[str, str]] = []
    panel = s.zoom if s.zoom is not None else s.focus
    if panel == P_TARGETS and not s.running:
        keys += [("Invio", t("dash.k.analyze")), ("a", t("dash.k.add")), ("d", t("dash.k.discover")),
                 ("p", t("dash.k.profile"))]
    elif panel == P_FINDINGS:
        keys += [("Invio", t("dash.k.details")), ("↑↓", t("dash.k.choose"))]
    elif panel == P_LIVE:
        keys += [("↑↓", t("dash.k.scroll")), ("End", t("dash.k.follow"))]
    elif panel in (P_PHASES, P_SURFACE):
        keys += [("Invio", t("dash.k.details"))]
    if s.running:
        keys.insert(0, ("x", t("dash.k.stop")))
    keys += [("Tab", t("dash.k.next")), ("1-5", t("dash.k.zoom") if s.zoom is None else t("dash.k.unzoom"))]
    if s.report:
        keys.append(("r", t("dash.k.report")))
    keys += [("?", t("dash.k.guide")), ("q", t("dash.k.quit"))]
    return keys


def _modal(c, s, g) -> None:
    m = s.modal
    w = min(c.w - 4, 78)
    body = []
    for line in m.lines:
        body += textwrap.wrap(clean(line, 1000), w - 4) or [""]
    if m.kind == "input":
        body += ["", "> " + m.text[-(w - 8):] + "_"]
    hint = {"confirm": t("dash.modal.confirm"), "input": t("dash.modal.input"), "info": t("dash.modal.info")}[m.kind]
    body += ["", hint]
    hh = min(len(body) + 2, c.h - 2)
    y, x = max(0, (c.h - hh) // 2), (c.w - w) // 2
    for i in range(hh):
        c.text(y + i, x, " " * w, "text")
    box(c, g, y, x, hh, w, m.title, True)
    for i, line in enumerate(body[: hh - 2]):
        if line == hint:
            role = "accent"
        elif line.startswith("> "):
            role = "title"
        elif m.danger and i == 0:
            role = "alert"
        else:
            role = "text"
        c.text(y + 1 + i, x + 2, line, role, w - 4)
