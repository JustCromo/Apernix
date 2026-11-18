"""Disegno della dashboard su una "tela" astratta (curses nella realtà, una griglia nei test)."""

from __future__ import annotations

import textwrap

from apernix import __version__
from apernix.dashboard.state import DashState
from apernix.engine import FLOW, mmss
from apernix.i18n import t
from apernix.term import clean

MIN_W, MIN_H = 80, 22
LEVEL_ROLE = {"critical": "critical", "high": "high", "medium": "warn", "low": "dim"}


class Glyphs:
    def __init__(self, unicode: bool) -> None:
        u = unicode
        self.h, self.v = ("─", "│") if u else ("-", "|")
        self.tl, self.tr, self.bl, self.br = ("┌", "┐", "└", "┘") if u else ("+", "+", "+", "+")
        self.full, self.empty = ("█", "░") if u else ("#", ".")
        self.link = "━━" if u else "--"
        self.state = ({"wait": "·", "run": "◐", "done": "✔", "skip": "–", "fail": "✖"} if u else
                      {"wait": ".", "run": "*", "done": "+", "skip": "-", "fail": "x"})
        self.sel, self.dot, self.ring = ("▸", "●", "○") if u else (">", "*", "o")


class Canvas:
    """Interfaccia minima: chi disegna davvero implementa put()."""

    def __init__(self, width: int, height: int) -> None:
        self.w, self.h = width, height

    def put(self, y: int, x: int, text: str, role: str = "text") -> None:
        raise NotImplementedError

    def text(self, y: int, x: int, text: str, role: str = "text", maxw: int | None = None) -> int:
        if y < 0 or y >= self.h or x >= self.w:
            return x
        room = self.w - x if maxw is None else min(maxw, self.w - x)
        s = clean(text, 2000)[: max(0, room)]
        if s:
            self.put(y, x, s, role)
        return x + len(s)


def box(c: Canvas, g: Glyphs, y: int, x: int, h: int, w: int, title: str, focused: bool) -> None:
    role = "brand" if focused else "border"
    c.text(y, x, g.tl + g.h * (w - 2) + g.tr, role)
    for i in range(1, h - 1):
        c.text(y + i, x, g.v, role)
        c.text(y + i, x + w - 1, g.v, role)
    c.text(y + h - 1, x, g.bl + g.h * (w - 2) + g.br, role)
    c.text(y, x + 2, f" {title} ", "title" if focused else "muted", w - 4)


def bar(g: Glyphs, frac: float, width: int) -> str:
    n = int(round(max(0.0, min(1.0, frac)) * width))
    return g.full * n + g.empty * (width - n)


PHASE_NAMES = {p: f"dash.phase.{p}" for p in FLOW}


def draw(c: Canvas, s: DashState, g: Glyphs) -> None:
    w, h = c.w, c.h
    if w < MIN_W or h < MIN_H:
        c.text(0, 0, t("dash.too_small", w=MIN_W, h=MIN_H), "warn")
        return
    _header(c, s, g)
    top = 4
    bottom = h - 2
    left_w = max(36, int(w * 0.42))
    right_x, right_w = left_w, w - left_w
    targets_h = max(5, min(len(s.targets) + 3, 9))
    _targets(c, s, g, top, 0, targets_h, left_w)
    _live(c, s, g, top + targets_h, 0, bottom - top - targets_h, left_w)
    phases_h = len(FLOW) + 2
    surf_h = 5
    _phases(c, s, g, top, right_x, phases_h, right_w)
    find_h = bottom - top - phases_h - surf_h
    _findings(c, s, g, top + phases_h, right_x, find_h, right_w)
    _surface(c, s, g, top + phases_h + find_h, right_x, surf_h, right_w)
    _footer(c, s, g)
    if s.modal:
        _modal(c, s, g)


def _header(c: Canvas, s: DashState, g: Glyphs) -> None:
    x = c.text(0, 0, "apernix", "brand")
    if s.running:
        status = t("dash.status.running", target=s.current)
    elif s.status:
        status = s.status
    else:
        status = t("dash.status.idle")
    x = c.text(0, x, " · ", "muted")
    c.text(0, x, status, "text", c.w - x - 20)
    ver = f"v{__version__}"
    c.text(0, c.w - len(ver), ver, "muted")
    n = s.counts()
    x = 0
    for lvl in ("critical", "high", "medium", "low"):
        x = c.text(1, x, f"{n[lvl]} ", LEVEL_ROLE[lvl] if n[lvl] else "muted")
        x = c.text(1, x, f"{t('dash.count.' + lvl)}   ", "text")
    x = c.text(1, x, f"{s.requests} {t('dash.requests')}   ", "text")
    x = c.text(1, x, f"{mmss(s.elapsed())}   ", "text")
    c.text(1, x, f"{t('dash.profile')}: ", "muted")
    c.text(1, x + len(t("dash.profile")) + 2, t("dash.profile." + ("full" if s.profile else "quick")), "brand")
    # flusso a fasi
    x = 0
    for i, p in enumerate(FLOW):
        ph = s.phases[p]
        role = {"done": "ok", "run": "brand", "fail": "alert", "skip": "muted"}.get(ph.state, "muted")
        x = c.text(2, x, f"{g.state[ph.state]} {t(PHASE_NAMES[p] + '.short')}", role)
        if i < len(FLOW) - 1:
            x = c.text(2, x, f" {g.link} ", "border")
    frac = s.overall() if (s.running or s.finished) else 0.0
    room = c.w - x - 10
    if room > 10:
        c.text(2, x + 3, bar(g, frac, room - 3), "brand" if s.running else "ok" if frac >= 1 else "muted")
        c.text(2, c.w - 5, f"{int(frac * 100):>3}%", "text")


def _targets(c, s, g, y, x, h, w) -> None:
    box(c, g, y, x, h, w, f"1 {t('dash.panel.targets')}", s.focus == 0)
    if not s.targets:
        msg = t("dash.discovering") if s.discovering else t("dash.no_targets")
        c.text(y + 1, x + 2, msg, "muted", w - 4)
        return
    rows = h - 2
    start = max(0, min(s.selected - rows + 1, len(s.targets) - rows))
    for i, tg in enumerate(s.targets[start:start + rows]):
        idx = start + i
        mark = g.sel if idx == s.selected and s.focus == 0 else " "
        dot = g.dot if tg.authorized else g.ring
        role = "text" if tg.authorized else "muted"
        xx = c.text(y + 1 + i, x + 1, f"{mark}{dot} ", "brand" if tg.authorized else "muted")
        name = tg.name or tg.url
        xx = c.text(y + 1 + i, xx, name[:24], "title" if idx == s.selected else role, 24)
        c.text(y + 1 + i, xx + 1, tg.url if tg.authorized else f"{tg.url}  {t('dash.not_authorized')}",
               "muted", x + w - xx - 3)


def _live(c, s, g, y, x, h, w) -> None:
    box(c, g, y, x, h, w, f"2 {t('dash.panel.live')}", s.focus == 1)
    rows = h - 2
    items = list(s.live)
    end = len(items) - s.live_scroll
    view = items[max(0, end - rows):end]
    if not view:
        c.text(y + 1, x + 2, t("dash.live.empty"), "muted", w - 4)
    for i, (ts, text) in enumerate(view):
        xx = c.text(y + 1 + i, x + 2, ts + " ", "muted")
        role = "warn" if text.startswith("!") else "text"
        c.text(y + 1 + i, xx, text, role, x + w - xx - 2)


def _phases(c, s, g, y, x, h, w) -> None:
    box(c, g, y, x, h, w, f"3 {t('dash.panel.phases')}", False)
    name_w = 22
    bar_w = max(8, min(20, w - name_w - 26))
    for i, p in enumerate(FLOW):
        ph = s.phases[p]
        role = {"done": "ok", "run": "brand", "fail": "alert", "skip": "muted"}.get(ph.state, "muted")
        yy = y + 1 + i
        xx = c.text(yy, x + 2, f"{g.state[ph.state]} ", role)
        xx = c.text(yy, xx, t(PHASE_NAMES[p]), "text" if ph.state != "skip" else "muted", name_w)
        xx = x + 2 + 2 + name_w + 1
        if ph.state == "skip":
            c.text(yy, xx, ph.note or t("dash.phase.skipped"), "muted", x + w - xx - 2)
            continue
        frac = 1.0 if ph.state in ("done",) else ph.frac
        xx = c.text(yy, xx, bar(g, frac, bar_w), role)
        xx = c.text(yy, xx + 1, f"{int(frac * 100):>3}% ", "text")
        c.text(yy, xx, ph.label if ph.state == "run" else ph.note, "muted", x + w - xx - 2)


def _findings(c, s, g, y, x, h, w) -> None:
    box(c, g, y, x, h, w, f"4 {t('dash.panel.findings')} {len(s.findings)}", s.focus == 2)
    rows = h - 2
    if not s.findings:
        key = "dash.findings.running" if s.running else ("dash.findings.none" if s.finished else "dash.findings.idle")
        c.text(y + 1, x + 2, t(key), "muted", w - 4)
        return
    start = max(0, min(s.finding_sel - rows + 1, len(s.findings) - rows))
    for i, f in enumerate(s.findings[start:start + rows]):
        idx = start + i
        mark = g.sel if idx == s.finding_sel and s.focus == 2 else " "
        xx = c.text(y + 1 + i, x + 1, mark, "brand")
        badge = f"{f.risk:>2} {t('level.' + f.level):<8}"
        xx = c.text(y + 1 + i, xx + 1, badge, LEVEL_ROLE[f.level])
        c.text(y + 1 + i, xx + 1, f.title, "title" if idx == s.finding_sel and s.focus == 2 else "text",
               x + w - xx - 3)


def _surface(c, s, g, y, x, h, w) -> None:
    box(c, g, y, x, h, w, f"5 {t('dash.panel.surface')}", False)
    tech = ", ".join(s.tech) if s.tech else "-"
    xx = c.text(y + 1, x + 2, f"{t('dash.tech')}: ", "muted")
    c.text(y + 1, xx, tech, "text", x + w - xx - 2)
    services = "; ".join(f"{host}: {', '.join(items) or '-'}" for host, items in s.services.items()) or "-"
    xx = c.text(y + 2, x + 2, f"{t('dash.services')}: ", "muted")
    c.text(y + 2, xx, services, "text", x + w - xx - 2)
    if s.report:
        xx = c.text(y + 3, x + 2, f"{t('dash.report')}: ", "muted")
        c.text(y + 3, xx, s.report, "ok", x + w - xx - 2)


def _footer(c, s, g) -> None:
    y = c.h - 2
    xx = c.text(y, 0, f"{t('dash.now')}: ", "brand")
    now = s.action if s.running else (t("dash.now.idle") if not s.finished else t("dash.now.finished"))
    c.text(y, xx, now, "text")
    keys = t("dash.keys.running") if s.running else t("dash.keys.idle")
    x = 0
    for part in keys.split("  "):
        k, _, label = part.partition(" ")
        x = c.text(c.h - 1, x, k, "brand")
        x = c.text(c.h - 1, x, f" {label}  ", "muted")


def _modal(c, s, g) -> None:
    m = s.modal
    w = min(c.w - 4, 76)
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
        role = "muted" if line == hint else ("alert" if m.danger and i == 0 else "text")
        c.text(y + 1 + i, x + 2, line, role, w - 4)
