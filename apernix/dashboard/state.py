"""Stato della dashboard: tutto quello che si vede a schermo, aggiornato dagli eventi del motore.

Niente curses qui dentro: lo stato si prova con i test senza un terminale vero.
"""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field

from apernix.engine import FLOW, Event
from apernix.i18n import t
from apernix.models import Finding
from apernix.term import clean

MAX_LIVE = 300
MAX_FINDINGS = 2000
PANELS = ("targets", "live", "phases", "findings", "surface")
P_TARGETS, P_LIVE, P_PHASES, P_FINDINGS, P_SURFACE = range(5)
LEVEL_ROLE = {"critical": "critical", "high": "high", "medium": "warn", "low": "muted"}
_HTTP = re.compile(r"^([A-Z]{3,7}) (\S.*) → (\d{3}|.+)$")


@dataclass
class TargetRow:
    url: str
    name: str
    authorized: bool
    via: str = ""


@dataclass
class PhaseState:
    state: str = "wait"      # wait | run | done | skip | fail
    frac: float = 0.0
    label: str = ""
    note: str = ""


@dataclass
class Modal:
    """Domanda in finestrella (certificato, autorizzazione, uscita) o testo da scrivere (URL)."""
    kind: str                # confirm | input | info
    title: str
    lines: list[str] = field(default_factory=list)
    on_yes: object = None
    on_no: object = None
    text: str = ""
    danger: bool = False


@dataclass
class Detail:
    """Pagina di dettaglio a tutto schermo (problema, fase, superficie, guida)."""
    title: str
    lines: list[tuple]           # [(testo, ruolo)] oppure [[(pezzo, ruolo), ...]] per righe a più colori
    scroll: int = 0


def http_segments(text: str) -> list[tuple[str, str]]:
    """'GET /path → 404' diviso in pezzi colorati: metodo, percorso, stato."""
    m = _HTTP.match(text)
    if not m:
        return [(text, "text")]
    method, path, status = m.groups()
    role = "alert"
    if status.isdigit():
        role = {"2": "ok", "3": "accent", "4": "muted", "5": "warn"}.get(status[0], "text")
    return [(f"{method} ", "accent"), (path, "text"), (" → ", "faint"), (status, role)]


@dataclass
class DashState:
    targets: list[TargetRow] = field(default_factory=list)
    selected: int = 0
    focus: int = P_TARGETS
    zoom: int | None = None
    detail: Detail | None = None
    phases: dict = field(default_factory=lambda: {p: PhaseState() for p in FLOW})
    phase_sel: int = 0
    active_phases: tuple = FLOW
    findings: list[Finding] = field(default_factory=list)
    finding_sel: int = 0
    live: deque = field(default_factory=lambda: deque(maxlen=MAX_LIVE))
    live_scroll: int = 0                 # 0 = segue gli ultimi passi
    action: list = field(default_factory=list)
    tech: list[str] = field(default_factory=list)
    services: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)
    running: bool = False
    current: str = ""
    started: float = 0.0
    finished: float = 0.0
    requests: int = 0
    profile: int = 1                     # 0 rapida, 1 completa
    status: str = ""
    status_role: str = "text"
    report: str = ""
    discovering: bool = False
    modal: Modal | None = None

    # ------------------------------------------------------------ eventi
    def reset_run(self, url: str, phases: tuple[str, ...]) -> None:
        self.phases = {p: PhaseState() for p in FLOW}
        self.active_phases = ("recon", *phases, "report")
        for p in FLOW:
            if p not in self.active_phases:
                self.phases[p].state = "skip"
        self.findings.clear()
        self.finding_sel = 0
        self.tech, self.services, self.sources = [], {}, {}
        self.running, self.current = True, url
        self.started, self.finished, self.requests = time.monotonic(), 0.0, 0
        self.report, self.status = "", ""
        self.live_scroll = 0
        self.focus, self.zoom = P_LIVE, None          # durante l'analisi si guarda il live
        self.log([("▶ ", "brand"), (clean(url, 200), "title")])

    def log(self, segments) -> None:
        if isinstance(segments, str):
            segments = [(segments, "text")]
        segs = [(clean(text, 300), role) for text, role in segments][:12]
        self.live.append((time.strftime("%H:%M:%S"), segs))
        if self.live_scroll:
            self.live_scroll = min(self.live_scroll + 1, len(self.live) - 1)   # chi scorre non viene spostato

    def apply(self, ev: Event) -> None:
        d = ev.data
        if ev.kind == "phase":
            ph = self.phases.get(d.get("id"))
            if ph is None:
                return
            ph.state = {"start": "run", "done": "done", "skip": "skip", "fail": "fail"}.get(d.get("state"), ph.state)
            if ph.state == "done":
                ph.frac = 1.0
            ph.note = clean(d.get("note", ""), 80)
            name = t(f"dash.phase.{d['id']}")
            if ph.state == "run":
                self.log([("◆ ", "accent"), (name, "accent")])
            elif ph.state in ("done", "fail"):
                role = "ok" if ph.state == "done" else "alert"
                self.log([("✔ " if ph.state == "done" else "✖ ", role), (name, role),
                          (f"  {ph.note}" if ph.note else "", "muted")])
        elif ev.kind == "progress":
            ph = self.phases.get(d.get("id"))
            if ph is not None and ph.state == "run":
                ph.frac = max(0.0, min(1.0, float(d.get("frac", 0.0))))
                ph.label = clean(d.get("label", ""), 40)
        elif ev.kind == "action":
            text = clean(d.get("text", ""), 300)
            segs = http_segments(text)
            if len(segs) > 1:
                self.requests += 1
            self.action = segs
            self.log(segs)
        elif ev.kind == "finding":
            f = d.get("finding")
            if isinstance(f, Finding) and len(self.findings) < MAX_FINDINGS:
                self.findings.append(f)
                self.findings.sort(key=lambda x: (-x.risk, x.check))
                self.log([(f"● {f.risk:>2} {t('level.' + f.level)}", LEVEL_ROLE[f.level]), ("  ", "text"),
                          (f.title, "title")])
        elif ev.kind == "tech":
            self.tech = [clean(x, 60) for x in d.get("items", [])][:30]
        elif ev.kind == "services":
            self.services[clean(d.get("host", "?"), 80)] = [clean(x, 80) for x in d.get("items", [])][:50]
        elif ev.kind == "target":
            self.current = clean(d.get("url", ""), 200)

    def finish(self) -> None:
        self.running, self.finished = False, time.monotonic()
        if self.findings:
            self.focus, self.finding_sel = P_FINDINGS, 0       # alla fine: il problema più grave è già pronto
        self.live_scroll = 0

    # ------------------------------------------------------------ riepiloghi
    def counts(self) -> dict:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            if f.scored:           # come nel report: i segnali da verificare e i problemi della macchina non contano
                c[f.level] += 1
        return c

    def overall(self) -> float:
        act = [p for p in self.active_phases if self.phases[p].state != "skip"]
        if not act:
            return 0.0
        return sum(1.0 if self.phases[p].state in ("done", "fail") else self.phases[p].frac for p in act) / len(act)

    def elapsed(self) -> float:
        if not self.started:
            return 0.0
        return (self.finished or time.monotonic()) - self.started
