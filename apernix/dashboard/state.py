"""Stato della dashboard: tutto quello che si vede a schermo, aggiornato dagli eventi del motore.

Niente curses qui dentro: lo stato si prova con i test senza un terminale vero.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from apernix.engine import FLOW, Event
from apernix.models import Finding
from apernix.term import clean

MAX_LIVE = 300
MAX_FINDINGS = 2000


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
    kind: str                # info | confirm | input
    title: str
    lines: list[str] = field(default_factory=list)
    on_yes: object = None    # funzione chiamata con "s" (confirm) o con il testo (input)
    on_no: object = None
    text: str = ""           # testo digitato (input)
    danger: bool = False


@dataclass
class DashState:
    targets: list[TargetRow] = field(default_factory=list)
    selected: int = 0
    focus: int = 0                      # 0 bersagli, 1 live, 2 problemi
    phases: dict = field(default_factory=lambda: {p: PhaseState() for p in FLOW})
    active_phases: tuple = ("recon", "web", "nuclei", "nmap", "report")
    findings: list[Finding] = field(default_factory=list)
    finding_sel: int = 0
    live: deque = field(default_factory=lambda: deque(maxlen=MAX_LIVE))
    live_scroll: int = 0
    action: str = ""
    tech: list[str] = field(default_factory=list)
    services: dict = field(default_factory=dict)
    running: bool = False
    current: str = ""                   # bersaglio in analisi
    started: float = 0.0
    finished: float = 0.0
    requests: int = 0
    profile: int = 1                    # 0 rapida, 1 completa
    status: str = ""
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
        self.tech, self.services = [], {}
        self.running, self.current = True, url
        self.started, self.finished, self.requests = time.monotonic(), 0.0, 0
        self.report = ""
        self.log(f"▶ {url}")

    def log(self, text: str) -> None:
        self.live.append((time.strftime("%H:%M:%S"), clean(text, 300)))

    def apply(self, ev: Event) -> None:
        d = ev.data
        if ev.kind == "phase":
            ph = self.phases.get(d.get("id"))
            if ph is None:
                return
            ph.state = {"start": "run", "done": "done", "skip": "skip", "fail": "fail"}.get(d.get("state"), ph.state)
            if ph.state in ("done",):
                ph.frac = 1.0
            ph.note = clean(d.get("note", ""), 80)
        elif ev.kind == "progress":
            ph = self.phases.get(d.get("id"))
            if ph is not None and ph.state == "run":
                ph.frac = max(0.0, min(1.0, float(d.get("frac", 0.0))))
                ph.label = clean(d.get("label", ""), 40)
        elif ev.kind == "action":
            text = clean(d.get("text", ""), 300)
            if " → " in text:
                self.requests += 1
            self.action = text
            self.log(text)
        elif ev.kind == "finding":
            f = d.get("finding")
            if isinstance(f, Finding) and len(self.findings) < MAX_FINDINGS:
                self.findings.append(f)
                self.findings.sort(key=lambda x: (-x.risk, x.check))
                self.log(f"! {f.risk} {f.title}")
        elif ev.kind == "tech":
            self.tech = [clean(x, 60) for x in d.get("items", [])][:30]
        elif ev.kind == "services":
            self.services[clean(d.get("host", "?"), 80)] = [clean(x, 80) for x in d.get("items", [])][:50]
        elif ev.kind == "target":
            self.current = clean(d.get("url", ""), 200)

    # ------------------------------------------------------------ riepiloghi
    def counts(self) -> dict:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
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
