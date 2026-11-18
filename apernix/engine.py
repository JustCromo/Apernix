"""Motore dell'analisi: esegue le fasi e "racconta" ogni passo con un evento.

Chi lo usa (la CLI che stampa righe, la dashboard che disegna pannelli) riceve gli eventi
e decide come mostrarli. Così il motore è uno solo e le interfacce restano semplici.

Eventi (Event.kind → Event.data):
  target   {url}                                  inizia un bersaglio
  phase    {id, state: start|done|skip|fail, note} cambio di stato di una fase
  progress {id, frac 0..1, label}                 avanzamento di una fase
  action   {text}                                 cosa sta facendo adesso, in dettaglio
  finding  {finding}                              nuovo problema trovato
  tech     {url, items}                           tecnologie riconosciute
  services {host, items}                          porte e servizi aperti
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests

from apernix import fingerprint as fpr
from apernix.i18n import t
from apernix.models import Finding
from apernix.scope import Scope
from apernix.sources import nmap, nuclei
from apernix.term import clean
from apernix.tools import which
from apernix.web import active, checks
from apernix.web.http import BudgetExceeded, Cancelled, OutOfScope, SafeClient

PHASES = ("web", "nuclei", "nmap")          # fasi che si possono scegliere
FLOW = ("recon", "web", "nuclei", "nmap", "report")   # tutte le fasi mostrate nel flusso
WEB_REQUESTS = 1 + len(active.EXPOSURES) + 2 + 4 + 2   # richieste previste dalla fase web
NUCLEI_EXPECTED = 240.0                                # secondi tipici con -as
NMAP_EXPECTED = {"top100": 40.0, "top1000": 120.0, "all": 900.0}


@dataclass
class Event:
    kind: str
    data: dict


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    reached: list[str] = field(default_factory=list)
    errors: dict = field(default_factory=dict)   # url → "tls" | "net"
    fingerprint: list[dict] = field(default_factory=list)
    services: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)
    cancelled: bool = False

    def source(self, name: str, status: str) -> None:
        # "ok" non sovrascrive un problema già visto su un altro bersaglio.
        if self.sources.get(name) in (None, "ok", "skipped"):
            self.sources[name] = status


def mmss(seconds: float) -> str:
    s = int(seconds)
    return f"{s // 60}:{s % 60:02d}"


class Run:
    def __init__(self, sc: Scope, client: SafeClient, phases, emit, cancel: threading.Event | None) -> None:
        self.sc, self.client, self.phases = sc, client, tuple(phases)
        self.emit_cb = emit or (lambda ev: None)
        self.cancel = cancel or threading.Event()
        self.res = ScanResult()
        self._web_done = 0
        client.cancel = self.cancel
        client.observer = self._observe

    def emit(self, kind: str, **data) -> None:
        self.emit_cb(Event(kind, data))

    def phase(self, pid: str, state: str, note: str = "") -> None:
        self.emit("phase", id=pid, state=state, note=note)

    def add(self, findings: list[Finding]) -> None:
        for f in findings:
            self.res.findings.append(f)
            self.emit("finding", finding=f)

    def _observe(self, method: str, url: str, status) -> None:
        path = urlsplit(url).path or "/"
        result = str(status) if isinstance(status, int) else t("dash.no_answer")
        self.emit("action", text=f"{method} {clean(path, 120)} → {result}")
        self._web_done += 1
        self.emit("progress", id="web", frac=min(1.0, self._web_done / WEB_REQUESTS), label="")

    def _tick(self, pid: str, expected: float):
        def tick(elapsed: float, limit: float) -> None:
            if self.cancel.is_set():
                raise Cancelled()
            frac = min(0.95, elapsed / expected) if expected else 0.0
            self.emit("progress", id=pid, frac=frac, label=f"{mmss(elapsed)} / ~{mmss(max(expected, elapsed))}")
            self.emit("wait", elapsed=elapsed, limit=limit)
        return tick

    # ------------------------------------------------------------------ fasi
    def run(self) -> ScanResult:
        try:
            self._targets()
            self._nmap()
        except Cancelled:
            self.res.cancelled = True
        return self.res

    def _targets(self) -> None:
        res = self.res
        res.source("apernix-web", "ok" if "web" in self.phases else "skipped")
        for tg in self.sc.targets:
            self.emit("target", url=tg.url)
            self.phase("recon", "start")
            self.emit("action", text=t("dash.act.connect", url=tg.url))
            try:
                home = self.client.get(tg.url)
            except requests.exceptions.SSLError:
                res.errors[tg.url] = "tls"
                self.phase("recon", "fail", t("dash.note.tls"))
                continue
            except (requests.RequestException, OutOfScope, BudgetExceeded):
                res.errors[tg.url] = "net"
                self.phase("recon", "fail", t("dash.note.net"))
                continue
            res.reached.append(tg.url)
            fp = fpr.from_response(home)
            res.fingerprint.append(fp)
            self.emit("tech", url=tg.url, items=list(fp["technologies"]))
            self.phase("recon", "done", ", ".join(fp["technologies"][:3]))
            self._web(tg, home)
            self._nuclei(tg)

    def _web(self, tg, home) -> None:
        if "web" not in self.phases:
            self.phase("web", "skip")
            return
        self.phase("web", "start")
        self.emit("action", text=t("dash.act.headers"))
        self.add(checks.run_passive(home))
        if tg.ca_file and tg.scheme == "https":
            self.add([checks.private_ca(tg.url, os.path.basename(tg.ca_file))])
        self.add(active.run_active(self.client, tg.url, home))
        self.emit("progress", id="web", frac=1.0, label="")
        self.phase("web", "done", t("dash.note.checks", n=WEB_REQUESTS))

    def _nuclei(self, tg) -> None:
        res = self.res
        if "nuclei" not in self.phases:
            res.source("nuclei", "skipped")
            self.phase("nuclei", "skip")
            return
        if which("nuclei") is None:
            res.source("nuclei", "missing")
            self.phase("nuclei", "skip", t("source.missing"))
            return
        self.phase("nuclei", "start")
        self.emit("action", text=t("dash.act.nuclei", url=tg.url))
        out = nuclei.scan(tg.url, self.sc.rate, self.sc.timeout, tick=self._tick("nuclei", NUCLEI_EXPECTED))
        if out.ok:
            found, tech = nuclei.parse(out.output)
            self.add(found)
            if res.fingerprint:
                res.fingerprint[-1]["technologies"] += [clean(x, 80) for x in tech[:20]]
                self.emit("tech", url=tg.url, items=list(res.fingerprint[-1]["technologies"]))
        res.source("nuclei", "ok" if out.ok else out.reason)
        self.phase("nuclei", "done" if out.ok else "fail", "" if out.ok else t("source." + out.reason))

    def _nmap(self) -> None:
        res = self.res
        if "nmap" not in self.phases or self.sc.ports == "none":
            res.source("nmap", "skipped")
            self.phase("nmap", "skip")
            return
        hosts: dict[str, list[int]] = {}
        for tg in self.sc.targets:
            if tg.url in res.reached:
                hosts.setdefault(tg.host, []).append(tg.port)
        if not hosts:
            self.phase("nmap", "skip")
            return
        if which("nmap") is None:
            res.source("nmap", "missing")
            self.phase("nmap", "skip", t("source.missing"))
            return
        self.phase("nmap", "start")
        for host, web_ports in hosts.items():
            self.emit("action", text=t("dash.act.nmap", host=host, ports=self.sc.ports))
            out = nmap.scan(host, self.sc.ports, tick=self._tick("nmap", NMAP_EXPECTED.get(self.sc.ports, 60.0)))
            if not out.ok:
                res.source("nmap", out.reason)
                continue
            try:
                ports = nmap.parse(out.output)
            except (ValueError, SyntaxError):
                res.source("nmap", "unparsable")
                continue
            res.source("nmap", "ok")
            res.services[host] = [nmap.describe(p) for p in ports]
            self.emit("services", host=host, items=list(res.services[host]))
            self.add(nmap.findings(host, ports, web_ports))
        ok = res.sources.get("nmap") == "ok"
        self.phase("nmap", "done" if ok else "fail", "" if ok else t("source." + res.sources.get("nmap", "failed")))


def run_scan(sc: Scope, client: SafeClient, phases=PHASES, emit=None, cancel=None) -> ScanResult:
    return Run(sc, client, phases, emit, cancel).run()
