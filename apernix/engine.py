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
from apernix.correlate import correlate, drop_contradictions, simplify
from apernix.i18n import t
from apernix.inside import containers, database, logs
from apernix.inside.transport import make_transport, private_tmp
from apernix.models import Finding
from apernix.scope import Scope
from apernix.sources import bandit, nmap, nuclei, semgrep, trivy
from apernix.term import clean
from apernix.tools import which
from apernix.web import active, checks
from apernix.web.http import BudgetExceeded, Cancelled, OutOfScope, SafeClient

PHASES = ("web", "nuclei", "nmap", "inside")          # fasi che si possono scegliere
FLOW = ("recon", "web", "nuclei", "nmap", "inside", "report")   # tutte le fasi mostrate nel flusso
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
        self.non_root: set[str] = set()
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
            self._inside()
        except Cancelled:
            self.res.cancelled = True
        self.add(correlate(self.res.findings))
        self.res.findings = drop_contradictions(simplify(self.res.findings, self.non_root), self.res.sources)
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


    # ------------------------------------------------------- analisi interna
    def _quiet_tick(self, elapsed: float, limit: float) -> None:
        if self.cancel.is_set():
            raise Cancelled()
        self.emit("wait", elapsed=elapsed, limit=limit)

    def _inside(self) -> None:
        res, cfg = self.res, self.sc.internal
        if "inside" not in self.phases:
            self.phase("inside", "skip")
            return
        if cfg is None:
            self.phase("inside", "skip", t("dash.note.no_internal"))
            return
        self.phase("inside", "start")
        tr = make_transport(cfg)
        if cfg.transport == "ssh":
            self.emit("action", text=t("dash.act.ssh", user=cfg.user, host=cfg.host))
            if not tr.check().ok:
                res.source("ssh", "failed")
                self.phase("inside", "fail", t("dash.note.ssh_fail"))
                return
            res.source("ssh", "ok")
        steps = [("code", bool(cfg.path)), ("containers", bool(cfg.containers)),
                 ("db", bool(cfg.db_container)), ("logs", bool(cfg.containers))]
        total = max(1, sum(on for _, on in steps) + 1)
        done = 0

        def advance(label: str) -> None:
            nonlocal done
            done += 1
            self.emit("progress", id="inside", frac=min(1.0, done / total), label=label)

        def status(name: str, out_ok: bool, reason: str) -> None:
            res.source(name, "ok" if out_ok else (reason or "failed"))

        if cfg.path:
            with private_tmp() as tmp:
                self.emit("action", text=t("dash.act.source", path=cfg.path))
                src, reason = tr.source(tmp)
                if reason:
                    for name in ("semgrep", "bandit", "trivy"):
                        res.source(name, reason if reason in ("missing", "timeout", "too_big") else "failed")
                else:
                    self._code(src)
            advance(t("dash.phase.inside.code"))
        if cfg.containers:
            self.emit("action", text=t("dash.act.containers", n=len(cfg.containers)))
            found, reason, self.non_root = containers.run_ex(tr, cfg.containers)
            self.add(found)
            status("docker", not reason, reason)
            advance(t("dash.phase.inside.containers"))
        if cfg.db_container:
            self.emit("action", text=t("dash.act.db", name=cfg.db_container))
            found, reason = database.run(tr, cfg)
            self.add(found)
            status("postgres", not reason, reason)
            advance(t("dash.phase.inside.db"))
        if cfg.containers:
            self.emit("action", text=t("dash.act.logs"))
            found, reason = logs.run(tr, cfg.containers)
            self.add(found)
            status("logs", not reason, reason)
            advance(t("dash.phase.inside.logs"))
        names = ("semgrep", "bandit", "trivy", "docker", "postgres", "logs")
        bad = [n for n in names if res.sources.get(n) not in (None, "ok", "skipped")]
        self.emit("progress", id="inside", frac=1.0, label="")
        self.phase("inside", "done", t("dash.note.inside_partial", n=len(bad)) if bad else "")

    def _code(self, src: str) -> None:
        res = self.res
        has_py = _has_python(src)
        for name, runner, parser, needed in (
            ("semgrep", lambda: semgrep.scan(src, tick=self._quiet_tick), lambda d: semgrep.parse(d, src), True),
            ("bandit", lambda: bandit.scan(src, tick=self._quiet_tick), lambda d: bandit.parse(d, src), has_py),
            ("trivy", lambda: trivy.scan(src, tick=self._quiet_tick), trivy.parse, True),
        ):
            if not needed:
                res.source(name, "skipped")
                continue
            if which(name) is None:
                res.source(name, "missing")
                continue
            self.emit("action", text=t(f"dash.act.{name}"))
            out = runner()
            if not out.ok:
                res.source(name, out.reason or "failed")
                continue
            try:
                found = parser(out.output)
            except ValueError:
                res.source(name, "unparsable")
                continue
            res.source(name, "ok")
            self.add(found)


def _has_python(src: str, limit: int = 20000) -> bool:
    seen = 0
    for _root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv")]
        for name in files:
            seen += 1
            if name.endswith(".py"):
                return True
            if seen > limit:
                return False
    return False


def run_scan(sc: Scope, client: SafeClient, phases=PHASES, emit=None, cancel=None) -> ScanResult:
    return Run(sc, client, phases, emit, cancel).run()
