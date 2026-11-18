"""Console guidata: si sceglie il bersaglio, si spuntano le fasi, si conferma e si parte.

Menu a numeri, niente interfaccia a tutto schermo: funziona uguale in locale e via SSH,
e il terminale resta sempre pulito (Ctrl+C torna indietro, Ctrl+D esce).
"""

from __future__ import annotations

import dataclasses
import os
import re

from apernix import __version__
from apernix import report as rpt
from apernix.i18n import t
from apernix.scope import Scope, ScopeError, load_scope, valid_port_spec
from apernix.scope_write import add_target
from apernix.term import clean, paint, symbol
from apernix.tools import which
from apernix.web.http import SafeClient


class Back(Exception):
    pass


_ESC = re.compile(r"(\x1b\[[0-9;]*m)")


def prompt_text(text: str) -> str:
    # \001 e \002 dicono a readline che i codici colore non occupano spazio sullo schermo.
    return _ESC.sub("\001\\1\002", paint(text, "brand"))


class Guided:
    def __init__(self, scope_path: str, out_dir: str, ask=input, say=print, runner=None) -> None:
        self.scope_path = scope_path
        self.out_dir = out_dir
        self._ask = ask
        self.say = say
        self.runner = runner      # funzione che esegue l'analisi (iniettata dalla CLI)

    def ask(self, text: str) -> str:
        try:
            answer = self._ask(prompt_text(f"{text}: "))
        except KeyboardInterrupt:
            self.say("")
            raise Back() from None
        return answer.strip()[:2048]

    def error(self, msg: str) -> None:
        self.say(paint(f"{symbol('warn')} {msg}", "warn"))

    # ------------------------------------------------------------ flusso principale
    def run(self) -> int:
        self.say(paint(f"APERNIX {__version__}", "brand") + paint(f"  {t('g.title')}", "dim"))
        while True:
            try:
                if not self.main_menu():
                    break
            except Back:
                continue
            except EOFError:
                self.say("")
                break
        self.say(t("console.bye"))
        return 0

    def load(self) -> Scope | None:
        if not os.path.exists(self.scope_path):
            return None
        try:
            return load_scope(self.scope_path)
        except ScopeError as exc:
            params = dict(exc.params)
            if "reason_key" in params:
                params["reason"] = t(params.pop("reason_key"), **params)
            self.error(t(exc.code, **params) + " — " + t(exc.code + ".hint"))
            return None

    def main_menu(self) -> bool:
        sc = self.load()
        self.say("")
        self.say(paint(t("g.targets"), "title"))
        targets = list(sc.targets) if sc else []
        if not targets:
            self.say(paint(f"  {t('g.no_targets')}", "dim"))
        for i, tg in enumerate(targets, 1):
            label = f"  ({clean(tg.name, 64)})" if tg.name else ""
            self.say(f"  {i}) {clean(tg.url)}{paint(label, 'dim')}")
        self.say(f"  a) {t('g.add')}")
        self.say(f"  q) {t('g.quit')}")
        choice = self.ask(t("g.choose")).lower()
        if choice in ("q", "0", "esci", "exit"):
            return False
        if choice == "a":
            self.add_flow()
            return True
        if choice.isdigit() and 1 <= int(choice) <= len(targets):
            self.scan_flow(sc, targets[int(choice) - 1])
            return True
        self.error(t("g.invalid"))
        return True

    def add_flow(self) -> None:
        url = self.ask(t("g.url"))
        if not url:
            raise Back()
        name = self.ask(t("g.name"))
        ca = self.ask(t("g.ca")) if url.lower().startswith("https://") else ""
        ports = self.ask(t("g.ports")) or "top1000"
        if not valid_port_spec(ports):
            self.error(t("scope.reason.bad_ports"))
            return
        if self.ask(t("g.authorize", url=clean(url, 200))).lower() not in ("si", "sì"):
            self.error(t("g.not_authorized"))
            return
        try:
            add_target(self.scope_path, url, name, ca, ports)
        except ScopeError as exc:
            params = dict(exc.params)
            if "reason_key" in params:
                params["reason"] = t(params.pop("reason_key"), **params)
            self.error(t(exc.code, **params))
            return
        except OSError:
            self.error(t("err.output_dir"))
            return
        self.say(paint(f"{symbol('ok')} {t('g.added', path=clean(self.scope_path))}", "ok"))

    def choose_phases(self, sc: Scope, url: str) -> tuple[str, ...]:
        avail = {"web": True, "nuclei": which("nuclei") is not None,
                 "nmap": which("nmap") is not None and sc.ports != "none"}
        on = {k: avail[k] for k in avail}
        order = ("web", "nuclei", "nmap")
        while True:
            self.say("")
            self.say(paint(t("g.phases", url=clean(url)), "title"))
            for i, key in enumerate(order, 1):
                mark = "x" if on[key] else " "
                label = t(f"g.phase.{key}", ports=sc.ports)
                note = ""
                if not avail[key]:
                    reason = t("g.missing") if which(key) is None else t("g.ports_none")
                    note = paint(f"  ({reason})", "dim")
                self.say(f"  {i}) [{mark}] {label}{note}")
            self.say(paint(f"  {t('g.phases_help')}", "dim"))
            self.say(f"  q) {t('g.back')}")
            choice = self.ask(t("g.choose")).lower()
            if choice == "q":
                raise Back()
            if choice == "":
                chosen = tuple(k for k in order if on[k])
                if chosen:
                    return chosen
                self.error(t("g.no_phase"))
                continue
            if choice.isdigit() and 1 <= int(choice) <= len(order):
                key = order[int(choice) - 1]
                if avail[key] or on[key]:
                    on[key] = not on[key]
                continue
            self.error(t("g.invalid"))

    def scan_flow(self, sc: Scope, tg) -> None:
        phases = self.choose_phases(sc, tg.url)
        self.say("")
        self.say(paint(t("g.summary"), "title"))
        self.say(f"  {t('g.summary.target')}: {clean(tg.url)}")
        self.say(f"  {t('g.summary.phases')}: {', '.join(phases)}")
        if self.ask(t("g.start")).lower() not in ("s", "si", "sì"):
            self.say(t("g.cancelled"))
            return
        one = dataclasses.replace(sc, targets=(tg,))
        try:
            outcome = self.runner(one, SafeClient(one), phases)
        except KeyboardInterrupt:
            self.say("")
            self.error(t("err.interrupted"))
            return
        if outcome == "tls":
            self.error(t("g.tls"))
        elif outcome == "net":
            self.error(t("g.unreachable"))
        elif isinstance(outcome, rpt.ReportError):
            self.error(t(outcome.code))
        self.ask(t("g.enter"))
