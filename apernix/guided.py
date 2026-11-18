"""Console guidata: Apernix fa da solo tutto quello che può, e chiede solo ciò che spetta a te.

- trova le web application su questa macchina (Docker e porte in ascolto)
- per i certificati non pubblici mostra emittente e impronta e chiede se fidarsi (come SSH)
- chiede SEMPRE in modo esplicito la conferma dell'autorizzazione
- profili pronti (rapida / completa) oppure fasi scelte a mano

Menu a numeri, niente interfaccia a tutto schermo: funziona uguale in locale e via SSH.
Ctrl+C torna indietro, Ctrl+D esce.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import re

from apernix import __version__, tlsinfo
from apernix import discover as disc
from apernix import report as rpt
from apernix.i18n import t
from apernix.scope import Scope, ScopeError, load_scope, parse_target_url
from apernix.scope_write import add_target
from apernix.term import clean, paint, symbol
from apernix.tools import which
from apernix.web.http import SafeClient

_ESC = re.compile(r"(\x1b\[[0-9;]*m)")
PROFILES = {"1": ("web",), "2": ("web", "nuclei", "nmap")}


def prompt_text(text: str) -> str:
    # \001 e \002 dicono a readline che i codici colore non occupano spazio sullo schermo.
    return _ESC.sub("\001\\1\002", paint(text, "brand"))


def is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host == "localhost" or host.endswith(".local")
    return ip.is_private or ip.is_loopback


class Back(Exception):
    pass


class Guided:
    def __init__(self, scope_path: str, out_dir: str, ask=input, say=print, runner=None,
                 finder=disc.discover, tls=tlsinfo, probe=disc.probe) -> None:
        self.scope_path = scope_path
        self.out_dir = out_dir
        self._ask = ask
        self.say = say
        self.runner = runner      # esegue l'analisi (iniettata dalla CLI)
        self.finder = finder      # scoperta delle webapp locali (sostituibile nei test)
        self.tls = tls            # funzioni TLS (sostituibili nei test)
        self.probe = probe        # lettura del titolo della pagina, per dare un nome al bersaglio

    # ------------------------------------------------------------ utilità
    def ask(self, text: str) -> str:
        try:
            answer = self._ask(prompt_text(f"{text}: "))
        except KeyboardInterrupt:
            self.say("")
            raise Back() from None
        return answer.strip()[:2048]

    def yes(self, text: str) -> bool:
        return self.ask(text).lower() in ("si", "sì")

    def error(self, msg: str) -> None:
        self.say(paint(f"{symbol('warn')} {msg}", "warn"))

    def ok(self, msg: str) -> None:
        self.say(paint(f"{symbol('ok')} {msg}", "ok"))

    def scope_error(self, exc: ScopeError) -> str:
        params = dict(exc.params)
        if "reason_key" in params:
            params["reason"] = t(params.pop("reason_key"), **params)
        return t(exc.code, **params)

    # ------------------------------------------------------------ menu principale
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
            self.error(self.scope_error(exc) + " — " + t(exc.code + ".hint"))
            return None

    def main_menu(self) -> bool:
        sc = self.load()
        targets = list(sc.targets) if sc else []
        self.say("")
        self.say(paint(t("g.targets"), "title"))
        if not targets:
            self.say(paint(f"  {t('g.no_targets')}", "dim"))
        for i, tg in enumerate(targets, 1):
            label = f"  ({clean(tg.name, 64)})" if tg.name else ""
            self.say(f"  {i}) {clean(tg.url)}{paint(label, 'dim')}")
        self.say(f"  n) {t('g.discover')}")
        self.say(f"  u) {t('g.manual')}")
        self.say(f"  q) {t('g.quit')}")
        choice = self.ask(t("g.choose")).lower()
        if choice in ("q", "0", "esci", "exit"):
            return False
        if choice == "n":
            self.discover_flow()
        elif choice == "u":
            url = self.ask(t("g.url"))
            if url:
                self.add_flow(url, "")
        elif choice.isdigit() and 1 <= int(choice) <= len(targets):
            self.scan_flow(targets[int(choice) - 1].url)
        else:
            self.error(t("g.invalid"))
        return True

    # ------------------------------------------------------------ nuovo bersaglio
    def discover_flow(self) -> None:
        self.say(paint(t("g.searching"), "info"))
        found = self.finder()
        if not found:
            self.error(t("g.none_found"))
            return
        self.say("")
        self.say(paint(t("g.found"), "title"))
        for i, c in enumerate(found, 1):
            title = f" — {clean(c.title, 60)}" if c.title and c.title != c.name else ""
            self.say(f"  {i}) {clean(c.name, 60)}{title}")
            self.say(paint(f"     {clean(c.url)}  [{c.via}]", "dim"))
        self.say(f"  q) {t('g.back')}")
        choice = self.ask(t("g.choose")).lower()
        if choice.isdigit() and 1 <= int(choice) <= len(found):
            c = found[int(choice) - 1]
            self.add_flow(c.url, c.name)
        elif choice != "q":
            self.error(t("g.invalid"))

    def trust_flow(self, url: str, changed: bool = False) -> str | None:
        """Certificato non pubblico: mostralo e chiedi se fidarsi. Restituisce il ca_file o None."""
        tg = parse_target_url(url)
        try:
            if not changed and self.tls.publicly_trusted(tg.host, tg.port):
                return ""
            chain = self.tls.fetch_chain(tg.host, tg.port)
        except OSError:
            self.error(t("g.unreachable"))
            return None
        if not chain:
            self.error(t("g.tls"))
            return None
        leaf, top = self.tls.describe(chain[0]), self.tls.describe(chain[-1])
        self.say("")
        self.say(paint(t("g.cert_changed" if changed else "g.cert_private"), "alert" if changed else "warn"))
        self.say(f"  {t('g.cert.subject')}: {clean(leaf['subject'])}")
        self.say(f"  {t('g.cert.issuer')}: {clean(top['issuer'])}")
        self.say(f"  {t('g.cert.expires')}: {clean(leaf['not_after'])}")
        self.say(f"  {t('g.cert.trusting')}: {clean(top['subject'])}")
        self.say(f"  SHA-256: {clean(top['sha256'])}")
        if not self.yes(t("g.cert.ask")):
            self.error(t("g.cert.refused"))
            return None
        base = os.path.dirname(os.path.abspath(self.scope_path))
        return self.tls.save_pin(base, tg.host, tg.port, chain[-1])

    def add_flow(self, url: str, name: str) -> None:
        try:
            tg = parse_target_url(url)
        except ValueError:
            self.error(t("err.scope_invalid", reason=t("scope.reason.bad_url", url=clean(url, 200))))
            return
        ca = ""
        if tg.scheme == "https":
            ca = self.trust_flow(tg.url)
            if ca is None:
                return
        if not self.yes(t("g.authorize", url=clean(tg.url, 200))):
            self.error(t("g.not_authorized"))
            return
        if not name:
            hit = self.probe(tg.host, tg.port)
            name = hit[1] if hit and hit[1] else tg.host
        rate = 20.0 if is_private(tg.host) else None
        try:
            add_target(self.scope_path, tg.url, name, ca, None, rate)
        except ScopeError as exc:
            self.error(self.scope_error(exc))
            return
        except OSError:
            self.error(t("err.output_dir"))
            return
        self.ok(t("g.added", path=clean(self.scope_path)))
        self.scan_flow(tg.url)

    # ------------------------------------------------------------ analisi
    def choose_profile(self, sc: Scope) -> tuple[str, ...]:
        self.say("")
        self.say(paint(t("g.profile"), "title"))
        self.say(f"  1) {t('g.profile.quick')}")
        self.say(f"  2) {t('g.profile.full')}  " + paint(t("g.recommended"), "brand"))
        self.say(f"  3) {t('g.profile.custom')}")
        self.say(f"  q) {t('g.back')}")
        choice = self.ask(t("g.choose_default")).lower() or "2"
        if choice == "q":
            raise Back()
        if choice in PROFILES:
            return PROFILES[choice]
        if choice == "3":
            return self.choose_phases(sc)
        self.error(t("g.invalid"))
        raise Back()

    def choose_phases(self, sc: Scope) -> tuple[str, ...]:
        avail = {"web": True, "nuclei": which("nuclei") is not None,
                 "nmap": which("nmap") is not None and sc.ports != "none"}
        on = dict(avail)
        order = ("web", "nuclei", "nmap")
        while True:
            self.say("")
            for i, key in enumerate(order, 1):
                note = ""
                if not avail[key]:
                    reason = t("g.missing") if which(key) is None else t("g.ports_none")
                    note = paint(f"  ({reason})", "dim")
                self.say(f"  {i}) [{'x' if on[key] else ' '}] {t(f'g.phase.{key}', ports=sc.ports)}{note}")
            self.say(paint(f"  {t('g.phases_help')}", "dim"))
            choice = self.ask(t("g.choose")).lower()
            if choice == "q":
                raise Back()
            if choice == "":
                chosen = tuple(k for k in order if on[k])
                if chosen:
                    return chosen
                self.error(t("g.no_phase"))
            elif choice.isdigit() and 1 <= int(choice) <= len(order):
                key = order[int(choice) - 1]
                if avail[key] or on[key]:
                    on[key] = not on[key]
            else:
                self.error(t("g.invalid"))

    def scan_flow(self, url: str) -> None:
        sc = self.load()
        tg = next((x for x in sc.targets if x.url == url), None) if sc else None
        if tg is None:
            return
        phases = self.choose_profile(sc)
        one = dataclasses.replace(sc, targets=(tg,))
        try:
            outcome = self.runner(one, SafeClient(one), phases)
        except KeyboardInterrupt:
            self.say("")
            self.error(t("err.interrupted"))
            return
        if outcome == "tls" and tg.scheme == "https":
            ca = self.trust_flow(tg.url, changed=bool(tg.ca_file))
            if ca:
                add_target(self.scope_path, tg.url, ca_file=ca)
                self.ok(t("g.cert.saved"))
                self.scan_flow(tg.url)
            return
        if outcome == "net":
            self.error(t("g.unreachable"))
        elif isinstance(outcome, rpt.ReportError):
            self.error(t(outcome.code))
        self.ask(t("g.enter"))
