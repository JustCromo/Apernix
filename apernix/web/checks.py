"""Controlli web passivi dall'esterno: header di sicurezza, cookie, versioni esposte, HTTPS.

Sono "passivi": leggono solo la risposta a una normale GET, non provano attacchi.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from apernix.i18n import t
from apernix.models import Finding
from apernix.web.http import Response

SOURCE = "apernix-web"
_VERSION = re.compile(r"\d+\.\d+")


def _f(check: str, element: str, impact: int, prob: int, evidence: list[str]) -> Finding:
    return Finding(
        check=check, title=t(f"{check}.title"), element=element,
        impact=impact, probability=prob, source=SOURCE,
        evidence=evidence, pt="not_applicable", remediation=t(f"{check}.fix"),
    )


def network_scope(url: str) -> str:
    """'loopback' (solo questa macchina), 'private' (rete locale) o 'public'."""
    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost":
        return "loopback"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "private" if host.endswith((".local", ".lan", ".home.arpa")) else "public"
    if ip.is_loopback:
        return "loopback"
    return "private" if ip.is_private or ip.is_link_local else "public"


# Probabilità che qualcuno legga il traffico in chiaro: su 127.0.0.1 il traffico non esce dalla macchina,
# in rete locale serve qualcuno già dentro la rete, su Internet è il caso peggiore.
CLEARTEXT_PROBABILITY = {"loopback": 1, "private": 2, "public": 3}


def check_transport(resp: Response) -> list[Finding]:
    if resp.url.lower().startswith("http://"):
        where = network_scope(resp.url)
        ev = [t("ev.scheme_http", url=resp.url), t(f"ev.net.{where}")]
        return [_f("WEB-HTTP-001", resp.url, 4, CLEARTEXT_PROBABILITY[where], ev)]
    return []


def check_headers(resp: Response) -> list[Finding]:
    h = resp.headers
    out: list[Finding] = []
    csp = h.get("content-security-policy", "")
    if not csp:
        out.append(_f("WEB-HDR-CSP", resp.url, 3, 3, [t("ev.header_missing", name="Content-Security-Policy")]))
    xfo = h.get("x-frame-options", "").strip().lower()
    if xfo not in ("deny", "sameorigin") and "frame-ancestors" not in csp.lower():
        out.append(_f("WEB-HDR-XFO", resp.url, 3, 2, [t("ev.header_missing", name="X-Frame-Options")]))
    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        out.append(_f("WEB-HDR-XCTO", resp.url, 2, 2, [t("ev.header_missing", name="X-Content-Type-Options")]))
    if resp.url.lower().startswith("https://") and "strict-transport-security" not in h:
        out.append(_f("WEB-HDR-HSTS", resp.url, 3, 2, [t("ev.header_missing", name="Strict-Transport-Security")]))
    if "referrer-policy" not in h:
        out.append(_f("WEB-HDR-REF", resp.url, 1, 2, [t("ev.header_missing", name="Referrer-Policy")]))
    return out


def check_disclosure(resp: Response) -> list[Finding]:
    ev = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = resp.headers.get(name, "")
        if value and _VERSION.search(value):
            ev.append(t("ev.header_value", name=name, value=value))
    if ev:
        return [_f("WEB-DISC-001", resp.url, 2, 4, ev)]
    return []


def _cookie_parts(raw: str) -> tuple[str, set[str]]:
    pieces = [p.strip() for p in raw.split(";")]
    name = pieces[0].split("=", 1)[0].strip() if pieces else "?"
    attrs = {p.split("=", 1)[0].strip().lower() for p in pieces[1:] if p}
    return name or "?", attrs


def check_cookies(resp: Response) -> list[Finding]:
    https = resp.url.lower().startswith("https://")
    miss: dict[str, list[str]] = {"httponly": [], "secure": [], "samesite": []}
    for raw in resp.set_cookies[:50]:
        name, attrs = _cookie_parts(raw)
        if "httponly" not in attrs:
            miss["httponly"].append(t("ev.cookie", name=name, attr="HttpOnly"))
        if "secure" not in attrs:
            miss["secure"].append(t("ev.cookie", name=name, attr="Secure"))
        if "samesite" not in attrs:
            miss["samesite"].append(t("ev.cookie", name=name, attr="SameSite"))
    out = []
    if miss["httponly"]:
        out.append(_f("WEB-CK-HTTPONLY", resp.url, 3, 3, miss["httponly"]))
    if miss["secure"]:
        # Su HTTP il problema principale è già WEB-HTTP-001: qui la probabilità resta più bassa.
        out.append(_f("WEB-CK-SECURE", resp.url, 3, 3 if https else 2, miss["secure"]))
    if miss["samesite"]:
        out.append(_f("WEB-CK-SAMESITE", resp.url, 3, 2, miss["samesite"]))
    return out


def private_ca(url: str, ca_name: str) -> Finding:
    """Il certificato è valido solo per chi si fida della CA privata indicata nello scope."""
    return _f("WEB-TLS-PRIVATE", url, 2, 2, [t("ev.private_ca", name=ca_name)])


ALL_CHECKS = (check_transport, check_headers, check_disclosure, check_cookies)


def run_passive(resp: Response) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(resp))
    return findings
