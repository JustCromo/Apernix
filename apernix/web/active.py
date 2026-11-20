"""Controlli web attivi ma innocui: solo GET/OPTIONS su percorsi noti, nessun dato modificato.

Per evitare falsi allarmi, un file "esposto" conta solo se la risposta contiene la sua firma
(es. .git/HEAD inizia con "ref: "), non basta un 200: molti siti rispondono 200 a tutto.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

import requests

from apernix.i18n import t
from apernix.models import Finding
from apernix.web.http import BudgetExceeded, OutOfScope, Response, SafeClient

SOURCE = "apernix-web"
EVIL_ORIGIN = "https://apernix-cors-test.invalid"


@dataclass(frozen=True)
class Exposure:
    path: str
    check: str
    impact: int
    prob: int
    pattern: re.Pattern


EXPOSURES = (
    Exposure(".git/HEAD", "WEB-EXP-GIT", 5, 4, re.compile(rb"^ref: refs/")),
    Exposure(".git/config", "WEB-EXP-GIT", 5, 4, re.compile(rb"^\[core\]", re.M)),
    Exposure(".env", "WEB-EXP-ENV", 5, 5, re.compile(rb"^[A-Z][A-Z0-9_]{2,}=", re.M)),
    Exposure("docker-compose.yml", "WEB-EXP-CONF", 4, 4, re.compile(rb"^services:\s*$", re.M)),
    Exposure("backup.sql", "WEB-EXP-DUMP", 5, 4, re.compile(rb"CREATE TABLE|INSERT INTO")),
    Exposure("dump.sql", "WEB-EXP-DUMP", 5, 4, re.compile(rb"CREATE TABLE|INSERT INTO")),
    Exposure("console", "WEB-EXP-DEBUG", 5, 5, re.compile(rb"Werkzeug.{0,200}[Cc]onsole", re.S)),
    Exposure("phpinfo.php", "WEB-EXP-DEBUG", 3, 4, re.compile(rb"<title>PHP [0-9.]+ - phpinfo\(\)")),
    Exposure("server-status", "WEB-EXP-STATUS", 3, 3, re.compile(rb"Apache Server Status")),
    Exposure("actuator/env", "WEB-EXP-DEBUG", 5, 4, re.compile(rb'"propertySources"')),
    Exposure(".DS_Store", "WEB-EXP-DSSTORE", 2, 3, re.compile(rb"^\x00\x00\x00\x01Bud1")),
)

ERROR_PATTERNS = (
    re.compile(rb"Traceback \(most recent call last\)"),
    re.compile(rb"Werkzeug Debugger"),
    re.compile(rb"You're seeing this error because you have <code>DEBUG = True</code>"),
    re.compile(rb"<b>(?:Fatal error|Warning|Parse error)</b>:"),
    re.compile(rb"\bat (?:org\.springframework|java\.lang)\.[A-Za-z.]+\("),
    re.compile(rb"SQLSTATE\[|psycopg2?\.errors|You have an error in your SQL syntax|ORA-\d{5}"),
    re.compile(rb"Microsoft \.NET Framework Version|Server Error in '/' Application"),
)
LISTING = re.compile(rb"<title>(?:Index of /|Directory listing for /)")
RISKY_METHODS = ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")


def _f(check: str, element: str, impact: int, prob: int, evidence: list[str], pt: str = "confirmed") -> Finding:
    """Questi controlli sono verifiche attive: il problema è stato osservato davvero in una risposta (esito PT
    "confermato"), senza modificare nulla sul sito. Fa eccezione WEB-METH: i metodi sono solo dichiarati."""
    return Finding(check=check, title=t(f"{check}.title"), element=element, impact=impact,
                   probability=prob, source=SOURCE, evidence=evidence, pt=pt,
                   remediation=t(f"{check}.fix"))


def _get(client: SafeClient, url: str, **kw) -> Response | None:
    try:
        return client.request(kw.pop("method", "GET"), url, **kw)
    except (requests.RequestException, OutOfScope):
        return None


def check_exposures(client: SafeClient, base: str) -> list[Finding]:
    out: list[Finding] = []
    for exp in EXPOSURES:
        r = _get(client, base + exp.path)
        if r is None or r.status != 200 or r.redirects:
            continue
        if exp.pattern.search(r.body[:65536]):
            snippet = r.body[:80].decode("utf-8", "replace").splitlines()[0] if r.body else ""
            out.append(_f(exp.check, r.url, exp.impact, exp.prob,
                          [t("ev.http_status", url=r.url, status=r.status), t("ev.signature", text=snippet)]))
    return out


def check_errors(client: SafeClient, base: str) -> list[Finding]:
    probes = [base + "apernix-" + secrets.token_hex(6), base + "apernix-%27%22%3C"]
    for url in probes:
        r = _get(client, url)
        if r is None:
            continue
        for pat in ERROR_PATTERNS:
            m = pat.search(r.body[:262144])
            if m:
                return [_f("WEB-ERR-001", url, 3, 4,
                           [t("ev.http_status", url=url, status=r.status),
                            t("ev.signature", text=m.group(0).decode("utf-8", "replace"))])]
    return []


def check_listing(client: SafeClient, base: str, home: Response) -> list[Finding]:
    candidates = [(home.url, home)]
    for sub in ("static/", "uploads/", "files/", "assets/"):
        r = _get(client, base + sub)
        if r is not None:
            candidates.append((r.url, r))
    for url, r in candidates:
        if r.status == 200 and LISTING.search(r.body[:8192]):
            return [_f("WEB-LIST-001", url, 3, 3, [t("ev.http_status", url=url, status=r.status)])]
    return []


def check_cors(client: SafeClient, base: str) -> list[Finding]:
    r = _get(client, base, headers={"Origin": EVIL_ORIGIN})
    if r is None:
        return []
    acao = r.headers.get("access-control-allow-origin", "").strip()
    creds = r.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    ev = [f"Origin: {EVIL_ORIGIN}", f"Access-Control-Allow-Origin: {acao}",
          f"Access-Control-Allow-Credentials: {'true' if creds else 'false'}"]
    if acao == EVIL_ORIGIN and creds:
        return [_f("WEB-CORS-001", base, 5, 4, ev)]
    if acao == EVIL_ORIGIN or acao == "null":
        return [_f("WEB-CORS-001", base, 3, 3, ev)]
    return []


def check_methods(client: SafeClient, base: str) -> list[Finding]:
    r = _get(client, base, method="OPTIONS")
    if r is None or r.status >= 400:
        return []
    allow = r.headers.get("allow", "") + "," + r.headers.get("access-control-allow-methods", "")
    risky = sorted({m.strip().upper() for m in allow.split(",")} & set(RISKY_METHODS))
    if risky:
        return [_f("WEB-METH-001", base, 2, 2, [f"Allow: {', '.join(risky)}"], pt="not_tested")]
    return []


def run_active(client: SafeClient, base: str, home: Response) -> list[Finding]:
    out: list[Finding] = []
    for step in (lambda: check_exposures(client, base), lambda: check_errors(client, base),
                 lambda: check_listing(client, base, home), lambda: check_cors(client, base),
                 lambda: check_methods(client, base)):
        try:
            out.extend(step())
        except BudgetExceeded:
            break
    return out
