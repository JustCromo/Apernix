"""Controlli sul database PostgreSQL dell'app: ruoli, privilegi, accesso da rete, cifratura password.

Si fa da dentro il container del database (`docker exec ... psql`): niente porte da aprire e nessuna
password da salvare. Servono solo permessi di lettura; Apernix non scrive mai nel database.
"""

from __future__ import annotations

from apernix.i18n import t
from apernix.inside.transport import Transport
from apernix.models import Finding
from apernix.scope import Internal

SOURCE = "postgres"
SEP = "\x1f"


def _f(check: str, element: str, impact: int, prob: int, evidence: list[str]) -> Finding:
    return Finding(check=check, title=t(f"{check}.title"), element=element, impact=impact, probability=prob,
                   source=SOURCE, evidence=evidence, pt="confirmed", remediation=t(f"{check}.fix"))


def _loopback(address: str) -> bool:
    """Regole su 127.0.0.1 o ::1: raggiungibili solo dall'interno del container, non dalla rete."""
    a = address.strip().lower()
    return a.startswith(("127.", "::1", "localhost"))


def query(tr: Transport, cfg: Internal, sql: str):
    argv = ["docker", "exec", cfg.db_container, "psql", "-U", cfg.db_user, "-d", cfg.db_name,
            "-X", "-At", "-F", SEP, "-v", "ON_ERROR_STOP=1", "-c", sql]
    res = tr.run(argv, timeout=30)
    if not res.ok:
        return None
    rows = []
    for line in res.output.decode("utf-8", "replace").splitlines()[:500]:
        rows.append(line.split(SEP))
    return rows


def run(tr: Transport, cfg: Internal):
    """Restituisce (problemi, motivo dell'errore o '')."""
    el = f"{cfg.db_container}/{cfg.db_name}"
    roles = query(tr, cfg, "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin "
                           "FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' ORDER BY rolname")
    if roles is None:
        return [], "failed"
    out: list[Finding] = []
    for row in roles:
        if len(row) < 6:
            continue
        name = row[0][:63]
        sup, crole, cdb, repl, login = (x == "t" for x in row[1:6])
        if not login:
            continue
        if name == cfg.db_user and sup:
            out.append(_f("DB-APP-SUPERUSER", f"{el} ({name})", 5, 3, [t("ev.db.app_super", role=name)]))
        elif sup:
            out.append(_f("DB-OTHER-SUPERUSER", f"{el} ({name})", 4, 2, [t("ev.db.other_super", role=name)]))
        elif name == cfg.db_user and (crole or cdb or repl):
            flags = ", ".join(x for x, on in (("CREATEROLE", crole), ("CREATEDB", cdb), ("REPLICATION", repl)) if on)
            out.append(_f("DB-APP-PRIV", f"{el} ({name})", 3, 2, [t("ev.db.app_priv", role=name, flags=flags)]))
    listen = query(tr, cfg, "SHOW listen_addresses")
    if listen and listen[0] and listen[0][0].strip() in ("*", "0.0.0.0"):
        out.append(_f("DB-LISTEN-ALL", el, 2, 1, [t("ev.db.listen", value=listen[0][0].strip())]))
    enc = query(tr, cfg, "SHOW password_encryption")
    if enc and enc[0] and enc[0][0].strip().lower() == "md5":
        out.append(_f("DB-PWENC-MD5", el, 3, 2, [t("ev.db.md5")]))
    hba = query(tr, cfg, "SELECT type, database, user_name, address, auth_method FROM pg_hba_file_rules")
    if hba:
        trust = [r for r in hba if len(r) >= 5 and r[4].strip() == "trust" and r[0].strip() != "local"
                 and not _loopback(r[3])]
        if trust:
            ev = [f"{r[0]} {r[1]} {r[2]} {r[3]} trust"[:200] for r in trust[:5]]
            out.append(_f("DB-HBA-TRUST", el, 5, 4, ev))
    return out, ""
