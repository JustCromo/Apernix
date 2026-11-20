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


def active_roles(tr: Transport, cfg: Internal) -> set[str] | None:
    """I ruoli con cui l'app è davvero connessa al database in questo momento (pg_stat_activity).
    L'utente indicato nello scope è quello con cui Apernix legge, di solito il proprietario: non è detto
    che sia quello dell'app. None = non verificabile (query fallita)."""
    rows = query(tr, cfg, "SELECT DISTINCT usename FROM pg_stat_activity WHERE datname = current_database() "
                          "AND usename IS NOT NULL AND pid <> pg_backend_pid() AND backend_type = 'client backend'")
    if rows is None:
        return None
    return {r[0][:63] for r in rows if r and r[0]}


def run(tr: Transport, cfg: Internal):
    """Restituisce (problemi, motivo dell'errore o '')."""
    el = f"{cfg.db_container}/{cfg.db_name}"
    roles = query(tr, cfg, "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin "
                           "FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' ORDER BY rolname")
    if roles is None:
        # psql assente nel container: non è PostgreSQL (MySQL, MariaDB...): lo si dice, senza falsi "a posto".
        probe = tr.run(["docker", "exec", cfg.db_container, "psql", "--version"], timeout=30)
        return [], ("failed" if probe.ok else "not_postgres")
    out: list[Finding] = []
    active = active_roles(tr, cfg) or set()      # vuoto = nessuna connessione visibile: non si sa chi usa l'app
    for row in roles:
        if len(row) < 6:
            continue
        name = row[0][:63]
        sup, crole, cdb, repl, login = (x == "t" for x in row[1:6])
        if not login:
            continue
        used_by_app = name in active if active else name == cfg.db_user
        if sup and active and name in active:
            out.append(_f("DB-APP-SUPERUSER", f"{el} ({name})", 5, 3, [t("ev.db.app_super", role=name)]))
        elif sup and active:      # superuser che l'app NON usa (tipico: il proprietario per le migrazioni)
            out.append(_f("DB-OTHER-SUPERUSER", f"{el} ({name})", 4, 1,
                          [t("ev.db.other_super", role=name), t("ev.db.not_connected")]))
        elif sup and name == cfg.db_user:    # nessuna connessione visibile: non si può dire che sia il ruolo dell'app
            f = _f("DB-APP-SUPERUSER", f"{el} ({name})", 4, 2, [t("ev.db.app_super_guess", role=name)])
            f.pt = "not_tested"
            out.append(f)
        elif sup:
            out.append(_f("DB-OTHER-SUPERUSER", f"{el} ({name})", 4, 2, [t("ev.db.other_super", role=name)]))
        elif used_by_app and (crole or cdb or repl):
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
