"""Correlazione: unisce risultati dall'esterno e dall'interno per trovare catene di problemi.

Un problema da solo può essere piccolo; due insieme possono essere gravi (es. database raggiungibile
dalla rete E con una password banale). Questi risultati nascono solo se entrambe le parti sono state trovate.
"""

from __future__ import annotations

import re

from apernix.i18n import t
from apernix.models import Finding

SOURCE = "apernix-correlazione"


def _first(findings: list[Finding], prefixes: tuple[str, ...]) -> list[Finding]:
    return [f for f in findings if f.check.startswith(prefixes)]


def drop_contradictions(findings: list[Finding], sources: dict | None = None) -> list[Finding]:
    """"Il database ascolta su tutte le interfacce" non è un problema se i controlli sul container mostrano che
    il database non è raggiungibile da fuori (nessuna porta pubblicata, rete host assente). Vale solo se
    i container sono stati davvero controllati."""
    if not sources or sources.get("docker") != "ok":
        return findings
    listen = [f for f in findings if f.check == "DB-LISTEN-ALL"]
    if not listen:
        return findings
    exposed = {f.element.split(":")[0] for f in findings if f.check in ("CTR-DB-PUBLISHED", "CTR-HOSTNET")}
    exposed |= {f.element for f in findings if f.check == "NET-DB-EXPOSED"}
    keep = [f for f in listen if f.element.split("/")[0] in exposed]
    if any(f.check == "NET-DB-EXPOSED" for f in findings):
        return findings
    return [f for f in findings if f.check != "DB-LISTEN-ALL" or f in keep]


def simplify(findings: list[Finding]) -> list[Finding]:
    """Toglie i doppioni: "Dockerfile senza USER" (trivy) e "il container gira come root" (docker) sono lo stesso
    problema. Resta quello osservato sul container vero; i Dockerfile coinvolti vanno nelle sue evidenze."""
    roots = [f for f in findings if f.check == "CTR-ROOT"]
    files = [f for f in findings if f.check == "CFG-DS-0002"]
    if not roots or not files:
        return findings
    cfg = files[0]
    left = []
    for path in (e[6:] for e in cfg.evidence if e.startswith("file: ")):
        # Il Dockerfile "db/Dockerfile" appartiene al container che ha "db" nel nome (racoonix-db-1), non agli altri.
        folder = path.replace("\\", "/").rsplit("/", 2)[-2] if path.count("/") else ""
        owners = [f for f in roots if folder and folder.lower() in re.split(r"[-_./]", f.element.lower())]
        for f in owners:
            f.evidence = [*f.evidence, f"Dockerfile senza USER ({path})"]
        if not owners:
            left.append(path)
    if not left:
        return [f for f in findings if f is not cfg]
    cfg.evidence = [cfg.evidence[0], *(f"file: {p}" for p in left)]       # i Dockerfile senza container noto restano
    cfg.element = left[0] + (" (+ altri file)" if len(left) > 1 else "")
    return findings


def correlate(findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    exposed = _first(findings, ("NET-DB-EXPOSED", "CTR-DB-PUBLISHED"))
    weak = _first(findings, ("CTR-WEAKPASS", "DB-HBA-TRUST", "DB-APP-SUPERUSER"))
    if exposed and weak:
        ev = [f"{f.source}: {f.title} ({f.element})" for f in (exposed[0], weak[0])]
        out.append(Finding(
            check="CHAIN-DB-EXPOSED", title=t("CHAIN-DB-EXPOSED.title"), element=exposed[0].element,
            impact=5, probability=4, source=SOURCE, evidence=ev, pt="not_tested",
            remediation=t("CHAIN-DB-EXPOSED.fix")))
    leaked = _first(findings, ("WEB-EXP-ENV", "WEB-EXP-GIT", "WEB-EXP-CONF", "WEB-EXP-DUMP"))
    secrets = _first(findings, ("SEC-", "CTR-WEAKPASS", "LOG-SECRETS"))
    if leaked and secrets:
        ev = [f"{f.source}: {f.title} ({f.element})" for f in (leaked[0], secrets[0])]
        out.append(Finding(
            check="CHAIN-SECRET-EXPOSED", title=t("CHAIN-SECRET-EXPOSED.title"), element=leaked[0].element,
            impact=5, probability=5, source=SOURCE, evidence=ev, pt="not_tested",
            remediation=t("CHAIN-SECRET-EXPOSED.fix")))
    return out
