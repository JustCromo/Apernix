"""Correlazione: unisce risultati dall'esterno e dall'interno per trovare catene di problemi.

Un problema da solo può essere piccolo; due insieme possono essere gravi (es. database raggiungibile
dalla rete E con una password banale). Questi risultati nascono solo se entrambe le parti sono state trovate.
"""

from __future__ import annotations

from apernix.i18n import t
from apernix.models import Finding

SOURCE = "apernix-correlazione"


def _first(findings: list[Finding], prefixes: tuple[str, ...]) -> list[Finding]:
    return [f for f in findings if f.check.startswith(prefixes)]


def simplify(findings: list[Finding]) -> list[Finding]:
    """Toglie i doppioni: "Dockerfile senza USER" (trivy) e "il container gira come root" (docker) sono lo stesso
    problema. Resta quello osservato sul container vero; i Dockerfile coinvolti vanno nelle sue evidenze."""
    roots = [f for f in findings if f.check == "CTR-ROOT"]
    files = [f for f in findings if f.check == "CFG-DS-0002"]
    if not roots or not files:
        return findings
    names = [e for e in files[0].evidence if e.startswith("file: ")][:4]
    for f in roots:
        f.evidence = [*f.evidence, *(f"Dockerfile senza USER ({n[6:]})" for n in names)]
    return [f for f in findings if f.check != "CFG-DS-0002"]


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
