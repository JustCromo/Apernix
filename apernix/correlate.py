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
