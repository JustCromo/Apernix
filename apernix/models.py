"""Modello dei dati: un problema trovato (Finding) e il calcolo del rischio."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from apernix.term import clean

PT_RESULTS = ("confirmed", "not_confirmed", "not_tested", "not_applicable")
LEVELS = ("low", "medium", "high", "critical")
MAX_EVIDENCE = 10


def risk_level(risk: int) -> str:
    """Rischio = impatto × probabilità (1-25) → livello."""
    if risk >= 17:
        return "critical"
    if risk >= 10:
        return "high"
    if risk >= 5:
        return "medium"
    return "low"


def _scale(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
        raise ValueError(f"{name} deve essere un intero da 1 a 5")
    return value


@dataclass
class Finding:
    check: str            # identificativo stabile del controllo, es. WEB-HDR-CSP
    title: str            # testo leggibile (già tradotto)
    element: str          # cosa è interessato: URL, servizio, file, tabella...
    impact: int           # 1-5
    probability: int      # 1-5
    source: str           # da dove arriva: apernix-web, nmap, nuclei, semgrep...
    evidence: list[str] = field(default_factory=list)
    pt: str = "not_tested"
    remediation: str = ""
    scored: bool = True   # False: segnale da verificare o problema della macchina; elencato ma fuori da voto e conteggi

    def __post_init__(self) -> None:
        self.impact = _scale(self.impact, "impact")
        self.probability = _scale(self.probability, "probability")
        if self.pt not in PT_RESULTS:
            raise ValueError("esito PT non valido")
        self.check = clean(self.check, 64)
        self.title = clean(self.title, 200)
        self.element = clean(self.element, 300)
        self.source = clean(self.source, 64)
        self.remediation = clean(self.remediation, 500)
        self.evidence = [clean(e, 300) for e in list(self.evidence)[:MAX_EVIDENCE]]

    @property
    def risk(self) -> int:
        return self.impact * self.probability

    @property
    def level(self) -> str:
        return risk_level(self.risk)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk"] = self.risk
        d["level"] = self.level
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        if not isinstance(d, dict):
            raise ValueError("finding non valido")
        keys = ("check", "title", "element", "impact", "probability", "source", "evidence", "pt", "remediation")
        missing = [k for k in keys if k not in d]
        if missing:
            raise ValueError("campi mancanti")
        for k in ("check", "title", "element", "source", "pt", "remediation"):
            if not isinstance(d[k], str):
                raise ValueError("tipo non valido")
        if not isinstance(d["evidence"], list) or not all(isinstance(e, str) for e in d["evidence"]):
            raise ValueError("evidenze non valide")
        return cls(**{k: d[k] for k in keys}, scored=d.get("scored") is not False)
