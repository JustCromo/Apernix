"""Testi per l'utente, separati dal codice: un file JSON per lingua in locales/."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from importlib import resources

DEFAULT_LANG = "it"


@lru_cache(maxsize=4)
def _catalog(lang: str) -> dict[str, str]:
    data = resources.files("apernix").joinpath("locales", f"{lang}.json").read_text("utf-8")
    catalog = json.loads(data)
    if not isinstance(catalog, dict):
        raise ValueError("catalogo lingua non valido")
    return {str(k): str(v) for k, v in catalog.items()}


def current_lang() -> str:
    lang = os.environ.get("APERNIX_LANG", DEFAULT_LANG)
    # Solo codici semplici: niente percorsi passati tramite variabile d'ambiente.
    if not lang.isalpha() or len(lang) > 5:
        return DEFAULT_LANG
    try:
        _catalog(lang)
    except (FileNotFoundError, ValueError, OSError):
        return DEFAULT_LANG
    return lang


def t(key: str, **params: object) -> str:
    """Restituisce il testo `key` nella lingua corrente, con i parametri inseriti."""
    catalog = _catalog(current_lang())
    text = catalog.get(key)
    if text is None:
        text = _catalog(DEFAULT_LANG).get(key, key)
    if params:
        try:
            return text.format(**params)
        except (KeyError, IndexError, ValueError):
            return text
    return text
