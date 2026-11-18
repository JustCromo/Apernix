"""Uscita su terminale: pulizia del testo esterno, colori a ruoli, ripiego ASCII."""

from __future__ import annotations

import os
import re
import sys

from apernix.palette import DARK, TERM_ROLES, rgb

# Caratteri di controllo C0/C1 (escluso \n e \t) e DEL: bloccano le sequenze di escape
# che un server malevolo potrebbe mettere in header o pagine per manomettere il terminale.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# Caratteri bidirezionali e invisibili che possono mascherare il testo mostrato.
_BIDI = re.compile(r"[​-‏‪-‮⁦-⁩﻿]")


def clean(text: object, limit: int = 300) -> str:
    """Rende sicuro un testo che arriva dall'esterno (server, file, tool di terzi)."""
    s = str(text)
    s = _CONTROL.sub("?", s)
    s = _BIDI.sub("?", s)
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s


def truecolor() -> bool:
    return os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if "NO_COLOR" in os.environ:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def use_unicode(stream=None) -> bool:
    stream = stream or sys.stdout
    enc = (getattr(stream, "encoding", None) or "").lower()
    return "utf" in enc


def paint(text: str, role: str, stream=None) -> str:
    """Colora `text` con un ruolo della palette (24 bit se il terminale lo supporta, sennò 16 colori)."""
    if not use_color(stream) or role not in TERM_ROLES:
        return text
    key, ansi16, bold, filled = TERM_ROLES[role]
    if truecolor():
        r, g, b = rgb(DARK[key])
        code = f"48;2;{r};{g};{b};38;2;255;255;255" if filled else f"38;2;{r};{g};{b}"
        if bold:
            code = "1;" + code
    else:
        code = ansi16 if not bold or ansi16.startswith("1") else "1;" + ansi16
    return f"\x1b[{code}m{text}\x1b[0m"


def symbol(name: str, stream=None) -> str:
    uni = {"ok": "✔", "warn": "▲", "alert": "✖", "dot": "•", "arrow": "→"}
    asc = {"ok": "+", "warn": "!", "alert": "x", "dot": "*", "arrow": "->"}
    table = uni if use_unicode(stream) else asc
    return table.get(name, "")


def level_role(level: str) -> str:
    return {"low": "dim", "medium": "warn", "high": "high", "critical": "critical"}.get(level, "info")
