"""Palette "Muschio e sangue": il bosco nei fondi, l'attacco nel colore principale.

Unica fonte dei colori: la usano sia il terminale sia il report HTML.
I colori dei livelli di rischio sono fissi e sempre distinguibili tra loro.
"""

DARK = {
    "bg": "#0E1410", "surface": "#172019", "text": "#E8E4D6", "muted": "#8A9686", "primary": "#C4303A",
    "low": "#8A9686", "medium": "#D9A93B", "high": "#E8743B", "critical": "#FF5247", "ok": "#6FBF73",
    "accent": "#E39A8E", "faint": "#4A544B",
}
LIGHT = {
    "bg": "#EDF0E8", "surface": "#FAFBF7", "text": "#151C16", "muted": "#5E6A5B", "primary": "#9B1C26",
    "low": "#5E6A5B", "medium": "#8F6200", "high": "#B4470F", "critical": "#D11F1F", "ok": "#2E7D4F",
    "accent": "#A8473F", "faint": "#C9CFC3",
}

# Ruoli del terminale → (colore della palette scura, ripiego a 16 colori ANSI, grassetto, pieno)
TERM_ROLES = {
    "brand": ("primary", "31", True, False),
    "title": ("text", "1", True, False),
    "info": ("muted", "37", False, False),
    "dim": ("muted", "2", False, False),
    "ok": ("ok", "32", False, False),
    "warn": ("medium", "33", False, False),
    "high": ("high", "33", True, False),
    "alert": ("critical", "31", True, False),
    "critical": ("critical", "37;41", True, True),
}


def rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
