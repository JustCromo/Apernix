#!/bin/sh
# Installa Apernix dopo `git clone`: crea un ambiente isolato e il comando `apernix`.
#   ./install.sh              installa (o aggiorna) Apernix
#   ./install.sh --tools      in più installa bandit e semgrep (analisi del codice) nello stesso ambiente
#   ./install.sh --uninstall  rimuove comando e ambiente (non tocca scope, report e fiducia nei certificati)
# Funziona su qualsiasi distro Linux con Python 3.11+ e il modulo venv. Non usa sudo.
set -eu

HOME_DIR="${APERNIX_HOME:-$HOME/.local/share/apernix}"
BIN_DIR="${APERNIX_BIN:-$HOME/.local/bin}"
REPO="$(cd "$(dirname "$0")" && pwd)"

say() { printf '%s\n' "$*"; }
fail() { printf 'Errore: %s\n' "$*" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$BIN_DIR/apernix"
    rm -rf "$HOME_DIR"
    say "Apernix rimosso (comando e ambiente). I tuoi scope e report non sono stati toccati."
    exit 0
fi

PY=""
for c in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
        PY="$c"
        break
    fi
done
[ -n "$PY" ] || fail "serve Python 3.11 o più recente (Arch: pacman -S python | Debian/Ubuntu: apt install python3 | Fedora: dnf install python3)"

"$PY" -c 'import venv, ensurepip' 2>/dev/null || fail "manca il modulo venv (Debian/Ubuntu: sudo apt install python3-venv)"

say "Uso $("$PY" --version) per creare l'ambiente in $HOME_DIR"
mkdir -p "$HOME_DIR" "$BIN_DIR"
chmod 700 "$HOME_DIR"
"$PY" -m venv "$HOME_DIR/venv"
"$HOME_DIR/venv/bin/python" -m pip install --quiet --upgrade pip
# modalità "editable": aggiornare il codice con git pull basta, senza reinstallare
LOG="$(mktemp)"
if ! "$HOME_DIR/venv/bin/python" -m pip install --quiet --editable "$REPO" >"$LOG" 2>&1; then
    cat "$LOG" >&2
    rm -f "$LOG"
    fail "installazione non riuscita (serve una connessione per scaricare 'requests')"
fi
rm -f "$LOG"

if [ "${1:-}" = "--tools" ]; then
    say "Installo bandit e semgrep (può richiedere qualche minuto)..."
    "$HOME_DIR/venv/bin/python" -m pip install --quiet bandit semgrep || say "Attenzione: bandit/semgrep non installati (vedi: apernix doctor)"
fi

ln -sf "$HOME_DIR/venv/bin/apernix" "$BIN_DIR/apernix"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say "Nota: $BIN_DIR non è nel PATH. Aggiungi questa riga a ~/.bashrc (o ~/.zshrc) e riapri il terminale:"
       say "  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

"$BIN_DIR/apernix" version
say ""
say "Fatto. Scrivi: apernix"
say "Per vedere quali strumenti opzionali mancano: apernix doctor"
