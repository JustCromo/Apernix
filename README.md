# Apernix

**Risk Assessment & VSPT (Vulnerability Scanning + Penetration Testing) per applicazioni web.**

Apernix fa parte della suite Nemirix, insieme a Vulpnix, Erinix e Strinix.
Il nome viene dal latino *aper*, cinghiale.

> Stato: in sviluppo (v0.2.0): analisi esterna (controlli web, fingerprint, nmap, nuclei).
> Il README completo arriva con la v1.0.0.

## Dipendenze esterne (consigliate)

Apernix funziona anche senza, ma il report dice quali fonti mancavano.

| Tool | A cosa serve | Arch Linux |
|---|---|---|
| nmap | porte e servizi esposti | `sudo pacman -S nmap` |
| nuclei | vulnerabilità note (template) | release ufficiale su GitHub (projectdiscovery/nuclei), poi `nuclei -update-templates` |

## Installazione

```bash
git clone https://github.com/JustCromo/Apernix.git
cd Apernix
python -m venv .venv
.venv/bin/pip install -e .
```

## Uso rapido

```bash
cp scope.example.toml scope.toml
chmod 600 scope.toml
# modifica scope.toml: URL del bersaglio e confirmed = true
.venv/bin/apernix scope
.venv/bin/apernix scan
```

Per un controllo veloce senza nmap e nuclei: `apernix scan --quick`.

Il report viene salvato in `apernix-reports/<data-ora>/` (`report.json` e `report.md`).

## Regola dello scope

Apernix non invia richieste a indirizzi che non sono nel file di scope, nemmeno se il sito
fa un redirect altrove. Usalo solo su sistemi che hai il permesso di analizzare.

## Codici di uscita

| Codice | Significato |
|---|---|
| 0 | analisi completata, nessun rischio alto o critico |
| 1 | analisi completata, trovati rischi alti o critici |
| 2 | errore (scope, rete, parametri) |

## Licenza

MIT
