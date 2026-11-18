# Apernix

**Risk Assessment & VSPT (Vulnerability Scanning + Penetration Testing) per applicazioni web.**

Apernix fa parte della suite Nemirix, insieme a Vulpnix, Erinix e Strinix.
Il nome viene dal latino *aper*, cinghiale.

> Stato: in sviluppo (v0.3.0): analisi esterna (controlli web, fingerprint, nmap, nuclei) e console guidata.
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

## Uso rapido: console guidata

```bash
.venv/bin/apernix
```

Senza argomenti si apre la console guidata: aggiungi il bersaglio (URL, nome, eventuale CA,
porte da controllare e conferma dell'autorizzazione), scegli le fasi da eseguire e avvia.
Lo scope viene scritto in `scope.toml` con permessi 600.

## Uso da riga di comando

```bash
.venv/bin/apernix scope                       # controlla lo scope
.venv/bin/apernix scan                        # tutte le fasi
.venv/bin/apernix scan --only web,nmap        # solo alcune fasi (web, nuclei, nmap)
.venv/bin/apernix scan --json                 # uscita JSON stabile
.venv/bin/apernix console                     # console classica a comandi
```

In alternativa alla console guidata puoi copiare `scope.example.toml` in `scope.toml`,
modificarlo e dargli `chmod 600`.

### HTTPS con CA interna (es. Caddy)

Se il sito usa un certificato della CA interna di Caddy, esporta la CA dal container e indicala
come `ca_file` (dalla console guidata o nello scope). Esempio:

```bash
docker cp NOME-CONTAINER-CADDY:/data/caddy/pki/authorities/local/root.crt ./caddy-ca.crt
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
