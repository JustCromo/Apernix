# Apernix

**Risk Assessment & VSPT (Vulnerability Scanning + Penetration Testing) per applicazioni web.**

Apernix fa parte della suite Nemirix, insieme a Vulpnix, Erinix e Strinix.
Il nome viene dal latino *aper*, cinghiale.

> Stato: in sviluppo (v0.5.1): analisi esterna (controlli web, fingerprint, nmap, nuclei) e dashboard.
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

## Uso rapido: la dashboard

```bash
.venv/bin/apernix
```

Senza argomenti si apre la **dashboard** a tutto schermo (serve un terminale di almeno 80x22):

| Pannello | Cosa mostra |
|---|---|
| intestazione | stato, contatori dei problemi per gravità, richieste, tempo, profilo e il **flusso delle fasi** con la barra di completamento |
| 1 Bersagli | bersagli autorizzati (●) e web application trovate su questa macchina, da autorizzare (○) |
| 2 Live | ogni passo dell'analisi in tempo reale (es. `GET /.git/HEAD → 404`) |
| 3 Fasi | stato e barra di avanzamento di ogni fase |
| 4 Problemi | problemi trovati, dal più grave; Invio apre evidenze e rimedio |
| 5 Superficie | tecnologie, servizi in rete e percorso dell'ultimo report |
| piede | **cosa sta facendo adesso** e i tasti disponibili |

Navigazione (come in Erinix): Tab / Maiusc+Tab passa da un pannello all'altro, `1`-`5` ingrandisce
un pannello (stesso numero o Esc per tornare), ↑↓ PagSu PagGiù scorre, Invio apre il dettaglio a
pagina intera (Esc o `q` per tornare). Nei Bersagli: Invio analizza, `a` aggiungi URL, `d` cerca di
nuovo, `p` cambia profilo. Sempre: `x` ferma, `r` report, `?` guida, `q` esci. I tasti utili nel
pannello attivo sono sempre scritti in basso. Quando parte un'analisi il focus va sul Live (che segue
gli ultimi passi, finché non scorri in su); quando finisce va sui Problemi, con il più grave già
selezionato. Per terminali piccoli c'è `apernix menu`, la console a numeri con lo stesso flusso.

La dashboard fa da sola tutto quello che può:

1. **trova le web application su questa macchina** (porte pubblicate da Docker e porte in ascolto,
   letta con `docker ps` e `ss`) oppure accetta un URL scritto a mano;
2. se il certificato HTTPS non è pubblico (es. CA interna di Caddy) mostra emittente e impronta
   SHA-256 e chiede se fidarsi, **come fa SSH**: il certificato accettato viene salvato in
   `.apernix-trust/` e da lì in poi Apernix si fida solo di quello; se cambia, avvisa;
3. chiede **sempre** la conferma esplicita dell'autorizzazione;
4. propone un profilo: *Rapida* (solo web), *Completa* (web + nuclei + nmap) o *Personalizzata*.

Lo scope viene scritto in `scope.toml` con permessi 600. Per i bersagli in rete privata il ritmo
predefinito è 20 richieste al secondo, per gli altri 5.

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

La console guidata gestisce da sola i certificati non pubblici (vedi sopra). In alternativa puoi
indicare a mano la CA come `ca_file` nello scope, ad esempio esportandola dal container di Caddy:

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
