# Apernix

**Risk Assessment & VSPT (Vulnerability Scanning + Penetration Testing) per applicazioni web.**

Apernix analizza una web application **dall'esterno** (come farebbe un visitatore) e **dall'interno**
(con il permesso di entrare nella macchina dove gira), mette tutti i risultati in **un'unica tabella** e per ogni
problema indica elemento, evidenza, esito della verifica attiva (PT), impatto, probabilità e **rischio = impatto × probabilità**.

Fa parte della suite **Nemirix**, insieme a Vulpnix, Erinix e Strinix. Il nome viene dal latino *aper*, cinghiale.
Vulpnix ed Erinix analizzano **la macchina** (hardening, utenti, kernel); Apernix analizza **l'applicazione**.
Per questo lo strumento ha due modalità distinte e oggi è disponibile la modalità **app**; la modalità **sistema**
verrà con l'integrazione di Nemirix sotto un'unica interfaccia.

## Cosa fa

| Parte | Cosa controlla | Con quali fonti |
|---|---|---|
| **Dall'esterno** (Vulnerability Scanning) | header di sicurezza, cookie, HTTPS e certificato, versioni esposte, file che non dovrebbero essere pubblici (`.git`, `.env`, backup...), pagine di errore con dettagli interni, elenco di file, CORS, metodi HTTP, porte e servizi aperti, vulnerabilità note | Apernix, nmap, nuclei |
| **Verifica attiva** (Penetration Testing, non distruttivo) | ogni problema che richiede una prova (file esposto, errore che rivela dettagli, CORS che accetta siti a caso, porta che risponde) viene **verificato davvero con una richiesta**, senza modificare nulla; l'esito (`confermato`, `non confermato`, `non testato`, `non applicabile`) e la prova finiscono nel report | Apernix, nmap, nuclei |
| **Dall'interno** (analisi dell'app) | codice sorgente, dipendenze vulnerabili, segreti scritti nel codice, configurazione dei container Docker (privilegi, utente root, mount pericolosi, porte del database pubblicate, password banali), ruoli e permessi di PostgreSQL, log (credenziali, errori, accessi falliti) | semgrep, bandit, trivy, Docker, psql (dentro il container) |
| **Correlazione** | unisce esterno e interno: per esempio *database raggiungibile dalla rete* + *password debole* = catena grave | Apernix |

L'analisi interna funziona sulla **stessa macchina** (`local`) o su **un'altra via SSH** (`ssh`).

### Calcolo del rischio

Impatto e probabilità vanno da 1 a 5, **rischio = impatto × probabilità** (1-25):

| Rischio | Livello |
|---|---|
| 1-4 | basso |
| 5-9 | medio |
| 10-16 | alto |
| 17-25 | critico |

La probabilità tiene conto del contesto: lo stesso problema (per esempio HTTP in chiaro) pesa meno su `127.0.0.1`
che su Internet.

**Voto (A-F).** Parte da 100 e scende per ogni problema, ma con un tetto per livello (alti -7 ciascuno fino a -35,
medi -2 fino a -20, bassi -0,5 fino a -5, critici -25 ciascuno): tanti problemi dello stesso tipo non azzerano il voto.
La F è riservata a chi ha problemi critici.

**Esito PT.** `confermato` = il fatto è stato osservato davvero (una risposta del sito, la configurazione letta dal
container o dal database); `non testato` = segnalato da analisi statica del codice o delle dipendenze, non provato.

### Come si riducono i falsi allarmi

- L'analisi del codice ignora le cartelle di strumenti e documentazione al primo livello (`tools`, `scripts`, `docs`,
  `examples`, `build`, `dist`, `vendor`...) e i test: non sono l'applicazione in produzione.
- Le regole Django di semgrep sono scartate se il progetto non usa Django.
- Le regole "audit" (e le "blacklist" di bandit) indicano un punto da guardare, non una falla certa: rischio ridotto e
  nota "da verificare a mano" nelle evidenze.
- Lo stesso problema trovato da due fonti (Dockerfile senza `USER` e container che gira come root) compare una sola volta.

## Requisiti

- **Linux** con **Python 3.11 o più recente** e il modulo `venv`. Provato su Arch con Python 3.13 e 3.14.
- Nessun servizio di Apernix da avviare: è un programma a riga di comando.
- L'applicazione da analizzare deve essere **in esecuzione e raggiungibile** all'URL che si indica.
- Per l'analisi interna di un'app in Docker: il **demone Docker attivo** e un utente che può usare `docker` (gruppo `docker`).
- Per l'analisi interna di un'altra macchina: **`sshd` attivo** sulla macchina remota e una chiave SSH (vedi sotto).

### Strumenti opzionali

Nessuno è obbligatorio: Apernix esegue le fasi possibili e **nel report dice quali fonti non erano disponibili**.
Il controllo web dall'esterno funziona sempre. `apernix doctor` mostra cosa manca e il comando giusto per la tua distro.

| Strumento | A cosa serve | Come installarlo |
|---|---|---|
| nmap | porte e servizi esposti | pacchetto `nmap` (`pacman -S`, `apt install`, `dnf install`) |
| nuclei | vulnerabilità note (template pubblici) | release ufficiale: <https://github.com/projectdiscovery/nuclei/releases> in `~/.local/bin` |
| semgrep, bandit | analisi del codice | `./install.sh --tools` (li mette nell'ambiente di Apernix) |
| trivy | dipendenze vulnerabili, segreti, Dockerfile/compose | <https://trivy.dev/latest/getting-started/installation/> (Arch: `pacman -S trivy`) |
| docker | container e database dell'app | pacchetto della distro |
| ssh | analisi interna di un'altra macchina | pacchetto `openssh` / `openssh-client` |

semgrep e trivy scaricano le proprie regole al primo uso: serve una connessione a Internet.

## Installazione

```bash
git clone https://github.com/JustCromo/Apernix.git
cd Apernix
./install.sh --tools      # crea un ambiente isolato e il comando `apernix` (senza --tools: solo Apernix)
apernix doctor            # controlla gli strumenti e dice come installare quelli che mancano
```

`install.sh` non usa `sudo`, crea l'ambiente in `~/.local/share/apernix` e il comando in `~/.local/bin/apernix`
(se quella cartella non è nel `PATH`, lo script dice la riga da aggiungere a `~/.bashrc`). Si aggiorna con `git pull`;
si rimuove con `./install.sh --uninstall` (non tocca scope, report e certificati accettati).

Alternativa manuale: `python -m venv .venv && .venv/bin/pip install -e .` e poi `.venv/bin/apernix`.

## Uso rapido: la dashboard

```bash
apernix
```

Si apre una **dashboard** a tutto schermo (terminale di almeno 80x22). Apernix fa da solo tutto quello che può:

1. **trova le web application su questa macchina** (porte pubblicate da Docker e porte in ascolto) oppure accetta un URL;
2. se il certificato HTTPS non è pubblico (es. CA interna di Caddy) mostra emittente e impronta SHA-256 e chiede
   se fidarsi, **come fa SSH**: il certificato accettato viene salvato in `.apernix-trust/` e da lì in poi ci si fida solo di quello;
3. chiede **sempre** la conferma esplicita dell'autorizzazione;
4. se l'app gira in Docker su questa macchina, **riconosce container, database e cartella del codice** e propone
   di attivare l'analisi interna (salva la configurazione nello scope, nessuna password);
5. propone un profilo: *Rapida* (solo web), *Completa* (web + nuclei + nmap + analisi interna) o *Personalizzata*.

Tasti: `Tab` cambia sezione, `↑↓` sceglie una riga, `Invio` apre la sezione e poi agisce, `1`-`5` apre una sezione,
`a` aggiunge un URL, `d` cerca di nuovo, `p` cambia profilo, `x` ferma, `o` apre il report nel browser, `?` guida, `q` esce.
Per terminali piccoli: `apernix menu` (console a numeri con lo stesso flusso).

## Come indicare il bersaglio (URL)

Il bersaglio sta nel file **`scope.toml`** (permessi 600, ignorato da git). Lo crea la dashboard, oppure si copia
`scope.example.toml` e si modifica:

```toml
[authorization]
confirmed = true          # solo se il proprietario ti ha autorizzato
owner = "Nome Cognome"

[[target]]
url = "https://192.168.1.50:443/"       # <-- l'URL dell'applicazione
name = "La mia web application"
# ca_file = "ca.crt"                    # solo per HTTPS con CA interna (la dashboard la gestisce da sola)

[network]
ports = "top1000"         # nmap: none, top100, top1000, all, oppure "22,80,443"

[limits]
rate = 5                  # richieste al secondo
max_requests = 300        # tetto di richieste di Apernix
timeout = 10              # secondi per risposta
```

**Regola dello scope:** Apernix non invia richieste a indirizzi che non sono nello scope, nemmeno se il sito fa un
redirect altrove. `confirmed = true` è obbligatorio.

## Accesso alla macchina e al database (analisi interna)

La sezione `[internal]` dello scope dice dove si trova l'applicazione. In locale si può **non scriverla**: la dashboard
la compila da sola. Per scriverla a mano:

```toml
[internal]
transport = "local"                         # "local" = questa macchina, "ssh" = un'altra
path = "/home/ivan/Projects/Racoonix"       # cartella con il codice dell'app
containers = ["racoonix-app-1", "racoonix-db-1"]   # container Docker da controllare (configurazione e log)
db_container = "racoonix-db-1"              # container PostgreSQL
db_user = "racoonix"                        # utente del database usato dall'app
db_name = "racoonix"
```

Per un'altra macchina (per esempio un Raspberry Pi) si aggiungono i dati SSH:

```toml
[internal]
transport = "ssh"
host = "192.168.1.60"
user = "pi"
port = 22
key = "~/.ssh/id_apernix"                   # chiave privata, chmod 600
path = "/home/pi/app"                       # percorso sulla macchina remota
containers = ["app-web-1", "app-db-1"]
db_container = "app-db-1"
db_user = "app"
db_name = "appdb"
```

Regole di sicurezza dell'accesso SSH:

- **solo chiave**, mai password (`BatchMode=yes`, `PasswordAuthentication=no`); le password non vengono mai chieste né salvate;
- l'host deve essere **già in `~/.ssh/known_hosts`** (`StrictHostKeyChecking=yes`): per la prima volta collegarsi a mano con `ssh utente@host` e verificare l'impronta;
- nessun inoltro di agent, porte o X11; la chiave deve avere permessi 600;
- sulla macchina remota **non si scrive nulla**: il codice viene solo letto (una copia temporanea locale, cancellata a fine analisi).

### Permessi richiesti

| Cosa | Permesso |
|---|---|
| leggere il codice | lettura sulla cartella dell'app |
| container e log | utente nel gruppo `docker` (sulla macchina remota, quello dell'utente SSH) |
| database | `docker exec <container> psql` con l'utente indicato: servono solo **letture** (Apernix non scrive mai nel database); l'elenco dei ruoli è leggibile da qualsiasi utente, le regole `pg_hba` solo da un superuser (altrimenti quel controllo viene saltato) |
| SSH | chiave autorizzata sull'utente remoto, nessun `sudo` |

Il database di un'altra macchina non viene contattato direttamente in rete: si entra nel container con `docker exec`,
quindi non serve aprire porte né salvare password.

## Come ottenere il report completo

```bash
apernix                                   # dashboard: scegli il bersaglio, profilo Completa, premi `o` a fine analisi
apernix scan --scope scope.toml           # stessa analisi da riga di comando (tutte le fasi)
apernix scan --only web,inside            # solo alcune fasi: web, nuclei, nmap, inside
apernix scan --quick                      # solo controlli web, in pochi secondi
apernix scan --json                       # uscita JSON stabile (formato apernix-report/1)
apernix report CARTELLA/report.json --format html > report.html     # rigenera un report (md, html, json)
```

Ogni analisi crea una cartella privata (permessi 700) con data e bersaglio nel nome, per esempio
`apernix-reports/2026-11-20_17-00_racoonix/`:

| File | Per chi |
|---|---|
| `report.html` | da aprire nel browser: voto e verdetto in una frase, piano d'azione (subito / presto / quando puoi), cosa va già bene, ogni problema spiegato con prove e rimedio, mappa del rischio e **la tabella unica con tutti i risultati** |
| `report.md` | la stessa tabella in Markdown |
| `report.json` | per altri programmi, formato stabile `apernix-report/1` |

La **tabella unica** (esterno e interno insieme) ha una riga per problema con: *Elemento, Problema, Evidenze, Esito PT, Impatto,
Probabilità, Rischio, Fonte*. Il report HTML è un file unico, senza JavaScript né risorse esterne, e neutralizza
tutto il testo che arriva dall'applicazione analizzata.

**Codici di uscita:** `0` analisi completata senza rischi alti o critici, `1` trovati rischi alti o critici, `2` errore.

## Altri comandi

| Comando | Cosa fa |
|---|---|
| `apernix scope` | controlla lo scope e mostra i bersagli autorizzati |
| `apernix doctor` | controlla gli strumenti installati e come installare quelli che mancano |
| `apernix console` / `apernix menu` | console classica a comandi / console guidata a numeri |
| `apernix help`, `apernix version` | aiuto e versione (tutti i comandi accettano `--json`) |

## Limiti noti

- La **verifica attiva (PT)** è non distruttiva e per ora si limita a confermare ciò che Apernix e le sue fonti hanno
  già osservato davvero in una risposta. Prove più profonde (iniezioni, credenziali deboli, controllo degli accessi
  dopo il login) **non sono ancora implementate**: sono tra le funzionalità future.
- La parte dell'applicazione protetta da login non viene vista dall'esterno; l'analisi interna la copre via codice, database e log.
- L'analisi del database supporta **PostgreSQL** in Docker; MySQL/MariaDB e database non containerizzati sono futuri.
- La **modalità sistema** (analisi della macchina) è demandata a Erinix e Vulpnix.
- Solo Linux; interfaccia solo in italiano per ora.
- semgrep può dare falsi positivi: ogni risultato indica la regola e il punto del codice da verificare a mano. Le cartelle escluse (vedi sopra) non vengono analizzate: se l'app vive in una di esse, il codice non viene visto.

## Funzionalità future

- Penetration Testing più profondo e sempre non distruttivo: iniezioni e XSS con dati innocui, credenziali di prova
  fornite dal proprietario, controllo dei permessi tra utenti e ruoli.
- Supporto a MySQL/MariaDB e a database non containerizzati; analisi della configurazione del web server (Caddy, nginx).
- Modalità sistema e interfaccia unica con Vulpnix, Erinix e Strinix (Nemirix).
- Confronto tra due report (cosa è migliorato), lingua inglese, esportazione PDF.

## Sicurezza dello strumento

Apernix è uno strumento di sicurezza e deve essere sicuro a sua volta: scope obbligatorio, nessuna shell, tool esterni
con ambiente ridotto e tempo massimo, certificati accettati una volta sola (TOFU), nessun segreto nel report.
Dettagli e come segnalare un problema in [SECURITY.md](SECURITY.md).
**Usalo solo su sistemi che hai il permesso di analizzare.** I report contengono informazioni sensibili: condividili solo con chi deve sistemare il problema.

## Sviluppo e test

```bash
python -m unittest discover -s tests      # test automatici (usano solo cartelle temporanee e server locali)
ruff check .                              # controllo dello stile (opzionale)
```

## Riferimenti utili

- OWASP Top 10: <https://owasp.org/www-project-top-ten/>
- OWASP Web Security Testing Guide: <https://owasp.org/www-project-web-security-testing-guide/>
- Calcolo del rischio (OWASP Risk Rating Methodology): <https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>
- nmap: <https://nmap.org/book/> · nuclei: <https://docs.projectdiscovery.io/> · semgrep: <https://semgrep.dev/docs/> · bandit: <https://bandit.readthedocs.io/> · trivy: <https://trivy.dev/>
- CIS Docker Benchmark: <https://www.cisecurity.org/benchmark/docker>
- PostgreSQL, `pg_hba.conf`: <https://www.postgresql.org/docs/current/auth-pg-hba-conf.html>

## Licenza

MIT
