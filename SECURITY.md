# Sicurezza

## Segnalare un problema in Apernix

Se trovi una vulnerabilità in Apernix, **non aprire una issue pubblica**: scrivi in privato al proprietario del
repository (JustCromo) tramite GitHub (*Security → Report a vulnerability*, se attivo, oppure un messaggio privato)
con una descrizione e i passi per riprodurla. Risponderò appena possibile.

## Come è protetto Apernix

- **Scope obbligatorio:** nessuna richiesta parte verso indirizzi non autorizzati, nemmeno seguendo un redirect.
  Lo scope richiede `confirmed = true` e permessi 600 (rifiutato se scrivibile da altri).
- **Limiti:** ritmo massimo, numero massimo di richieste, tempo massimo per risposta, corpo delle risposte limitato a 2 MB.
- **Nessuna shell:** i programmi esterni (nmap, nuclei, semgrep, bandit, trivy, docker, ssh) partono con argomenti
  in lista e **ambiente ridotto**; nome host, utente, container e database sono validati (niente valori che iniziano per `-`).
- **Uscita dei tool non fidata:** limite di dimensione, tempo massimo, lettura JSON/XML rigorosa (entità XML rifiutate);
  ogni testo che arriva dal bersaglio viene ripulito dai caratteri di controllo prima di essere mostrato.
- **Certificati (TOFU):** un certificato non pubblico va accettato esplicitamente, viene salvato e da lì in poi è l'unico
  considerato valido; se cambia, Apernix avvisa.
- **SSH:** solo chiave, host già in `known_hosts`, nessun inoltro; sulla macchina remota si legge soltanto.
- **Database:** solo letture, dentro il container (`docker exec`); nessuna password salvata.
- **Segreti:** i valori trovati (chiavi nel codice, password nei log o nelle variabili dei container) **non vengono mai
  copiati nel report**: si indica solo la regola e il punto.
- **Report:** cartelle 700, file nel report HTML senza JavaScript, con `Content-Security-Policy: default-src 'none'`
  e tutto il testo neutralizzato.
- **Test:** ogni funzione ha test, compresi i casi di abuso (input malevoli, archivi con percorsi pericolosi,
  permessi sbagliati). Nessun test tocca file reali.

## Uso responsabile

Apernix è uno strumento offensivo se usato male. Va usato **solo su sistemi di cui sei proprietario o per cui hai
un'autorizzazione scritta**. Gli autori non rispondono dell'uso improprio.

## Informazioni sensibili

I report descrivono i punti deboli di un sistema: conservali in un posto protetto e condividili solo con chi deve
correggere i problemi. Non inserire nel repository `scope.toml`, report, certificati o chiavi (sono già in `.gitignore`).
