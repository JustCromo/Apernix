"""Scrittura dello scope dalla console guidata, senza modificare il TOML a mano.

- il file viene scritto in modo atomico (file temporaneo + rename) con permessi 600
- non si scrive mai attraverso un link simbolico
- prima di salvare, il risultato viene riletto e validato come qualsiasi altro scope
"""

from __future__ import annotations

import os
import tempfile

from apernix.scope import (
    LIMITS_DEFAULT,
    Scope,
    ScopeError,
    clean_name,
    parse_target_url,
    read_scope_doc,
    scope_from_dict,
)


def _q(value: str) -> str:
    """Stringa TOML sicura (virgolette e barre rovesciate escapate, niente caratteri di controllo)."""
    out = []
    for ch in value:
        if ch in ('"', "\\"):
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _d(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def to_toml(doc: dict) -> str:
    auth = _d(doc.get("authorization"))
    lines = ["# Scope di Apernix: SOLO i bersagli che hai il permesso di analizzare.",
             "# Scritto dalla console guidata; puoi modificarlo anche a mano (permessi 600).", "",
             "[authorization]", f"confirmed = {'true' if auth.get('confirmed') is True else 'false'}"]
    owner = auth.get("owner", "")
    if isinstance(owner, str) and owner:
        lines.append(f"owner = {_q(owner[:128])}")
    for tg in doc.get("target", []):
        lines += ["", "[[target]]", f"url = {_q(tg['url'])}"]
        if tg.get("name"):
            lines.append(f"name = {_q(tg['name'])}")
        if tg.get("ca_file"):
            lines.append(f"ca_file = {_q(tg['ca_file'])}")
    internal = doc.get("internal")
    if isinstance(internal, dict):
        lines += ["", "[internal]"]
        for key in ("transport", "path", "host", "user", "key", "db_container", "db_user", "db_name"):
            if isinstance(internal.get(key), str) and internal[key]:
                lines.append(f"{key} = {_q(internal[key])}")
        if isinstance(internal.get("port"), int) and not isinstance(internal.get("port"), bool):
            lines.append(f"port = {internal['port']}")
        cont = [c for c in internal.get("containers", []) if isinstance(c, str)]
        if cont:
            lines.append("containers = [" + ", ".join(_q(c) for c in cont) + "]")
    net = _d(doc.get("network"))
    lines += ["", "[network]", f"ports = {_q(str(net.get('ports', 'none')))}"]
    lim = {**LIMITS_DEFAULT, **_d(doc.get("limits"))}
    lines += ["", "[limits]", f"rate = {float(lim['rate'])}", f"max_requests = {int(lim['max_requests'])}",
              f"timeout = {float(lim['timeout'])}", ""]
    return "\n".join(lines)


def _write_atomic(path: str, text: str) -> None:
    if os.path.islink(path):
        raise ScopeError("err.scope_unsafe_file")
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".scope-", suffix=".toml", dir=folder)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def set_internal(path: str, internal: dict) -> Scope:
    """Salva la sezione [internal] nello scope (che deve già esistere). Validata prima di scrivere."""
    doc = read_scope_doc(path)
    keys = ("transport", "path", "host", "user", "port", "key", "containers", "db_container", "db_user", "db_name")
    doc["internal"] = {k: internal[k] for k in keys if k in internal}
    base = os.path.dirname(os.path.abspath(path))
    scope = scope_from_dict(doc, base)
    raw = doc.get("target")
    doc["target"] = [{k: it[k] for k in ("url", "name", "ca_file") if isinstance(it.get(k), str)}
                     for it in raw if isinstance(it, dict)] if isinstance(raw, list) else []
    _write_atomic(path, to_toml(doc))
    return scope


def add_target(path: str, url: str, name: str = "", ca_file: str = "", ports: str | None = None,
               rate: float | None = None) -> Scope:
    """Aggiunge un bersaglio allo scope (lo crea se manca). Va chiamata solo dopo la conferma
    esplicita dell'autorizzazione da parte dell'utente."""
    try:
        tg = parse_target_url(url)
    except ValueError as exc:
        raise ScopeError("err.scope_invalid", reason_key="scope.reason.bad_url", url=url[:200]) from exc
    if os.path.exists(path) or os.path.islink(path):
        doc = read_scope_doc(path)
    else:
        doc = {"network": {"ports": "top1000"}, "limits": dict(LIMITS_DEFAULT)}
    doc.setdefault("authorization", {})
    if not isinstance(doc["authorization"], dict):
        doc["authorization"] = {}
    doc["authorization"]["confirmed"] = True
    raw_targets = doc.get("target")
    targets = []
    for item in raw_targets if isinstance(raw_targets, list) else []:
        if isinstance(item, dict) and isinstance(item.get("url"), str):
            targets.append({k: item[k] for k in ("url", "name", "ca_file") if isinstance(item.get(k), str)})
    known = set()
    for item in targets:
        try:
            known.add(parse_target_url(item["url"]).url)
        except ValueError:
            pass
    if tg.url not in known:
        entry = {"url": tg.url, "name": clean_name(name)}
        if ca_file:
            entry["ca_file"] = ca_file
        targets.append(entry)
    elif ca_file:
        for item in targets:
            try:
                if parse_target_url(item["url"]).url == tg.url:
                    item["ca_file"] = ca_file
            except ValueError:
                pass
    doc["target"] = targets
    if rate is not None:
        doc["limits"] = {**_d(doc.get("limits")), "rate": rate}
    if ports is not None:
        doc["network"] = {**_d(doc.get("network")), "ports": ports}
    base = os.path.dirname(os.path.abspath(path))
    scope = scope_from_dict(doc, base)          # valida tutto prima di scrivere
    _write_atomic(path, to_toml(doc))
    return scope
