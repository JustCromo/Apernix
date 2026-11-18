"""Certificati HTTPS non pubblici: fiducia al primo uso (TOFU), come fa SSH.

Apernix mostra chi ha emesso il certificato e la sua impronta SHA-256; se l'utente si fida,
salva il certificato più "alto" della catena presentata e da lì in poi si fida solo di quello.
Se il server cambia certificato, la verifica fallisce e Apernix lo segnala invece di proseguire.
"""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import tempfile

import certifi

MAX_CHAIN = 8
TRUST_DIR = ".apernix-trust"


def fetch_chain(host: str, port: int, timeout: float = 5.0) -> list[bytes]:
    """Scarica la catena di certificati presentata dal server, SENZA fidarsi (serve solo a mostrarla)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            if hasattr(tls, "get_unverified_chain"):          # Python 3.13+
                chain = [bytes(c) for c in (tls.get_unverified_chain() or [])][:MAX_CHAIN]
                if chain:
                    return chain
            leaf = tls.getpeercert(binary_form=True)
            return [leaf] if leaf else []


def publicly_trusted(host: str, port: int, timeout: float = 5.0) -> bool:
    """True se il certificato è valido per le CA pubbliche (le stesse usate da requests)."""
    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except (ssl.SSLError, ssl.CertificateError):
        return False


def fingerprint(der: bytes) -> str:
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _name(rdns) -> str:
    try:
        for rdn in rdns:
            for key, value in rdn:
                if key == "commonName":
                    return str(value)[:120]
        return ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)[:120]
    except (TypeError, ValueError):
        return "?"


def describe(der: bytes) -> dict:
    """Soggetto, emittente, scadenza e impronta di un certificato (DER)."""
    info = {"subject": "?", "issuer": "?", "not_after": "?", "sha256": fingerprint(der)}
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decode is None:
        return info
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as fh:
        fh.write(ssl.DER_cert_to_PEM_cert(der))
        fh.flush()
        try:
            data = decode(fh.name)
        except (ssl.SSLError, ValueError, OSError):
            return info
    info["subject"] = _name(data.get("subject", ()))
    info["issuer"] = _name(data.get("issuer", ()))
    info["not_after"] = str(data.get("notAfter", "?"))[:40]
    return info


def save_pin(scope_dir: str, host: str, port: int, der: bytes) -> str:
    """Salva il certificato accettato (permessi 600) e restituisce il percorso relativo allo scope."""
    folder = os.path.join(scope_dir, TRUST_DIR)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    safe_host = "".join(c if c.isalnum() or c in ".-" else "_" for c in host)[:100]
    name = f"{safe_host}_{int(port)}.pem"
    path = os.path.join(folder, name)
    if os.path.islink(path):
        os.unlink(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(ssl.DER_cert_to_PEM_cert(der))
    return os.path.join(TRUST_DIR, name)


def pinned_context(ca_file: str) -> ssl.SSLContext:
    """Contesto TLS che si fida SOLO del certificato indicato, anche se è un intermedio
    (PARTIAL_CHAIN). Il controllo del nome host resta attivo."""
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
    return ctx
