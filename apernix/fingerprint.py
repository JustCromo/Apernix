"""Fingerprint: capire che tecnologie ha davanti Apernix, per scegliere i controlli giusti."""

from __future__ import annotations

from apernix.term import clean
from apernix.web.http import Response

COOKIE_HINTS = {
    "phpsessid": "PHP", "jsessionid": "Java (servlet)", "asp.net_sessionid": "ASP.NET",
    "csrftoken": "Django", "sessionid": "Django", "connect.sid": "Node.js (Express)",
    "laravel_session": "Laravel (PHP)", "session": "Flask (probabile)", "_rails_session": "Ruby on Rails",
}
HEADER_HINTS = {"werkzeug": "Flask/Werkzeug (Python)", "gunicorn": "Gunicorn (Python)",
                "uvicorn": "Uvicorn (Python)", "express": "Node.js (Express)", "php": "PHP",
                "nginx": "nginx", "apache": "Apache httpd", "caddy": "Caddy", "microsoft-iis": "IIS",
                "jetty": "Jetty (Java)", "tomcat": "Tomcat (Java)"}


def from_response(resp: Response) -> dict:
    tech: list[str] = []
    for name in ("server", "x-powered-by"):
        value = resp.headers.get(name, "").lower()
        for key, label in HEADER_HINTS.items():
            if key in value and label not in tech:
                tech.append(label)
    for raw in resp.set_cookies[:50]:
        cname = raw.split("=", 1)[0].strip().lower()
        label = COOKIE_HINTS.get(cname)
        if label == "Flask (probabile)" and any(x.startswith("Flask") for x in tech):
            continue
        if label and label not in tech:
            tech.append(label)
    return {
        "url": clean(resp.url),
        "status": resp.status,
        "server": clean(resp.headers.get("server", ""), 120),
        "powered_by": clean(resp.headers.get("x-powered-by", ""), 120),
        "technologies": [clean(x, 80) for x in tech],
    }
