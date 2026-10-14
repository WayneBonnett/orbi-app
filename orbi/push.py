"""Phone alerts through ntfy (https://ntfy.sh, or a server you run): free, no account, iPhone and Android apps.

Anyone who knows the topic can read the alerts and post fake ones, so it's a long random name kept DPAPI-encrypted,
shown only on request (each showing goes in History), and replaceable with a new one at any time.
"""
import json
import logging
import queue
import secrets
import threading
import time
import urllib.error
import urllib.request

from . import config, dpapi

log = logging.getLogger("orbi.push")
DEFAULT_SERVER = "https://ntfy.sh"

_queue: "queue.Queue[tuple[str, str, int]]" = queue.Queue(maxsize=200)
_worker: threading.Thread | None = None
_lock = threading.Lock()


def enabled(settings: dict | None = None) -> bool:
    s = settings or config.load()
    return bool(s.get("push_enabled") and s.get("push_topic_enc"))


def topic(settings: dict | None = None) -> str:
    enc = (settings or config.load()).get("push_topic_enc")
    return dpapi.unprotect(enc) if enc else ""


def subscribe_url(settings: dict | None = None) -> str:
    s = settings or config.load()
    return f"{s.get('push_server') or DEFAULT_SERVER}/{topic(s)}"


def new_topic(server: str | None = None) -> dict:
    server = (server or DEFAULT_SERVER).strip().rstrip("/")
    if not server.startswith("https://") or len(server) > 200 or any(c in server for c in " ?#@"):
        raise ValueError("The ntfy server must be an https:// address")
    return config.save({"push_server": server, "push_topic_enc": dpapi.protect("orbi-" + secrets.token_urlsafe(18)),
                        "push_enabled": True})


def send_now(title: str, message: str, priority: int = 4, settings: dict | None = None) -> dict:
    """Send one alert and wait for the answer. {"ok": bool, "detail": str}; never raises."""
    s = settings or config.load()
    if not s.get("push_topic_enc"):
        return {"ok": False, "detail": "Phone alerts aren't set up"}
    body = json.dumps({"topic": topic(s), "title": title[:200], "message": message[:3000], "priority": priority,
                       "tags": ["house"]}).encode()
    req = urllib.request.Request(s.get("push_server") or DEFAULT_SERVER, data=body,
                                 headers={"Content-Type": "application/json", "User-Agent": "OrbiControl"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            res = {"ok": 200 <= r.status < 300, "detail": f"sent ({r.status})"}
    except urllib.error.HTTPError as e:
        res = {"ok": False, "detail": f"the ntfy server refused it (HTTP {e.code})"}
    except OSError as e:
        res = {"ok": False, "detail": f"couldn't reach the ntfy server: {e}"}
    config.save({"push_last": {**res, "ts": time.time()}})
    return res


def send(title: str, message: str, priority: int = 4):
    """Queue an alert for the phone. Never blocks the caller or raises; a no-op when phone alerts are off."""
    global _worker
    try:
        if not enabled():
            return
        _queue.put_nowait((title, message, priority))
    except Exception:
        log.exception("couldn't queue a phone alert")
        return
    with _lock:
        if not (_worker and _worker.is_alive()):
            _worker = threading.Thread(target=_drain, name="push", daemon=True)
            _worker.start()


def _drain():
    while True:
        try:
            title, message, priority = _queue.get(timeout=60)
        except queue.Empty:
            return
        for wait in RETRY_WAITS:  # keep trying for ~8 min: alerts often come right as the internet drops
            res = send_now(title, message, priority)
            if res["ok"]:
                break
            log.warning("phone alert not sent (%s)", res["detail"])
            if wait:
                time.sleep(wait)


RETRY_WAITS = (20, 40, 60, 120, 240, 0)
