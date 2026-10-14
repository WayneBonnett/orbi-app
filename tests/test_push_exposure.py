import json
import time

import pytest

from orbi import config, exposure, push

from .test_advanced import client, wait_job  # noqa: F401 (client is a fixture)


@pytest.fixture
def sent(monkeypatch):
    """Every ntfy message the app tries to send, instead of sending it."""
    out = []

    def fake_send_now(title, message, priority=4, settings=None):
        s = settings or config.load()
        out.append({"topic": push.topic(s), "title": title, "message": message})
        return {"ok": True, "detail": "sent (200)"}
    monkeypatch.setattr(push, "send_now", fake_send_now)
    monkeypatch.setattr(push, "RETRY_WAITS", (0,))
    return out


def drain():
    for _ in range(100):
        if push._queue.empty() and not (push._worker and push._worker.is_alive() and not push._queue.empty()):
            time.sleep(0.05)
            return
        time.sleep(0.02)


# ---- phone alerts ----
def test_alerts_stay_on_the_pc_until_set_up(monitor, sent):
    monitor.notify("Something", "happened")
    drain()
    assert monitor.notes == [("Something", "happened")] and sent == []


def test_every_alert_goes_to_the_phone_once_set_up(monitor, sent):
    push.new_topic()
    monitor.notify("Content filter turned off", "The router no longer uses X")
    drain()
    assert monitor.notes == [("Content filter turned off", "The router no longer uses X")]
    assert [m["title"] for m in sent] == ["Content filter turned off"]


def test_topic_is_random_encrypted_and_server_must_be_https(tmp_config):
    a = push.topic(push.new_topic())
    b = push.topic(push.new_topic())
    assert a != b and a.startswith("orbi-") and len(a) > 20
    assert b not in (tmp_config / "settings.json").read_text("utf-8")
    with pytest.raises(ValueError):
        push.new_topic("http://ntfy.example.com")
    with pytest.raises(ValueError):
        push.new_topic("https://user@ntfy.example.com")


def test_send_now_posts_json_to_the_server(tmp_config, monkeypatch):
    push.new_topic("https://ntfy.example.com/")
    got = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    def fake_urlopen(req, timeout):
        got.update(url=req.full_url, body=json.loads(req.data))
        return Resp()
    monkeypatch.setattr(push.urllib.request, "urlopen", fake_urlopen)
    assert push.send_now("Hi", "there")["ok"]
    assert got["url"] == "https://ntfy.example.com" and got["body"]["title"] == "Hi" and got["body"]["topic"] == push.topic()
    assert config.load()["push_last"]["ok"]


def test_unreachable_server_never_raises(tmp_config, monkeypatch):
    push.new_topic()

    def boom(req, timeout):
        raise OSError("offline")
    monkeypatch.setattr(push.urllib.request, "urlopen", boom)
    assert push.send_now("Hi", "there") == {"ok": False, "detail": "couldn't reach the ntfy server: offline"}


def test_setup_show_and_new_code_api(client, sent):
    r = client.post("/api/push/setup", json={}).json()
    first = r["topic"]
    assert r["enabled"] and r["test"]["ok"] and "<svg" in r["qr_svg"] and r["url"].endswith(first)
    assert client.get("/api/push").json() == {**client.get("/api/push").json(), "configured": True, "enabled": True}
    assert "topic" not in client.get("/api/push").json()  # only shown on request

    shown = client.post("/api/push/show", json={}).json()
    drain()
    assert shown["topic"] == first
    assert any(m["title"] == "Phone-alert code was shown" for m in sent)
    assert any(e["title"] == "Phone-alert code shown" for e in client.get("/api/events").json())

    sent.clear()
    second = client.post("/api/push/setup", json={}).json()["topic"]
    assert second != first
    assert sent[0]["topic"] == first and sent[0]["title"] == "Phone alerts moved to a new code"  # old phone is told


def test_turning_alerts_off_tells_the_phone_first(client, sent):
    assert client.put("/api/push", json={"enabled": True}).status_code == 400  # not set up yet
    client.post("/api/push/setup", json={})
    sent.clear()
    assert client.put("/api/push", json={"enabled": False}).json()["enabled"] is False
    assert [m["title"] for m in sent] == ["Phone alerts turned off"]
    ev = next(e for e in client.get("/api/events").json() if e["title"] == "Phone alerts turned off")
    assert ev["severity"] == "warn"


def test_bad_server_is_rejected(client, sent):
    assert client.post("/api/push/setup", json={"server": "ftp://x"}).status_code == 400


# ---- remote-access watch ----
@pytest.fixture
def ports_open(monkeypatch):
    state = {}
    monkeypatch.setattr(exposure, "is_open", lambda ip, port, timeout=0.8: port in state.get(ip, ()))
    return state


def test_first_check_reports_what_is_already_open(monitor, ports_open):
    monitor.scan()  # kid-phone .20, kid-tablet .21, tv .22; this PC .58; router .1
    ports_open["192.168.1.58"] = {3389}
    now = monitor.check_exposure()
    assert now["this-pc"]["ports"] == [3389] and now["AA:00:00:00:00:01"]["ports"] == []
    assert monitor.notes == [("Remote access found", "First check of the house: This PC (192.168.1.58): Remote Desktop (3389)")]


def test_quiet_first_check(monitor, ports_open):
    monitor.scan()
    monitor.check_exposure()
    assert monitor.notes == []
    assert monitor.store.q("SELECT title FROM events WHERE kind='remote_access'")[0]["title"].startswith("Remote-access check: nothing")


def test_new_service_alerts_and_closing_is_recorded(monitor, ports_open):
    monitor.scan()
    monitor.check_exposure()
    ports_open["192.168.1.20"] = {22}
    monitor.check_exposure()
    assert monitor.notes[-1][0] == "Remote access opened on kid-phone" and "SSH (22)" in monitor.notes[-1][1]
    monitor.check_exposure()  # still open: no second alert
    assert len(monitor.notes) == 1
    ports_open["192.168.1.20"] = set()
    monitor.check_exposure()
    titles = [e["title"] for e in monitor.store.q("SELECT title FROM events WHERE kind='remote_access' ORDER BY id")]
    assert titles[-1] == "Remote access closed on kid-phone" and len(monitor.notes) == 1


def test_device_going_offline_and_back_is_not_new(monitor, ports_open, fake_router):
    monitor.scan()
    ports_open["192.168.1.21"] = {5900}
    monitor.check_exposure()
    notes = len(monitor.notes)
    fake_router.devs = [d for d in fake_router.devs if d["ip"] != "192.168.1.21"]
    monitor.scan()
    assert "AA:00:00:00:00:02" in monitor.check_exposure()  # remembered while offline
    fake_router.devs.append(fake_router._dev("AA:00:00:00:00:02", "kid-tablet", "192.168.1.21", "x"))
    monitor.scan()
    monitor.check_exposure()
    assert len(monitor.notes) == notes


def test_exposure_api(client, ports_open):
    ports_open["192.168.1.22"] = {5938}
    assert client.get("/api/exposure").json()["ts"] is None
    assert client.post("/api/exposure/scan", json={}).status_code == 200
    assert wait_job(client, "exposure")["error"] is None
    j = client.get("/api/exposure").json()
    assert j["devices"][0]["name"] == "tv" and j["devices"][0]["services"] == [{"port": 5938, "name": "TeamViewer"}]


def test_real_scan_finds_a_listening_port():
    import socket
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        assert exposure.scan(["127.0.0.1"], ports=[port, 1], timeout=0.5) == {"127.0.0.1": [port]}
    finally:
        srv.close()
