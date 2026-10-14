import pytest

from orbi import config, filtering

from .test_advanced import client, wait_job  # noqa: F401 (client is a fixture)

LINK = "https://link-ip.nextdns.io/abc123/0123456789abcdef"


def test_new_services_detected(tmp_config):
    assert filtering.provider_for(["76.76.2.4", "76.76.10.4"]) == "controld_family"
    assert filtering.provider_for(["208.67.222.123"]) == "opendns_familyshield"
    assert filtering.provider_for(["9.9.9.9"]) == "quad9"
    assert filtering.blocks_adult("controld_family") and not filtering.blocks_adult("quad9")
    assert not filtering.blocks_adult("controld_social") and not filtering.blocks_adult(None)


def test_account_services_only_count_once_connected(tmp_config):
    # plain OpenDNS without an account filters nothing, so it must not show up as "OpenDNS Home"
    assert filtering.provider_for(["208.67.222.222"]) is None
    assert filtering.providers()["nextdns"]["dns"] == []
    filtering.save_opendns("me@example.com", "pw", "")
    filtering.save_nextdns(["45.90.28.7", "45.90.30.7"], LINK)
    assert filtering.provider_for(["208.67.222.222"]) == "opendns_home"
    assert filtering.provider_for(["45.90.28.7", "45.90.30.7"]) == "nextdns"


def test_account_secrets_are_encrypted(tmp_config):
    filtering.save_opendns("me@example.com", "hunter2-secret", "Home")
    filtering.save_nextdns(["45.90.28.7", "45.90.30.7"], LINK)
    raw = (tmp_config / "settings.json").read_text("utf-8")
    assert "hunter2-secret" not in raw and "0123456789abcdef" not in raw
    # blank password / link keeps the saved one
    filtering.save_opendns("me@example.com", None, "Home")
    filtering.save_nextdns(["45.90.28.8", "45.90.30.8"], None)
    assert config.load()["opendns_password_enc"] and config.load()["nextdns_link_enc"]


@pytest.mark.parametrize("dns, link, msg", [
    (["45.90.28.7"], LINK, "both"),
    (["45.90.28.7", "nope"], LINK, "isn't an IP"),
    (["45.90.28.7", "192.168.1.1"], LINK, "public"),
    (["45.90.28.7", "45.90.30.7"], "https://evil.example.com/x/y", "link-ip.nextdns.io"),
    (["45.90.28.7", "45.90.30.7"], None, "Paste the update link"),
])
def test_nextdns_validation(tmp_config, dns, link, msg):
    with pytest.raises(ValueError, match=msg):
        filtering.save_nextdns(dns, link)


def test_opendns_validation(tmp_config):
    with pytest.raises(ValueError, match="email"):
        filtering.save_opendns("a b", "pw", "")
    with pytest.raises(ValueError, match="password"):
        filtering.save_opendns("me@example.com", None, "")
    with pytest.raises(ValueError, match="Network name"):
        filtering.save_opendns("me@example.com", "pw", "home;rm")


@pytest.mark.parametrize("reply, ok, words", [
    ((200, "good 1.2.3.4"), True, "1.2.3.4"),
    ((200, "nochg 1.2.3.4"), True, "1.2.3.4"),
    ((200, "badauth"), False, "rejected"),
    ((200, "nohost"), False, "no network"),
    ((500, "oops"), False, "500"),
])
def test_opendns_replies(tmp_config, monkeypatch, reply, ok, words):
    sent = {}
    monkeypatch.setattr(filtering, "_get", lambda url, headers=None: sent.update(url=url, headers=headers) or reply)
    filtering.save_opendns("me@example.com", "pw", "Home Net")
    r = filtering.refresh_account("opendns_home")
    assert r["ok"] is ok and words in r["detail"]
    assert sent["url"].endswith("?hostname=Home+Net") and sent["headers"]["Authorization"].startswith("Basic ")


def test_nextdns_refresh(tmp_config, monkeypatch):
    filtering.save_nextdns(["45.90.28.7", "45.90.30.7"], LINK)
    monkeypatch.setattr(filtering, "_get", lambda url, headers=None: (200, "1.2.3.4") if url == LINK else (0, ""))
    assert filtering.refresh_account("nextdns") == {"ok": True, "detail": "NextDNS is linked to 1.2.3.4"}
    monkeypatch.setattr(filtering, "_get", lambda url, headers=None: (403, "bad"))
    assert not filtering.refresh_account("nextdns")["ok"]


def test_unreachable_service_never_raises(tmp_config, monkeypatch):
    filtering.save_nextdns(["45.90.28.7", "45.90.30.7"], LINK)

    def boom(url, headers=None):
        raise OSError("no route")
    monkeypatch.setattr(filtering, "_get", boom)
    assert filtering.refresh_account("nextdns") == {"ok": False, "detail": "couldn't reach NextDNS (your account): no route"}


def test_opendns_block_page_counts_as_blocked(monkeypatch):
    answers = {"www.youtube.com": ["142.251.153.4"], "www.google.com": ["142.251.153.119"], "pornhub.com": ["146.112.61.106"]}
    monkeypatch.setattr(filtering, "_resolve_via_router", lambda ip, name: answers[name])
    monkeypatch.setattr(filtering.socket, "create_connection", lambda *a, **k: type("C", (), {"close": lambda self: None})())
    assert filtering.check("192.168.1.1")["adult_blocked"] is True


def test_account_service_needs_connection_and_confirmation(client, monitor, monkeypatch):
    applied = []
    monkeypatch.setattr(filtering, "apply_provider", lambda host, pw, key: applied.append(key) or {"ok": True, "confirmed": True})
    monkeypatch.setattr("orbi.routercert.gateway_mac", lambda host: None)
    r = client.post("/api/filtering", json={"provider": "nextdns", "account_ready": True})
    assert r.status_code == 400 and "Connect" in r.json()["detail"]

    monkeypatch.setattr(filtering, "_get", lambda url, headers=None: (200, "1.2.3.4"))
    r = client.put("/api/filtering/account/nextdns", json={"dns": ["45.90.28.7", "45.90.30.7"], "link": LINK})
    assert r.status_code == 200 and r.json()["ok"]
    got = client.get("/api/filtering").json()
    assert got["accounts"]["nextdns"]["connected"] and got["accounts"]["nextdns"]["last"]["ok"]
    assert LINK not in str(got)

    r = client.post("/api/filtering", json={"provider": "nextdns"})
    assert r.status_code == 400 and "Confirm" in r.json()["detail"]
    assert applied == []
    assert client.post("/api/filtering", json={"provider": "nextdns", "account_ready": True}).status_code == 200
    assert wait_job(client, "filtering")["error"] is None and applied == ["nextdns"]


def test_router_untouched_if_account_cant_be_linked(client, monitor, monkeypatch):
    applied = []
    monkeypatch.setattr(filtering, "apply_provider", lambda host, pw, key: applied.append(key) or {"ok": True})
    monkeypatch.setattr(filtering, "_get", lambda url, headers=None: (200, "badauth"))
    client.put("/api/filtering/account/opendns_home", json={"user": "me@example.com", "password": "wrong"})
    assert client.post("/api/filtering", json={"provider": "opendns_home", "account_ready": True}).status_code == 200
    j = wait_job(client, "filtering")
    assert "Router not changed" in j["error"] and "rejected" in j["error"] and applied == []


def test_unknown_account_and_bad_input(client):
    assert client.put("/api/filtering/account/quad9", json={}).status_code == 404
    assert client.put("/api/filtering/account/nextdns", json={"dns": ["1.1.1.1"], "link": LINK}).status_code == 400


def test_background_relink_alerts_once_and_records_recovery(monitor, monkeypatch):
    filtering.save_opendns("me@example.com", "pw", "")
    monitor.state["wan"] = {"dns": ["208.67.222.222", "208.67.220.220"]}
    reply = [(200, "badauth")]
    monkeypatch.setattr(filtering, "_get", lambda url, headers=None: reply[0])
    monitor.refresh_dns_account("opendns_home", quiet=True)  # a parent saving it doesn't count
    monitor._dns_account_tick()
    assert monitor.notes == []
    monitor._dns_account_tick()
    monitor._dns_account_tick()
    assert [n[0] for n in monitor.notes] == ["Content filter may have stopped"]
    reply[0] = (200, "nochg 1.2.3.4")
    monitor._dns_account_tick()
    titles = [e["title"] for e in monitor.store.q("SELECT title FROM events WHERE kind='filter_account' ORDER BY id")]
    assert titles == ["OpenDNS Home (your account) may have stopped filtering", "OpenDNS Home (your account) is filtering again"]


def test_no_relink_for_other_services(monitor, monkeypatch):
    monkeypatch.setattr(filtering, "_get", lambda url, headers=None: pytest.fail("shouldn't call out"))
    monitor.state["wan"] = {"dns": ["76.76.2.4", "76.76.10.4"]}
    monitor._dns_account_tick()


def test_switch_to_security_only_alerts(monitor):
    monitor._watch_filter(["76.76.2.4", "76.76.10.4"])
    monitor._watch_filter(["9.9.9.9", "149.112.112.112"])
    assert monitor.notes == [("Adult-site filtering turned off",
                              "The router switched from Control D Family to Quad9, which doesn't block adult sites")]
    monitor._watch_filter(["185.228.168.168", "185.228.169.168"])  # back to a family filter: not an alert
    assert len(monitor.notes) == 1
