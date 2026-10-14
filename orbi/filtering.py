"""Content filtering: which family-DNS service the router uses, changed safely.

Every change snapshots the router's Internet settings, applies the new DNS, then checks
within two minutes that (1) nothing else in the Internet settings changed, (2) the
internet still works, and (3) the provider's filtering is really in effect. If any
check fails, the previous DNS servers are restored automatically.
"""
import base64
import ipaddress
import logging
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from . import config, dpapi
from .routerui import RouterUI, RouterUIError

log = logging.getLogger("orbi.filtering")

YT_RESTRICTED = {"216.239.38.119": "moderate", "216.239.38.120": "strict"}

# kind: "family" blocks adult sites; "social" and "security" don't; "account" filters whatever the parent chose in
# their own account at that service, and only while the service knows this home's internet address.
PROVIDERS = {
    "adguard_family": {"name": "AdGuard Family", "dns": ["94.140.14.15", "94.140.15.16"], "youtube": True, "kind": "family",
                       "summary": "Blocks adult sites, forces SafeSearch, YouTube Restricted Mode. Reddit allowed. Also blocks ads and trackers, which breaks some streaming apps (ESPN won't play)."},
    "cleanbrowsing_family": {"name": "CleanBrowsing Family", "dns": ["185.228.168.168", "185.228.169.168"], "youtube": True, "kind": "family",
                             "summary": "Blocks adult sites, VPN/proxy sites and Reddit; forces SafeSearch and YouTube Restricted Mode."},
    "cleanbrowsing_adult": {"name": "CleanBrowsing Adult", "dns": ["185.228.168.10", "185.228.169.11"], "youtube": False, "kind": "family",
                            "summary": "Blocks adult sites and forces SafeSearch. YouTube unrestricted."},
    "cloudflare_family": {"name": "Cloudflare for Families", "dns": ["1.1.1.3", "1.0.0.3"], "youtube": False, "kind": "family",
                          "summary": "Blocks malware and adult sites. No YouTube restriction."},
    "controld_family": {"name": "Control D Family", "dns": ["76.76.2.4", "76.76.10.4"], "youtube": True, "kind": "family",
                        "summary": "Blocks adult sites; forces Google and Bing SafeSearch and YouTube Restricted Mode (strict). Reddit allowed."},
    "opendns_familyshield": {"name": "OpenDNS FamilyShield", "dns": ["208.67.222.123", "208.67.220.123"], "youtube": False, "kind": "family",
                             "summary": "Blocks adult sites and some proxy sites. No SafeSearch or YouTube restriction."},
    "controld_social": {"name": "Control D No Social", "dns": ["76.76.2.3", "76.76.10.3"], "youtube": False, "kind": "social",
                        "summary": "Blocks social media (Facebook, Instagram, TikTok, Reddit and more), ads and malware. Does NOT block adult sites or force SafeSearch."},
    "quad9": {"name": "Quad9", "dns": ["9.9.9.9", "149.112.112.112"], "youtube": False, "kind": "security",
              "summary": "Blocks malware and phishing sites only. Adult sites are NOT blocked."},
    "cloudflare_security": {"name": "Cloudflare Malware Blocking", "dns": ["1.1.1.2", "1.0.0.2"], "youtube": False, "kind": "security",
                            "summary": "Blocks malware and phishing sites only. Adult sites are NOT blocked."},
    "cleanbrowsing_security": {"name": "CleanBrowsing Security", "dns": ["185.228.168.9", "185.228.169.9"], "youtube": False, "kind": "security",
                               "summary": "Blocks malware and phishing sites only. Adult sites are NOT blocked."},
    "nextdns": {"name": "NextDNS (your account)", "dns": [], "youtube": False, "kind": "account",
                "summary": "Blocks whatever you choose in your NextDNS account: adult sites, individual apps, SafeSearch, YouTube. Needs a NextDNS account set up first."},
    "opendns_home": {"name": "OpenDNS Home (your account)", "dns": [], "youtube": False, "kind": "account",
                     "summary": "Blocks the categories you choose in your OpenDNS dashboard. Needs an OpenDNS Home account with your network added first."},
}
OPENDNS_HOME_DNS = ["208.67.222.222", "208.67.220.220"]
ADULT_BLOCKED_PREFIXES = ("185.228.168.", "185.228.169.", "146.112.61.")  # CleanBrowsing and OpenDNS block pages
NEXTDNS_LINK = re.compile(r"https://link-ip\.nextdns\.io/[A-Za-z0-9]{4,32}/[A-Za-z0-9]{8,64}/?")
OPENDNS_REPLIES = {
    "badauth": "OpenDNS rejected the email or password",
    "nohost": "OpenDNS has no network with that name on your account",
    "!yours": "that network belongs to a different OpenDNS account",
    "abuse": "OpenDNS blocked updates for this account; sign in at opendns.com",
    "911": "OpenDNS is having problems; trying again later",
}


def providers(settings: dict | None = None) -> dict:
    """PROVIDERS, with the account services' DNS servers filled in once their account is connected."""
    s = settings or config.load()
    out = {k: dict(v) for k, v in PROVIDERS.items()}
    if s.get("nextdns_link_enc"):
        out["nextdns"]["dns"] = list(s.get("nextdns_dns") or [])
    if s.get("opendns_password_enc"):
        out["opendns_home"]["dns"] = list(OPENDNS_HOME_DNS)
    return out


def provider_for(dns_servers, settings: dict | None = None) -> str | None:
    for key, p in providers(settings).items():
        if dns_servers and dns_servers[0] in p["dns"]:
            return key
    return None


def blocks_adult(key: str | None) -> bool:
    return bool(key) and PROVIDERS[key]["kind"] in ("family", "account")


# ---- account services: keep them told which internet address is this home ----
def save_nextdns(dns_servers: list[str], link: str | None) -> dict:
    dns_servers = [d.strip() for d in dns_servers if d and d.strip()]
    if len(dns_servers) != 2:
        raise ValueError("Enter both DNS addresses from the Linked IP section of your NextDNS setup page")
    for d in dns_servers:
        try:
            ip = ipaddress.ip_address(d)
        except ValueError:
            raise ValueError(f"{d} isn't an IP address") from None
        if ip.version != 4 or not ip.is_global:
            raise ValueError(f"{d} isn't a public IPv4 address; copy the two from NextDNS's Linked IP section")
    patch = {"nextdns_dns": dns_servers}
    if link:
        link = link.strip()
        if not NEXTDNS_LINK.fullmatch(link):
            raise ValueError("The update link should look like https://link-ip.nextdns.io/abc123/xyz789…")
        patch["nextdns_link_enc"] = dpapi.protect(link)
    elif not config.load().get("nextdns_link_enc"):
        raise ValueError("Paste the update link from the Linked IP section of your NextDNS setup page")
    return config.save(patch)


def save_opendns(user: str, password: str | None, network: str) -> dict:
    user, network = user.strip(), network.strip()
    if not 3 <= len(user) <= 128 or not user.isprintable() or " " in user:
        raise ValueError("Enter the email you sign in to OpenDNS with")
    if network and not re.fullmatch(r"[A-Za-z0-9 _.\-]{1,64}", network):
        raise ValueError("Network name can only have letters, numbers, spaces, dots, dashes and underscores")
    patch = {"opendns_user": user, "opendns_network": network}
    if password:
        if len(password) > 128 or not password.isprintable():
            raise ValueError("The password must be up to 128 characters")
        patch["opendns_password_enc"] = dpapi.protect(password)
    elif not config.load().get("opendns_password_enc"):
        raise ValueError("Enter your OpenDNS password")
    return config.save(patch)


def _get(url: str, headers: dict | None = None) -> tuple[int, str]:
    from .updater import RUNNING
    req = urllib.request.Request(url, headers={"User-Agent": f"OrbiControl/{RUNNING}", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read(512).decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as e:
        return e.code, e.read(512).decode("utf-8", "replace").strip()


def refresh_account(key: str, settings: dict | None = None) -> dict:
    """Tell an account service this home's current internet address. {"ok": bool, "detail": str}, never raises."""
    s = settings or config.load()
    try:
        if key == "nextdns":
            if not s.get("nextdns_link_enc"):
                return {"ok": False, "detail": "NextDNS isn't connected yet"}
            code, body = _get(dpapi.unprotect(s["nextdns_link_enc"]))
            if code == 200:
                return {"ok": True, "detail": f"NextDNS is linked to {body}" if body else "NextDNS link updated"}
            return {"ok": False, "detail": f"NextDNS refused the update link (HTTP {code}); copy it again from your setup page"}
        if key == "opendns_home":
            if not s.get("opendns_password_enc"):
                return {"ok": False, "detail": "OpenDNS isn't connected yet"}
            auth = base64.b64encode(f"{s['opendns_user']}:{dpapi.unprotect(s['opendns_password_enc'])}".encode()).decode()
            url = "https://updates.opendns.com/nic/update"
            if s.get("opendns_network"):
                url += "?" + urllib.parse.urlencode({"hostname": s["opendns_network"]})
            code, body = _get(url, {"Authorization": f"Basic {auth}"})
            word = body.split()[0] if body else ""
            if code == 200 and word in ("good", "nochg"):
                return {"ok": True, "detail": f"OpenDNS knows your home is {body.split()[-1]}"}
            return {"ok": False, "detail": OPENDNS_REPLIES.get(word) or f"OpenDNS answered {code} {body[:60]}".strip()}
        return {"ok": False, "detail": f"{key} has no account to update"}
    except OSError as e:
        return {"ok": False, "detail": f"couldn't reach {PROVIDERS[key]['name']}: {e}"}


def _resolve_via_router(router_ip: str, name: str) -> list[str]:
    import dns.message
    import dns.query
    r = dns.query.udp(dns.message.make_query(name, "A"), router_ip, timeout=4)
    return [rr.address for rrset in r.answer for rr in rrset if rrset.rdtype == 1]


def check(router_ip: str) -> dict:
    """What the router's DNS currently does (asks the router, like every device does)."""
    out = {"youtube": None, "safesearch": None, "adult_blocked": None, "internet": False}
    try:
        yt = _resolve_via_router(router_ip, "www.youtube.com")
        out["youtube"] = next((YT_RESTRICTED[i] for i in yt if i in YT_RESTRICTED), "unrestricted")
        out["safesearch"] = "216.239.38.120" in _resolve_via_router(router_ip, "www.google.com")
        adult = _resolve_via_router(router_ip, "pornhub.com")
        out["adult_blocked"] = not adult or adult[0] in ("0.0.0.0", "94.140.14.35") or adult[0].startswith(ADULT_BLOCKED_PREFIXES)
    except Exception as e:
        out["error"] = str(e)
    for host in ("1.1.1.1", "8.8.8.8"):
        try:
            socket.create_connection((host, 443), timeout=4).close()
            out["internet"] = True
            break
        except OSError:
            pass
    return out


def apply_provider(host: str, password: str, key: str, verify_timeout: float = 120) -> dict:
    if key not in PROVIDERS:
        raise ValueError(f"Unknown provider {key}")
    provider = providers()[key]
    if not provider["dns"]:
        raise ValueError(f"Connect your {provider['name']} first")
    with RouterUI(host, password) as ui:
        before = ui.ether_snapshot()
        f = ui.form("BAS_ether.htm")
        old = [f.get("wan_dns1_pri"), f.get("wan_dns1_sec")] if f.get("DNSAssign") == "1" else None
        log.info("switching DNS %s -> %s", old, provider["dns"])
        ui.set_dns(*provider["dns"])
        after = ui.ether_snapshot()
    problems = [f"{k} changed ({before[k]} -> {after[k]})" for k in before if before[k] != after[k]]

    # Roll back only for real breakage: other settings changed, or no internet.
    status, deadline = {}, time.time() + verify_timeout
    while not problems and time.time() < deadline:
        status = check(host)
        if status["internet"] and "error" not in status:
            break
        time.sleep(8)
    else:
        if not problems:
            problems.append(f"the internet didn't come back within {int(verify_timeout)}s: {status}")
    if not problems:
        # Filtering can take a few minutes to show while the router's DNS cache expires.
        confirm_deadline = time.time() + 360
        while provider["youtube"] and status.get("youtube") not in ("moderate", "strict") and time.time() < confirm_deadline:
            time.sleep(15)
            status = check(host)
        return {"ok": True, "provider": key, "status": status, "previous": old,
                "confirmed": status.get("youtube") in ("moderate", "strict") if provider["youtube"] else True}

    log.error("DNS change failed (%s); rolling back to %s", problems, old)
    if old:
        with RouterUI(host, password) as ui:
            ui.set_dns(*old)
    raise RouterUIError("Change undone: " + "; ".join(problems))
