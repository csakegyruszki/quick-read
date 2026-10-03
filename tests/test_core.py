"""quick-read tests. Real URLs and real addresses only; no invented page content.

Network tests are marked `network` and SKIP (never pass) when the network is unreachable.
Run: python -m pytest -v        (offline only: python -m pytest -m "not network")
"""
import ipaddress

import pytest

import quick_read as Q
from quick_read import core


_NET_MARKERS = ("ConnectError", "ConnectTimeout", "ReadTimeout", "NetworkError", "getaddrinfo", "DNS:")


def _is_network_failure(r) -> bool:
    msg = str(r.get("message", ""))
    return (r.get("error") == "FETCH_FAILED" and not msg.startswith("unexpected error")
            and any(m in msg for m in _NET_MARKERS))


def _net(r):
    """Skip only when the fetch failed because the network is unreachable. Any other
    FETCH_FAILED (an "unexpected error", too many redirects, ...) is a real failure."""
    if _is_network_failure(r):
        pytest.skip(f"network unavailable: {r.get('message')}")
    if r.get("error") == "FETCH_FAILED":
        pytest.fail(f"FETCH_FAILED that is not a network outage: {r.get('message')}")


def test_net_helper_skips_only_on_network_errors():
    for msg in ("ConnectError: [Errno 11001] getaddrinfo failed", "ConnectTimeout: timed out",
                "ReadTimeout: x", "DNS: [Errno -2] Name or service not known", "NetworkError: x"):
        with pytest.raises(pytest.skip.Exception):
            _net({"ok": False, "error": "FETCH_FAILED", "message": msg})
    for msg in ("unexpected error: ValueError: boom", "unexpected error: ConnectError: wrapped",
                "more than 5 redirects", "total time > 15.0s"):
        with pytest.raises(pytest.fail.Exception):
            _net({"ok": False, "error": "FETCH_FAILED", "message": msg})
    _net({"ok": True})  # a success neither skips nor fails


# ---- guards: no network needed (addresses are literals) -------------------------------

def test_invalid_input():
    assert Q.quick_read("not a url")["error"] == "BAD_INPUT"
    assert Q.quick_read("")["error"] == "BAD_INPUT"
    assert Q.quick_read(None)["error"] == "BAD_INPUT"  # type: ignore[arg-type]


@pytest.mark.parametrize("url", ["file:///etc/passwd", "file:///C:/Windows/win.ini",
                                 "ftp://example.com/x", "gopher://example.com/"])
def test_scheme_blocked(url):
    assert Q.quick_read(url)["error"] == "BAD_INPUT"


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:1/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://100.64.1.1/",            # CGNAT, missed by is_private
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",    # IPv4-mapped IPv6 loopback
    "http://[::ffff:10.0.0.1]/",
    "http://[fe80::1]/",
    "http://0.0.0.0/",
    "http://[64:ff9b::7f00:1]/",             # NAT64 embedding 127.0.0.1
    "http://[64:ff9b::a9fe:a9fe]/",          # NAT64 embedding 169.254.169.254
    "http://[64:ff9b:1::7f00:1]/",           # local-use NAT64 (RFC 8215)
    "http://[::7f00:1]/",                    # IPv4-compatible 127.0.0.1
    "http://[::a00:1]/",                     # IPv4-compatible 10.0.0.1
    "http://[2002:7f00:1::1]/",              # 6to4 embedding 127.0.0.1
    "http://[2001:0:4136:e378:8000:63bf:f5ff:fffe]/",  # Teredo, client 10.0.0.1
])
def test_ssrf_blocked(url):
    assert Q.quick_read(url).get("error") == "BLOCKED_ADDRESS", url


@pytest.mark.parametrize("addr,allowed", [
    ("127.0.0.1", False), ("10.0.0.1", False), ("169.254.169.254", False),
    ("100.64.1.1", False), ("::1", False), ("::ffff:127.0.0.1", False),
    ("224.0.0.1", False), ("8.8.8.8", True), ("2606:4700:4700::1111", True),
    ("64:ff9b::7f00:1", False), ("64:ff9b::a9fe:a9fe", False), ("::7f00:1", False),
    ("64:ff9b:1::7f00:1", False), ("2002:7f00:1::1", False), ("2002:a00:1::1", False),
    ("2001:0:4136:e378:8000:63bf:f5ff:fffe", False),
    ("64:ff9b::808:808", True),      # NAT64 to a public IPv4 stays reachable
    ("2002:808:808::1", True),       # 6to4 of a public IPv4
])
def test_ip_allowed(addr, allowed):
    assert core._ip_allowed(ipaddress.ip_address(addr)) is allowed


def test_user_agent_non_identifying():
    assert core.UA.startswith("quick-read/")
    assert "https://github.com/csakegyruszki/quick-read" in core.UA
    assert "@" not in core.UA


def test_limits():
    assert core.MAX_BYTES == 5 * 1024 * 1024
    assert core.MAX_HOPS == 5
    assert core.TOTAL_S == 15.0
    assert core.TIMEOUT.connect == 5.0


# ---- network tests --------------------------------------------------------------------

@pytest.mark.network
def test_wikipedia_article():
    r = Q.quick_read("https://en.wikipedia.org/wiki/Python_(programming_language)")
    _net(r)
    assert r["ok"], r
    assert r["status"] == 200
    assert "Guido van Rossum" in r["text"]
    assert "UNTRUSTED" in r["text"]
    assert len(r["sha256_raw"]) == 64 and len(r["sha256_text"]) == 64
    assert r["needs_render"] is False


@pytest.mark.network
def test_pdf_unsupported():
    r = Q.quick_read("https://arxiv.org/pdf/1706.03762")
    _net(r)
    assert r.get("error") == "UNSUPPORTED_TYPE", r
    assert "PDF" in r["hint"]
    assert "text" not in r


@pytest.mark.network
def test_on_capture_callback_and_error_isolation():
    seen = {}

    def ok(result, raw):
        seen["n"] = len(raw)
        seen["sha"] = result["sha256_raw"]

    r = Q.quick_read("https://www.gov.uk/government/organisations/hm-treasury", on_capture=ok)
    _net(r)
    assert r["ok"], r
    assert seen["n"] > 0 and seen["sha"] == r["sha256_raw"]

    def boom(result, raw):
        raise RuntimeError("callback failure")

    r2 = Q.quick_read("https://www.gov.uk/government/organisations/hm-treasury", on_capture=boom)
    _net(r2)
    assert r2["ok"] and "capture_error" in r2


# Measurement on 5 real benign pages (see README, "Known limits").
# Measured 2026-10-03; pages change, so only the field contract is asserted for risk,
# and the known false positive is recorded as a non-failing observation in
# test_observation_ipaddress_page_false_positive.
BENIGN = [
    "https://en.wikipedia.org/wiki/Python_(programming_language)",
    "https://www.bbc.co.uk/news/articles/c6y9z9r4ejzwo",
    "https://docs.python.org/3/library/ipaddress.html",
    "https://github.com/psf/requests",
    "https://www.gov.uk/government/organisations/hm-treasury",
]


@pytest.mark.network
@pytest.mark.parametrize("url", BENIGN)
def test_benign_page_contract(url):
    r = Q.quick_read(url, max_chars=10**7)
    _net(r)
    assert r["ok"], r
    assert r["injection_risk"] in ("CLEAN", "LOW", "MED", "HIGH")
    if r["injection_risk"] in ("HIGH", "MED"):
        assert "warning" in r


@pytest.mark.network
def test_observation_ipaddress_page_false_positive(record_property):
    """Observation, not a pass/fail claim about the scorer: on 2026-10-03 this page scored HIGH
    through the `act as` role pattern ("can act as containers"). The test records whatever the
    risk is today (pytest -rP / junit property `injection_risk`) and asserts only the field contract."""
    r = Q.quick_read("https://docs.python.org/3/library/ipaddress.html", max_chars=10**7)
    _net(r)
    assert r["ok"], r
    record_property("injection_risk", r["injection_risk"])
    print(f"OBSERVATION ipaddress page injection_risk={r['injection_risk']} (2026-10-03: HIGH)")
    assert r["injection_risk"] in ("CLEAN", "LOW", "MED", "HIGH")
