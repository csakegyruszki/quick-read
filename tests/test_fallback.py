"""Tests for quick_read.fallback. No live network: every HTTP call goes through the module's single
seam (`_http_get`) and is answered by a recorded-shape fake (Wayback availability / CDX JSON, a
challenge interstitial, robots.txt). Page text is taken from this repository's LICENSE file.

Run: python -m pytest tests/test_fallback.py -v
"""
import json
import time
from pathlib import Path

import pytest

from quick_read import core, fallback as fb

REAL_CHECK_HOST = core._check_host
REAL_HTTP_GET = fb._http_get
REAL_RENDER = fb._render
LICENSE = (Path(__file__).resolve().parent.parent / "LICENSE").read_text(encoding="utf-8")
PARAS = [" ".join(p.split()) for p in LICENSE.split("\n\n") if len(" ".join(p.split())) > 200]
BODY = "".join(f"<p>{p}</p>" for p in PARAS[:4])
ARTICLE = f"<html><head><title>Fixture article</title></head><body><article>{BODY}</article></body></html>".encode()
CF_PAGE = (b"<html><head><title>Just a moment...</title></head><body><div id='challenge-error-text'>"
           b"Enable JavaScript and cookies to continue</div>"
           b"<script src='/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1'></script></body></html>")
URL = "https://news.example.org/story/1"
HOST = "news.example.org"
TS = "20260102030405"


def resp(status=200, body=b"", ctype="text/html", headers=None, hosts=None, error=None, final_url=None):
    return {"status": status, "final_url": final_url, "ctype": ctype, "body": body, "charset": "utf-8",
            "headers": headers or {}, "hosts": hosts or [], "error": error, "message": ""}


class Net:
    """Routes _http_get calls: handler(url, ua) -> response dict. Records every call."""

    def __init__(self, handler):
        self.handler, self.calls = handler, []

    def __call__(self, url, *, ua, timeout, headers=None, follow=True, max_bytes=0):
        self.calls.append({"url": url, "ua": ua, "timeout": timeout, "follow": follow})
        r = self.handler(url, ua)
        r.setdefault("final_url", None)
        if r["final_url"] is None:
            r["final_url"] = url
        if not r["hosts"]:
            r["hosts"] = [fb.urlparse(url).hostname]
        return r

    def urls(self):
        return [c["url"] for c in self.calls]


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "_check_host", lambda url: None)   # no live DNS
    monkeypatch.setattr(fb, "_SLEEP", lambda s: None)
    monkeypatch.setattr(fb, "GAP_S", 0.0)
    monkeypatch.setattr(fb, "GAP_ARCHIVE_S", 0.0)
    # T2 would otherwise touch the real network; default = unreachable, tests override where needed
    monkeypatch.setattr(fb, "_core_fetch", lambda url: {
        "status": None, "final_url": url, "ctype": "", "body": b"", "charset": None, "headers": {},
        "hosts": [], "error": "connect_error"})
    fb._robots.clear()
    fb._next_slot.clear()
    monkeypatch.setenv("QUICK_READ_STATE_DIR", str(tmp_path / "state"))
    yield tmp_path
    fb._http_get, fb._render = REAL_HTTP_GET, REAL_RENDER


def run(url=URL, **kw):
    return fb.fetch_with_fallback(url, **kw)


def robots_404(url):
    return url.endswith("/robots.txt")


def live_handler(page=None, ua_rules=None):
    """robots.txt -> 404; page -> `page` response (or by UA)."""
    def h(url, ua):
        if robots_404(url):
            return resp(404, b"")
        if ua_rules:
            return ua_rules(ua)
        return page
    return h


# ----------------------------------------------------------------------------- challenge gate
def test_fixture_has_enough_text():
    assert len(fb._extract(ARTICLE, URL)) > fb.MIN_CHARS


def test_gate_interstitial_title_and_markup():
    assert fb.detect_challenge(CF_PAGE.decode(), "", 200) == "interstitial"
    markup_only = "<html><head><title>x</title></head><script src='/cdn-cgi/challenge-platform/h/b'></script></html>"
    assert fb.detect_challenge(markup_only, "", 200) == "cloudflare"
    assert fb.detect_challenge("<html></html>", "", 403) == "http_403"
    assert fb.detect_challenge("<html></html>", "", 429) == "http_429"


def test_gate_does_not_flag_real_content_with_a_captcha_widget():
    long_text = "word " * 1000
    page = "<html><title>Contact</title><form><div class='g-recaptcha'></div></form></html>"
    assert fb.detect_challenge(page, long_text, 200) is None
    assert fb.detect_challenge(page, "", 200) == "recaptcha"      # same widget, no real text: flagged


# ----------------------------------------------------------------------------- T1 / T2 / UA switch
def test_t1_success_wraps_text_and_records_egress(isolated):
    net = Net(live_handler(resp(200, ARTICLE)))
    fb._http_get = net
    r = run()
    assert r["ok"] and r["tier_used"] == 1 and r["stale"] is False and r["snapshot"] is None
    assert r["text"].startswith(fb.WRAP_OPEN) and r["text"].endswith(fb.WRAP_CLOSE)
    assert r["egress"] == [HOST]
    a1 = [a for a in r["attempts"] if a["tier"] == 1][0]
    assert a1["egress"] == [HOST] and a1["ok"] and a1["ua"] == "tool"
    assert r["sha256_raw"] and r["injection_risk"] in ("CLEAN", "LOW", "MED", "HIGH")


def test_t1_third_party_redirect_host_is_in_egress():
    net = Net(lambda url, ua: resp(404) if robots_404(url) else resp(200, ARTICLE, hosts=[HOST, "cdn.other.example"]))
    fb._http_get = net
    r = run()
    assert r["ok"] and r["egress"] == [HOST, "cdn.other.example"]


def test_ua_switch_after_plain_403(isolated):
    seen = []

    def rules(ua):
        seen.append(ua)
        return resp(403, b"<html><title>Forbidden</title></html>") if ua == fb.TOOL_UA else resp(200, ARTICLE)

    net = Net(live_handler(ua_rules=rules))
    fb._http_get = net
    r = run()
    assert r["ok"] and r["tier_used"] == 1
    assert seen == [fb.TOOL_UA, fb.BROWSER_UA]
    mem = json.loads((isolated / "state" / "domain-memory.json").read_text())
    assert mem[HOST]["ua"] == "browser" and mem[HOST]["tier"] == 1


def test_no_ua_switch_after_named_challenge():
    seen = []

    def rules(ua):
        seen.append(ua)
        return resp(403, CF_PAGE)

    net = Net(live_handler(ua_rules=rules))
    fb._http_get = net
    r = run(archives=False)
    assert not r["ok"]
    assert seen == [fb.TOOL_UA]          # one request: the browser UA was NOT tried
    assert "interstitial" in r["challenge"]["seen"]


def test_challenge_page_is_never_returned_as_content():
    net = Net(live_handler(resp(200, CF_PAGE)))      # HTTP 200 interstitial
    fb._http_get = net
    r = run(archives=False)
    assert r["ok"] is False and r["text"] == ""
    assert r["error"] == "challenge:interstitial"
    assert "Just a moment" not in json.dumps(r)


def test_t2_used_when_t1_is_thin(monkeypatch):
    thin = b"<html><title>t</title><body><p>short</p></body></html>"
    fb._http_get = Net(live_handler(resp(200, thin)))
    monkeypatch.setattr(fb, "_core_fetch", lambda url: {
        "status": 200, "final_url": url, "ctype": "text/html", "body": ARTICLE, "charset": "utf-8",
        "headers": {}, "hosts": [], "error": None})
    r = run()
    assert r["ok"] and r["tier_used"] == 2
    assert [a["error"] for a in r["attempts"] if a["tier"] == 1] == ["thin_content"]


def test_unsupported_type_stops_the_ladder():
    net = Net(live_handler(resp(200, b"%PDF-1.7", ctype="application/pdf")))
    fb._http_get = net
    r = run()
    assert r["ok"] is False and r["error"].startswith("unsupported_type")
    assert not any("archive" in u for u in net.urls())
    assert "PDF" in r["hint"]


# ----------------------------------------------------------------------------- per-tier timeouts
def test_per_tier_timeouts_are_passed():
    net = Net(live_handler(resp(200, ARTICLE)))
    fb._http_get = net
    run(timeouts={1: 3.5})
    page_calls = [c for c in net.calls if c["url"] == URL]
    assert page_calls[0]["timeout"] == 3.5


# ----------------------------------------------------------------------------- T4 archives
def availability(found=True):
    snap = {"closest": {"available": True, "timestamp": TS, "status": "200",
                        "url": f"http://web.archive.org/web/{TS}/{URL}"}} if found else {}
    return json.dumps({"url": URL, "archived_snapshots": snap}).encode()


CDX = json.dumps([["timestamp", "original"], ["20250101000000", URL], [TS, URL]]).encode()


def archive_handler(avail=None, cdx=CDX, snapshot=None, today=None):
    def h(url, ua):
        if robots_404(url):
            return resp(404)
        if url == URL:
            return resp(403, b"<html><title>Forbidden</title></html>")
        if url.startswith("https://archive.org/wayback/available"):
            return avail() if callable(avail) else resp(200, avail or availability(False), ctype="application/json")
        if "web.archive.org/cdx/search/cdx" in url:
            return resp(200, cdx, ctype="application/json")
        if url.startswith("https://web.archive.org/web/"):
            return snapshot or resp(200, ARTICLE)
        if url.startswith("https://archive.ph/"):
            return today or resp(404)
        raise AssertionError(f"unexpected URL {url}")
    return h


def test_wayback_availability_hit_is_stale_with_snapshot_date():
    net = Net(archive_handler(avail=availability(True)))
    fb._http_get = net
    r = run()
    assert r["ok"] and r["tier_used"] == 4 and r["stale"] is True
    assert r["snapshot"]["service"] == "wayback" and r["snapshot"]["timestamp"] == "2026-01-02T03:04:05Z"
    assert r["snapshot"]["snapshot_url"] == f"https://web.archive.org/web/{TS}id_/{URL}"
    w = [a for a in r["attempts"] if a["method"] == "wayback"][0]
    assert w["egress"] == ["archive.org", "web.archive.org"] and w["lookup"] == "availability#1"
    assert "web.archive.org" in r["egress"]


def test_wayback_empty_availability_falls_back_to_cdx_newest():
    net = Net(archive_handler(avail=availability(False)))
    fb._http_get = net
    r = run()
    w = [a for a in r["attempts"] if a["method"] == "wayback"][0]
    assert r["ok"] and w["lookup"] == "cdx" and w["snapshot_ts"] == TS          # newest row, not the first
    assert sum(u.startswith("https://archive.org/wayback/available") for u in net.urls()) == 2   # retried once


def test_wayback_429_backs_off_then_retries(monkeypatch):
    sleeps = []
    monkeypatch.setattr(fb, "_SLEEP", sleeps.append)
    answers = iter([resp(429, b""), resp(200, availability(True), ctype="application/json")])
    net = Net(archive_handler(avail=lambda: next(answers)))
    fb._http_get = net
    r = run()
    assert r["ok"] and [a for a in r["attempts"] if a["method"] == "wayback"][0]["lookup"] == "availability#2"
    assert 8.0 in sleeps


def test_archive_today_challenge_is_skipped_not_solved():
    redirect = resp(302, b"", headers={"location": f"https://archive.ph/AbCdE/{TS}/{URL}"})
    captcha = resp(200, b"<html><title>Verify you are human</title><div class='g-recaptcha'></div></html>")

    def h(url, ua):
        if url.startswith("https://archive.ph/newest/"):
            return redirect
        if url.startswith("https://archive.ph/"):
            return captcha
        return archive_handler(avail=availability(False), cdx=b"[]")(url, ua)

    net = Net(h)
    fb._http_get = net
    r = run()
    a = [a for a in r["attempts"] if a["method"] == "archive.today"][0]
    assert r["ok"] is False
    assert a["error"].startswith("challenge_skipped:") and a["ok"] is False
    assert net.urls().count(f"https://archive.ph/AbCdE/{TS}/{URL}") == 1      # one look, no solving, no retry


def test_archive_today_snapshot_used_when_clean():
    redirect = resp(302, b"", headers={"location": f"https://archive.ph/AbCdE/{TS}/{URL}"})

    def h(url, ua):
        if url.startswith("https://archive.ph/newest/"):
            return redirect
        if url.startswith("https://archive.ph/"):
            return resp(200, ARTICLE)
        return archive_handler(avail=availability(False), cdx=b"[]")(url, ua)

    fb._http_get = Net(h)
    r = run()
    assert r["ok"] and r["snapshot"]["service"] == "archive.today" and r["stale"] is True
    assert r["snapshot"]["timestamp"] == "2026-01-02T03:04:05Z"


def test_archive_snapshot_that_is_a_challenge_is_rejected():
    fb._http_get = Net(archive_handler(avail=availability(True), snapshot=resp(200, CF_PAGE)))
    r = run()
    assert r["ok"] is False and r["text"] == ""


def test_archives_can_be_switched_off():
    net = Net(archive_handler())
    fb._http_get = net
    r = run(archives=False)
    assert r["ok"] is False and not any("archive" in u for u in net.urls())


# ----------------------------------------------------------------------------- robots.txt
ROBOTS_DISALLOW = b"User-agent: *\nDisallow: /story/\n"


def test_robots_disallow_blocks_live_fetch_but_archives_still_asked():
    def h(url, ua):
        if url.endswith("/robots.txt"):
            return resp(200, ROBOTS_DISALLOW, ctype="text/plain")
        return archive_handler(avail=availability(True))(url, ua)

    net = Net(h)
    fb._http_get = net
    r = run()
    assert URL not in net.urls()
    assert r["ok"] and r["tier_used"] == 4 and r["stale"] is True
    assert any(a.get("error") == "robots_disallowed" for a in r["attempts"])


def test_robots_disallow_without_archives_is_an_error():
    net = Net(lambda url, ua: resp(200, ROBOTS_DISALLOW, ctype="text/plain"))
    fb._http_get = net
    r = run(archives=False)
    assert r["ok"] is False and r["error"] == "robots_disallowed" and URL not in net.urls()


def test_robots_5xx_is_treated_as_disallow():
    net = Net(lambda url, ua: resp(503, b"") if robots_404(url) else resp(200, ARTICLE))
    fb._http_get = net
    r = run(archives=False)
    assert r["ok"] is False and URL not in net.urls()


def test_robots_can_be_ignored_explicitly():
    net = Net(lambda url, ua: resp(200, ROBOTS_DISALLOW, ctype="text/plain") if robots_404(url) else resp(200, ARTICLE))
    fb._http_get = net
    assert run(respect_robots=False)["ok"]


# ----------------------------------------------------------------------------- cache + memory
def test_cache_hit_within_24h_makes_no_requests(isolated):
    net = Net(live_handler(resp(200, ARTICLE)))
    fb._http_get = net
    first = run()
    n = len(net.calls)
    second = run()
    assert first["cache_hit"] is False and second["cache_hit"] is True and second["ok"]
    assert len(net.calls) == n and second["egress"] == []
    assert second["text"].startswith(fb.WRAP_OPEN) and second["tier_used"] == 1


def test_cache_expires_after_ttl(isolated):
    net = Net(live_handler(resp(200, ARTICLE)))
    fb._http_get = net
    run()
    f = next((isolated / "state" / "cache").glob("*.json"))
    rec = json.loads(f.read_text())
    rec["cached_at"] = time.time() - fb.CACHE_TTL_S - 5
    f.write_text(json.dumps(rec))
    assert run()["cache_hit"] is False


def test_cache_keeps_archive_hits_marked_stale():
    fb._http_get = Net(archive_handler(avail=availability(True)))
    run()
    again = run()
    assert again["cache_hit"] and again["stale"] is True and again["snapshot"]["service"] == "wayback"


def test_cache_dir_and_memory_path_are_configurable(tmp_path):
    fb._http_get = Net(live_handler(resp(200, ARTICLE)))
    cd, mp = tmp_path / "mycache", tmp_path / "mem" / "m.json"
    run(cache_dir=cd, memory_path=mp)
    assert list(cd.glob("*.json")) and json.loads(mp.read_text())[HOST]["tier"] == 1
    assert not (tmp_path / "state").exists()


def test_cache_and_memory_can_be_switched_off(isolated):
    fb._http_get = Net(live_handler(resp(200, ARTICLE)))
    run(use_cache=False, remember=False)
    assert not (isolated / "state").exists()


def test_domain_memory_starts_at_the_tier_that_worked(monkeypatch, isolated):
    thin = b"<html><title>t</title><body><p>short</p></body></html>"
    fb._http_get = Net(live_handler(resp(200, thin)))
    monkeypatch.setattr(fb, "_core_fetch", lambda url: {
        "status": 200, "final_url": url, "ctype": "text/html", "body": ARTICLE, "charset": "utf-8",
        "headers": {}, "hosts": [], "error": None})
    first = run(use_cache=False)
    assert first["tier_used"] == 2 and first["tier_order"] == [1, 2]
    second = run(use_cache=False)
    assert second["tier_order"] == [2, 1] and second["tier_used"] == 2
    assert [a["tier"] for a in second["attempts"] if a["tier"] in (1, 2)] == [2]


def test_domain_memory_expires():
    mem = {"tier": 2, "last_ok": time.time() - fb.MEMORY_TTL_S - 10}
    assert fb._live_order(mem, [1, 2]) == [1, 2]
    assert fb._live_order({"tier": 2, "last_ok": time.time()}, [1, 2]) == [2, 1]


def test_429_sets_domain_backoff_and_next_call_skips_live(isolated):
    net = Net(live_handler(resp(429, b"", headers={"retry-after": "120"})))
    fb._http_get = net
    r = run(archives=False, use_cache=False)
    assert not r["ok"]
    n = len(net.calls)
    r2 = run(archives=False, use_cache=False)
    assert len(net.calls) == n                      # backed off: no request at all
    assert any(a.get("error") == "domain_backoff" for a in r2["attempts"])


# ----------------------------------------------------------------------------- render (optional extra)
def test_render_is_off_by_default():
    net = Net(live_handler(resp(403, b"<html><title>Forbidden</title></html>")))
    fb._http_get = net
    called = []
    fb._render = lambda url, t: called.append(url) or {"error": "x"}
    r = run(archives=False)
    assert called == [] and not any(a["tier"] == 3 for a in r["attempts"])


def test_render_tier_records_third_party_egress(monkeypatch):
    fb._http_get = Net(live_handler(resp(403, b"<html><title>Forbidden</title></html>")))
    monkeypatch.setattr(fb, "_render", lambda url, t: {
        "html": ARTICLE.decode(), "status": 200, "final_url": URL, "success": True,
        "hosts": [HOST, "tracker.example.net"]})
    r = run(render=True, archives=False)
    assert r["ok"] and r["tier_used"] == 3
    a3 = [a for a in r["attempts"] if a["tier"] == 3][0]
    assert a3["egress"] == [HOST, "tracker.example.net"] and "tracker.example.net" in r["egress"]


def test_render_without_the_extra_degrades_cleanly(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "crawl4ai", None)       # simulates "not installed"
    r = fb._render(URL, 1.0)
    assert r["error"] == "render_unavailable" and "quick-read[render]" in r["message"]


# ----------------------------------------------------------------------------- SSRF and input
def test_ssrf_blocked_address_never_reaches_the_network(monkeypatch):
    monkeypatch.setattr(core, "_check_host", REAL_CHECK_HOST)    # the real check; literals need no DNS
    called = []
    fb._http_get = lambda *a, **k: called.append(a) or resp(200, ARTICLE)
    for u in ("http://127.0.0.1:1/", "http://[64:ff9b::7f00:1]/", "http://169.254.169.254/"):
        r = fb.fetch_with_fallback(u, use_cache=False, remember=False)
        assert r["ok"] is False and r["error"] == "blocked_address", u
    assert called == []


def test_real_http_get_refuses_a_blocked_address_before_connecting(monkeypatch):
    monkeypatch.setattr(core, "_check_host", REAL_CHECK_HOST)
    r = REAL_HTTP_GET("http://127.0.0.1:1/", ua="x", timeout=1)
    assert r["error"] == "blocked_address" and r["body"] == b""


@pytest.mark.parametrize("bad", ["", "   ", "ftp://example.org/x", "file:///etc/passwd", None, 42])
def test_bad_input_never_raises(bad):
    r = fb.fetch_with_fallback(bad)
    assert r["ok"] is False and r["error"].startswith("bad_input")


def test_internal_error_is_reported_not_raised(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(fb, "_robots_allows", boom)
    fb._http_get = Net(live_handler(resp(200, ARTICLE)))
    r = run(use_cache=False, remember=False)
    assert r["ok"] is False and r["error"].startswith("internal:RuntimeError")


def test_max_chars_truncates_wrapped_text():
    fb._http_get = Net(live_handler(resp(200, ARTICLE)))
    r = run(max_chars=100)
    assert r["truncated"] is True and len(r["text"]) == 100 + len(fb.WRAP_OPEN) + len(fb.WRAP_CLOSE)
