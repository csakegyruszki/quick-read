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


def test_ua_switch_after_plain_403_only_when_opted_in(isolated):
    seen = []

    def rules(ua):
        seen.append(ua)
        return resp(403, b"<html><title>Forbidden</title></html>") if ua == fb.TOOL_UA else resp(200, ARTICLE)

    net = Net(live_handler(ua_rules=rules))
    fb._http_get = net
    r = run(ua_fallback=True)
    assert r["ok"] and r["tier_used"] == 1
    assert seen == [fb.TOOL_UA, fb.BROWSER_UA]
    mem = json.loads((isolated / "state" / "domain-memory.json").read_text())
    assert mem[HOST]["ua"] == "browser" and mem[HOST]["tier"] == 1


def test_no_ua_switch_by_default(isolated):
    seen = []

    def rules(ua):
        seen.append(ua)
        return resp(403, b"<html><title>Forbidden</title></html>") if ua == fb.TOOL_UA else resp(200, ARTICLE)

    fb._http_get = Net(live_handler(ua_rules=rules))
    r = run(archives=False)
    assert not r["ok"]
    assert seen == [fb.TOOL_UA]          # the browser UA is never sent unless ua_fallback=True


def test_remembered_browser_ua_is_ignored_without_opt_in(isolated):
    (isolated / "state").mkdir()
    (isolated / "state" / "domain-memory.json").write_text(json.dumps(
        {HOST: {"tier": 1, "ua": "browser", "last_ok": time.time(), "ok": 1}}))
    seen = []

    def rules(ua):
        seen.append(ua)
        return resp(200, ARTICLE)

    fb._http_get = Net(live_handler(ua_rules=rules))
    assert run(use_cache=False)["ok"]
    assert seen == [fb.TOOL_UA]


def test_cli_ua_fallback_flag_is_off_unless_given(monkeypatch):
    import quick_read.__main__ as m
    got = []
    monkeypatch.setattr(m, "fetch_with_fallback", lambda url, **kw: got.append(kw) or {"ok": True, "text": "x"})
    m.main(["https://example.org/", "--fallback"])
    m.main(["https://example.org/", "--fallback", "--ua-fallback"])
    assert [g["ua_fallback"] for g in got] == [False, True]


def test_no_ua_switch_after_named_challenge():
    seen = []

    def rules(ua):
        seen.append(ua)
        return resp(403, CF_PAGE)

    net = Net(live_handler(ua_rules=rules))
    fb._http_get = net
    r = run(archives=False, ua_fallback=True)
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


@pytest.mark.parametrize("robots_answer", [
    resp(500, b""), resp(503, b""), resp(599, b""),                       # RFC 9309 2.3.1.4: server error
    resp(0, b"", error="connect_error"), resp(0, b"", error="timeout"),    # ... or network error
    resp(0, b"", error="tls_error"), resp(0, b"", error="too_many_redirects"),
    resp(0, b"", error="blocked_address"),                                 # redirect into a private address
    resp(302, b""),                                                        # a redirect we cannot follow
], ids=lambda r: str(r["status"] or r["error"]))
def test_robots_unreachable_means_complete_disallow(robots_answer):
    robots_answer["status"] = robots_answer["status"] or None
    net = Net(lambda url, ua: dict(robots_answer) if robots_404(url) else resp(200, ARTICLE))
    fb._http_get = net
    r = run(archives=False)
    assert r["ok"] is False and r["error"] == "robots_disallowed" and URL not in net.urls()
    assert [a for a in r["attempts"] if a["tier"] == "robots"][0]["robots"] == "unreachable"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410, 429, 451])
def test_robots_4xx_means_unavailable_so_allowed(status):
    # RFC 9309 2.3.1.3: any 4xx = no robots.txt, the crawler MAY access anything
    net = Net(lambda url, ua: resp(status, b"") if robots_404(url) else resp(200, ARTICLE))
    fb._http_get = net
    r = run(archives=False)
    assert r["ok"] is True and URL in net.urls()
    assert [a for a in r["attempts"] if a["tier"] == "robots"][0]["robots"] == "unavailable"


def test_robots_unreachable_verdict_is_retried_after_a_short_ttl(monkeypatch):
    state = {"robots": resp(503, b"")}
    net = Net(lambda url, ua: dict(state["robots"]) if robots_404(url) else resp(200, ARTICLE))
    fb._http_get = net
    assert run(archives=False, use_cache=False, remember=False)["ok"] is False
    now = time.time()
    monkeypatch.setattr(fb.time, "time", lambda: now + fb.ROBOTS_UNREACHABLE_TTL_S - 1)
    assert run(archives=False, use_cache=False, remember=False)["ok"] is False      # still cached
    monkeypatch.setattr(fb.time, "time", lambda: now + fb.ROBOTS_UNREACHABLE_TTL_S + 1)
    state["robots"] = resp(404, b"")
    assert run(archives=False, use_cache=False, remember=False)["ok"] is True       # asked again, now allowed


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


def test_render_redirected_to_a_private_address_is_rejected(monkeypatch):
    """An allowed entry URL whose render ends on 127.0.0.1 / the metadata address: content dropped."""
    fb._http_get = Net(live_handler(resp(403, b"<html><title>Forbidden</title></html>")))
    secret = "<html><body><article>" + "internal secret " * 80 + "</article></body></html>"
    for target in ("http://127.0.0.1:8080/admin", "http://169.254.169.254/latest/meta-data/"):
        monkeypatch.setattr(core, "_check_host", lambda url: (
            {"error": "BLOCKED_ADDRESS", "message": "not public"} if fb.urlparse(url).hostname in ("127.0.0.1", "169.254.169.254")
            else None))
        monkeypatch.setattr(fb, "_render", lambda url, t, target=target: {
            "html": secret, "status": 200, "final_url": target, "success": True, "hosts": [HOST], "blocked": []})
        r = run(render=True, archives=False, use_cache=False, remember=False)
        assert r["ok"] is False and r["text"] == "", target
        a3 = [a for a in r["attempts"] if a["tier"] == 3][0]
        assert a3["error"] == "render_blocked_address" and a3["chars"] == 0
        assert "internal secret" not in json.dumps(r)


def test_render_with_a_refused_main_frame_navigation_is_rejected(monkeypatch):
    """The guard aborted a redirect hop / JS navigation: whatever the browser shows instead is not returned."""
    fb._http_get = Net(live_handler(resp(403, b"<html><title>Forbidden</title></html>")))
    monkeypatch.setattr(fb, "_render", lambda url, t: {
        "html": ARTICLE.decode(), "status": 200, "final_url": URL, "success": True, "hosts": [HOST],
        "blocked": [{"url": "http://127.0.0.1/x", "host": "127.0.0.1", "error": "BLOCKED_ADDRESS",
                     "navigation": True, "main_frame": True}]})
    r = run(render=True, archives=False, use_cache=False, remember=False)
    assert r["ok"] is False
    assert [a for a in r["attempts"] if a["tier"] == 3][0]["error"] == "render_blocked_address"


def test_render_private_subresource_is_aborted_and_recorded_not_returned_as_egress(monkeypatch):
    fb._http_get = Net(live_handler(resp(403, b"<html><title>Forbidden</title></html>")))
    monkeypatch.setattr(fb, "_render", lambda url, t: {
        "html": ARTICLE.decode(), "status": 200, "final_url": URL, "success": True, "hosts": [HOST],
        "blocked": [{"url": "http://10.0.0.5/pixel.png", "host": "10.0.0.5", "error": "BLOCKED_ADDRESS",
                     "navigation": False, "main_frame": True}]})
    r = run(render=True, archives=False, use_cache=False, remember=False)
    assert r["ok"] and r["tier_used"] == 3
    a3 = [a for a in r["attempts"] if a["tier"] == 3][0]
    assert a3["blocked"] == [{"host": "10.0.0.5", "error": "BLOCKED_ADDRESS", "navigation": False}]
    assert "10.0.0.5" not in r["egress"]


# ---- the route guard itself (the hook that crawl4ai/Playwright runs for every browser request)
class _Frame:
    def __init__(self, main):
        self.parent_frame = None if main else object()


class _Req:
    def __init__(self, url, nav=False, main=True):
        self.url, self._nav, self.frame = url, nav, _Frame(main)

    def is_navigation_request(self):
        return self._nav


class _Resp:
    def __init__(self, status=200, location=None):
        self.status, self.headers = status, ({"location": location} if location else {})


class _Route:
    def __init__(self, req, resp=None):
        self.request, self._resp, self.did = req, resp, []

    async def fetch(self, **kw):
        assert kw == {"max_redirects": 0}      # never let Playwright follow a redirect for us
        return self._resp

    async def fallback(self):
        self.did.append("fallback")

    async def abort(self, reason="failed"):
        self.did.append(f"abort:{reason}")

    async def fulfill(self, **kw):
        self.did.append("fulfill")


def _guard_check(url):
    return None if fb.urlparse(url).hostname.endswith(".example") else {"error": "BLOCKED_ADDRESS", "message": "x"}


def _drive(req, resp=None):
    import asyncio
    blocked, redirects = [], []
    route = _Route(req, resp)
    asyncio.run(fb._make_route_guard(blocked, redirects, check=_guard_check)(route))
    return route.did, blocked, redirects


def test_guard_aborts_private_subresources_and_passes_public_ones():
    assert _drive(_Req("http://169.254.169.254/latest/meta-data/"))[0] == ["abort:blockedbyclient"]
    did, blocked, _ = _drive(_Req("http://127.0.0.1:9/pixel.gif"))
    assert did == ["abort:blockedbyclient"] and blocked[0]["host"] == "127.0.0.1" and blocked[0]["navigation"] is False
    assert _drive(_Req("https://cdn.static.example/app.js"))[0] == ["fallback"]
    assert _drive(_Req("data:image/png;base64,AAAA"))[0] == ["fallback"]      # no network involved


def test_guard_refuses_a_navigation_redirect_to_a_private_address_before_it_is_requested():
    did, blocked, redirects = _drive(_Req("https://a.example/", nav=True), _Resp(302, "http://127.0.0.1:8080/admin"))
    assert did == ["abort:blockedbyclient"] and redirects == []
    assert blocked == [{"url": "http://127.0.0.1:8080/admin", "host": "127.0.0.1", "error": "BLOCKED_ADDRESS",
                        "navigation": True, "main_frame": True}]
    did, blocked, _ = _drive(_Req("https://a.example/", nav=True), _Resp(301, "/elsewhere"))      # relative: stays on a.example
    assert did == ["abort:aborted"]


def test_guard_hands_a_safe_main_frame_redirect_back_for_a_fresh_guarded_request():
    did, blocked, redirects = _drive(_Req("https://a.example/old", nav=True), _Resp(302, "/new"))
    assert did == ["abort:aborted"] and redirects == ["https://a.example/new"] and blocked == []


def test_guard_passes_a_non_redirect_navigation_through():
    assert _drive(_Req("https://a.example/", nav=True), _Resp(200))[0] == ["fulfill"]


def test_guard_checks_the_first_hop_of_an_iframe_redirect():
    did, blocked, _ = _drive(_Req("https://a.example/f", nav=True, main=False), _Resp(302, "http://10.1.1.1/"))
    assert did == ["abort:blockedbyclient"] and blocked[0]["main_frame"] is False
    assert _drive(_Req("https://a.example/f", nav=True, main=False), _Resp(302, "https://b.example/"))[0] == ["fulfill"]


def test_guard_fails_closed_when_the_check_itself_raises():
    import asyncio

    def boom(url):
        raise RuntimeError("dns exploded")

    route = _Route(_Req("https://a.example/x"))
    asyncio.run(fb._make_route_guard([], [], check=boom)(route))
    assert route.did == ["abort:blockedbyclient"]


def test_render_refuses_to_run_without_an_installed_guard(monkeypatch):
    """If crawl4ai never calls our hook (API change), the result must be discarded, not returned unguarded."""
    import sys
    import types

    class Res:
        html, status_code, redirected_url, success, error_message, network_requests = "<p>x</p>", 200, "", True, "", []

    class Strategy:
        def set_hook(self, name, fn):
            pass                                 # silently never runs it

    class Crawler:
        def __init__(self, config=None):
            self.crawler_strategy = Strategy()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def arun(self, url, config=None):
            return Res()

    mod = types.SimpleNamespace(AsyncWebCrawler=Crawler, BrowserConfig=lambda **k: None, CacheMode=types.SimpleNamespace(BYPASS=0),
                                CrawlerRunConfig=lambda **k: None)
    monkeypatch.setitem(sys.modules, "crawl4ai", mod)
    r = fb._render(URL, 2.0)
    assert r["error"] == "render_guard_not_installed" and "html" not in r


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
