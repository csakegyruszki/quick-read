"""Real-browser check of the T3 request guard (skipped unless crawl4ai and its browser are installed).

Two throw-away servers on 127.0.0.1: A (allowed by the patched SSRF check) and B (refused). Whatever A
redirects to, links to or navigates to on B must never be requested: B's request log has to stay empty.

Run: python -m pytest tests/test_render_guard_browser.py -v
"""
import http.server
import threading

import pytest

pytest.importorskip("crawl4ai")

from quick_read import core, fallback as fb  # noqa: E402


@pytest.fixture()
def servers(monkeypatch):
    hits = {"A": [], "B": []}
    ports = {}

    def make(name):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                hits[name].append(self.path)
                pb = ports["B"]
                routes = {
                    "/hello": b"<html><body><p>hello</p></body></html>",
                    "/sub": (f'<html><body><p>sub</p><img src="http://127.0.0.1:{pb}/pixel">'
                             f'<script>fetch("http://127.0.0.1:{pb}/xhr")</script></body></html>').encode(),
                    "/js": f'<html><body><script>location="http://127.0.0.1:{pb}/jsnav"</script></body></html>'.encode(),
                }
                redirects = {"/redir": f"http://127.0.0.1:{pb}/secret", "/hop": "/redir", "/okredir": "/hello"}
                if name == "A" and self.path in redirects:
                    self.send_response(302)
                    self.send_header("Location", redirects[self.path])
                    self.end_headers()
                    return
                body = routes.get(self.path, b"<html><body><p>SECRET-INTERNAL</p></body></html>")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)
        return H

    srv = {n: http.server.ThreadingHTTPServer(("127.0.0.1", 0), make(n)) for n in "AB"}
    for n, s in srv.items():
        ports[n] = s.server_address[1]
        threading.Thread(target=s.serve_forever, daemon=True).start()
    monkeypatch.setattr(core, "_check_host", lambda url: None if f":{ports['A']}/" in url else {
        "error": "BLOCKED_ADDRESS", "message": "test: only server A is allowed"})
    yield ports, hits
    for s in srv.values():
        s.shutdown()


def _render_or_skip(url):
    r = fb._render(url, 25.0)
    if r.get("error"):
        pytest.skip(f"render unavailable here: {r['error']}")
    return r


def test_baseline_safe_redirect_is_followed(servers):
    ports, hits = servers
    r = _render_or_skip(f"http://127.0.0.1:{ports['A']}/okredir")
    if "hello" not in r["html"]:
        pytest.skip("no working browser here")
    assert r["final_url"].endswith("/hello") and r["blocked"] == []


@pytest.mark.parametrize("path", ["/redir", "/hop"])
def test_redirect_to_a_refused_host_is_never_requested(servers, path):
    ports, hits = servers
    _render_or_skip(f"http://127.0.0.1:{ports['A']}/okredir")        # browser works at all?
    r = fb._render(f"http://127.0.0.1:{ports['A']}{path}", 25.0)
    assert hits["B"] == []
    assert "SECRET-INTERNAL" not in r.get("html", "")
    assert any(b["navigation"] and b["main_frame"] for b in r.get("blocked", []))


def test_refused_subresources_and_js_navigation_are_never_requested(servers):
    ports, hits = servers
    _render_or_skip(f"http://127.0.0.1:{ports['A']}/okredir")
    for path in ("/sub", "/js"):
        r = fb._render(f"http://127.0.0.1:{ports['A']}{path}", 25.0)
        assert r.get("blocked"), path
    assert hits["B"] == []
