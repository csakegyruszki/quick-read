# Changelog

## 0.2.0 - 2026-10-10

Added
- `fetch_with_fallback(url, ...)` and `python -m quick_read --fallback` (opt-in): HTTP with a
  User-Agent switch, the regular quick_read path, Wayback (availability with retry, then CDX) and
  archive.today lookup (skipped on a challenge, never solved), with a challenge-page gate,
  robots.txt, per-domain tier memory, a 24 h cache, per-tier timeouts, `egress` per attempt and
  `stale` plus the snapshot date for archive hits.
- Optional extra `quick-read[render]` (crawl4ai) for a headless render tier; off unless `render=True`.
  Every browser request is checked against the SSRF policy and aborted when it fails; main-frame
  redirects are checked hop by hop before they are requested; a render that ends on a non-public
  address is discarded. Limits (subresource redirects, DNS rebinding, WebSockets) are in the README.
- `ua_fallback=False` / `--ua-fallback`: the browser-style User-Agent retry after a plain 401/403/406 is
  opt-in.
- robots.txt follows RFC 9309 section 2.3.1: 4xx = unavailable (allowed); 5xx or a network error =
  unreachable (complete disallow).
- `tests/test_fallback.py`: offline tests on recorded-shape responses; `tests/test_render_guard_browser.py`
  checks the render guard against a real browser (skipped when crawl4ai is not installed).
- `quick_read.search` (standalone, no page fetching involved): federated, multilingual web search.
  Backends `ddgs` (optional extra `quick-read[search]`), `searxng` (`QUICK_READ_SEARXNG_URL`) and the
  public keyless `parallel` endpoint (opt-in), plus `register_backend` for your own; per-backend time
  budgets, URL normalisation, RRF merge, locale-twin collapse (`alt_urls`), a single-source relevance
  guard, `publish_date` + `date_source` (engine / url / snippet / none), a 6 h cache, and
  `search_multi(query, langs, translations)` with a 55-language ISO 639-1 region table. The caller
  supplies the translations; nothing is translated for you. `register_route` is the interface for
  rule-triggered direct lookups (none ship; one example is in the README).
- CLI: `python -m quick_read search "query" --langs ru,he --translation ru="..."`.
- `tests/test_search.py`: 97 offline tests.

Unchanged
- `quick_read()` and its guards behave as in 0.1.0.

## 0.1.0 - 2026-10-03

- First public release: `quick_read()`, SSRF checks on every hop, IPv6 transition-form unwrapping,
  content-type and size limits, prompt-injection risk scoring, CLI and optional MCP server.
