# Changelog

## 0.3.0 - 2026-11-17

Breaking (environment)
- The `mcp` extra now requires the MCP Python SDK 2.x (`mcp==2.3.0`, was `mcp==1.30.0`). Installing
  `quick-read[mcp]` next to another package that pins `mcp<2` gives a resolver conflict; use a separate
  virtual environment for the server if you need both.
- `quick_read.mcp_server.mcp` is now an `mcp.server.mcpserver.MCPServer` (FastMCP was removed in mcp 2), so code
  that used FastMCP-only attributes on it (`settings`, old `run()` arguments) must be updated.

Unchanged for MCP clients
- Tool name `quick_read`, its input schema (`url`, `max_chars` default 20000) and its output (one JSON text
  content, no structured output) are the same as in 0.2.0, compared on both SDK versions.

Changed
- An unexpected exception inside the tool is reported by SDK 2 as `Error executing tool quick_read` without the
  exception text (SDK 1 included it). Normal failures are unaffected: they come back as a result with `ok: false`
  and an `error` code, as before.
- The server reports the package version in `serverInfo.version` (SDK 2 no longer fills it in).
- `trafilatura` pinned to 2.3.1 (was 2.3.0).

Added
- `tests/test_mcp_server.py`: stdio test of the MCP server (initialize, tools/list, tools/call on a blocked
  address, no network needed); skipped when the `mcp` extra is not installed.

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
