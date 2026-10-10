# Changelog

## 0.2.0 - 2026-10-10

Added
- `fetch_with_fallback(url, ...)` and `python -m quick_read --fallback` (opt-in): HTTP with a
  User-Agent switch, the regular quick_read path, Wayback (availability with retry, then CDX) and
  archive.today lookup (skipped on a challenge, never solved), with a challenge-page gate,
  robots.txt, per-domain tier memory, a 24 h cache, per-tier timeouts, `egress` per attempt and
  `stale` plus the snapshot date for archive hits.
- Optional extra `quick-read[render]` (crawl4ai) for a headless render tier; off unless `render=True`.
- `tests/test_fallback.py`: 43 offline tests on recorded-shape responses.

Unchanged
- `quick_read()` and its guards behave as in 0.1.0.

## 0.1.0 - 2026-10-03

- First public release: `quick_read()`, SSRF checks on every hop, IPv6 transition-form unwrapping,
  content-type and size limits, prompt-injection risk scoring, CLI and optional MCP server.
