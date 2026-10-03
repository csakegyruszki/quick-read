# quick-read

Fast single-URL reader for LLM agents. Fetches one static web page, extracts clean
Markdown text with [trafilatura](https://github.com/adbar/trafilatura), and applies
scheme, address, content-type and size guards (see Known limits). In-process: no browser, no subprocess. Measured 2026-10-03 on one Windows machine, 3 runs on the English Wikipedia article for Python: median 1.99 s wall time per call (fetch 0.6-0.9 s, extraction about 0.9 s). One page, one connection; yours will differ.

```
pip install .            # httpx + trafilatura
pip install ".[mcp]"     # plus a one-tool MCP server
```

```python
from quick_read import quick_read
r = quick_read("https://example.org/")
r["ok"], r["title"], r["injection_risk"], r["text"]
```

```
python -m quick_read https://example.org/ --json
python -m quick_read.mcp_server        # stdio MCP server, one tool: quick_read
```

The function never raises. Failures return `{"ok": False, "error": CODE, "message": ...}`
with `BAD_INPUT`, `BLOCKED_ADDRESS`, `FETCH_FAILED`, `HTTP_<n>`, `UNSUPPORTED_TYPE` or
`TOO_LARGE`. A success returns `text` (wrapped in `<<<UNTRUSTED WEB CONTENT>>>` markers),
`title`, `date`, `final_url`, `status`, `sha256_raw`, `sha256_text`, `injection_risk`,
`needs_render`, `truncated`, and a `warning` when the risk is HIGH or MED.

Optional `on_capture(result, raw_bytes)` callback runs after a successful read, for
example to archive the raw page; a callback exception is reported as `capture_error`.

## Guards

- http/https only.
- SSRF: every resolved address must be globally routable (`ipaddress.is_global`), checked on
  every redirect hop; redirects are followed manually, at most 5. Covers loopback, private,
  link-local, CGNAT (100.64.0.0/10), reserved, multicast and IPv4-mapped IPv6. IPv6 forms that
  embed an IPv4 address are unwrapped and the embedded address must be global too: NAT64
  `64:ff9b::/96` and `64:ff9b:1::/48`, IPv4-compatible `::/96`, 6to4 `2002::/16`, Teredo `2001::/32`
  (so `[64:ff9b::7f00:1]` is blocked as 127.0.0.1)
- Content-Type allowlist: `text/html`, `application/xhtml+xml`, `text/plain`. PDF gets a hint.
- 5 MB cap, enforced while streaming. Connect timeout 5 s; the elapsed-time budget of 15 s is checked before each redirect hop and after each streamed chunk, and httpx applies 15 s per read operation. DNS resolution happens before that check and is not included in the budget.
- No JavaScript. A page that yields under 400 characters is flagged `needs_render`.
- Environment proxies are ignored (`trust_env=False`).
- User-Agent `quick-read/<version> (+https://github.com/csakegyruszki/quick-read)`: no
  personal data, but with a URL because Wikimedia rejects user agents without one.

## Known limits

- **DNS rebinding (TOCTOU).** The address check and the connection are separate lookups, and
  the IP is not pinned. An attacker who controls DNS for a host can return a public address
  to the check and a private one to the connection. Do not rely on this library alone where
  that matters; run it in a network-isolated environment.
- **The injection scorer is weak.** It is a small set of English regexes, not a classifier.
  Measured 2026-10-03 on 5 real benign pages and 5 published injection strings
  (sources and quotes in `tests/test_injection_scorer.py`):

  | | flagged HIGH/MED | not flagged |
  |---|---|---|
  | injection (5) | 2 (TP) | 3 (FN) |
  | benign (5) | 1 (FP) | 4 (TN) |

  The two hits were the fake-tag payload (`[system](#context)`) and the all-caps "IGNORE ANY
  PREVIOUS AND FOLLOWING INSTRUCTIONS". It missed "Ignore the above directions...", "Ignore
  the prompt above...", and a role-reassignment payload with no trigger phrase. The false
  positive was the Python `ipaddress` documentation page (HIGH, via the `act as` role pattern
  matching "can act as containers"; recorded as an observation in
  `tests/test_core.py::test_observation_ipaddress_page_false_positive`). Pages that discuss prompt injection are flagged too.
  Ten samples say little about real-world rates. Treat `injection_risk=CLEAN` as "no known
  pattern matched", never as "safe"; the UNTRUSTED wrapper is the actual defence, and only
  works if the consuming agent honours it. English only; paraphrase, encoding and other
  languages are not covered.
- The risk is scored on the full extracted text, while `text` is cut to `max_chars`.
- Static HTML only. JS-rendered pages, logins and bot walls come back thin or fail.

## Tests

```
python -m pytest -v                   # network tests skip, not pass, if the net is down
python -m pytest -m "not network"     # offline guard tests only
```

Guard tests use real addresses (127.0.0.1, 10.0.0.1, 169.254.169.254, `[::ffff:127.0.0.1]`,
100.64.1.1, the NAT64/IPv4-compatible/6to4/Teredo forms above, `file://`), not mocks.

## License

Apache-2.0, see `LICENSE`.
