"""CLI: python -m quick_read <url> [--json] [--max-chars N]   |   python -m quick_read search "<query>" [...]"""
from __future__ import annotations

import argparse
import json
import sys

from .core import quick_read
from .fallback import fetch_with_fallback


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "search":
        from .search import main as search_main
        return search_main(argv[1:])
    ap = argparse.ArgumentParser(prog="quick_read",
                                 description="Read one static web page into clean text.")
    ap.add_argument("url")
    ap.add_argument("--max-chars", type=int, default=20000)
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    ap.add_argument("--fallback", action="store_true",
                    help="escalate through fallback tiers (archives, optional render) when the plain read fails")
    ap.add_argument("--render", action="store_true",
                    help="with --fallback: allow a headless render tier (needs quick-read[render])")
    ap.add_argument("--ua-fallback", action="store_true",
                    help="with --fallback: retry with a browser-style User-Agent after a plain 401/403/406. "
                         "May violate a site's wishes; use only where permitted")
    a = ap.parse_args(argv)
    if a.fallback:
        r = fetch_with_fallback(a.url, max_chars=a.max_chars, render=a.render,
                                ua_fallback=a.ua_fallback)
    else:
        r = quick_read(a.url, a.max_chars)
    if a.json:
        print(json.dumps(r, ensure_ascii=False))
    else:
        if r.get("stale"):
            print(f"[STALE: archive snapshot, {r['snapshot']['service']} {r['snapshot'].get('timestamp')}]")
        print(r.get("text") or json.dumps(r, ensure_ascii=False, indent=1))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
