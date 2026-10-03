"""CLI: python -m quick_read <url> [--json] [--max-chars N]"""
from __future__ import annotations

import argparse
import json
import sys

from .core import quick_read


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="quick_read",
                                 description="Read one static web page into clean text.")
    ap.add_argument("url")
    ap.add_argument("--max-chars", type=int, default=20000)
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    a = ap.parse_args(argv)
    r = quick_read(a.url, a.max_chars)
    if a.json:
        print(json.dumps(r, ensure_ascii=False))
    else:
        print(r.get("text") or json.dumps(r, ensure_ascii=False, indent=1))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
