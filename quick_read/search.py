"""Federated, multilingual web search.

Fans a query out to several search backends in parallel threads (each with its own time budget; a slow
backend is dropped, not waited for), merges the answers with Reciprocal Rank Fusion over normalised URLs,
collapses locale twins of one page (``/en/x`` and ``/ru/x``) into one result with ``alt_urls``, demotes
single-source hits that share almost no terms with the query, and labels every result with a publication
date only when one is given by the engine or stated in the URL or snippet.

    from quick_read.search import search, search_multi
    r = search("rust async runtime comparison", k=10)
    r = search_multi("sanctions evasion", langs=["ru", "he"],
                     translations={"ru": "<your translation>", "he": "<your translation>"})

    python -m quick_read search "sanctions evasion" --langs ru,he --translation ru="<translation>"

Built-in backends
    ddgs      DuckDuckGo through the optional ``ddgs`` package (``pip install "quick-read[search]"``).
    searxng   A SearXNG instance with the JSON format enabled; base URL in ``QUICK_READ_SEARXNG_URL``.
    parallel  The public, keyless Parallel Search MCP endpoint. Off unless named in ``backends=``:
              the query goes to a third party, and its terms and rate limits are theirs.
Your own backends and "routes" (rule-triggered direct lookups) plug in through ``register_backend`` and
``register_route``; modules named in ``QUICK_READ_SEARCH_PLUGINS`` (comma separated) are imported once and
may register on import (import runs their code: list only modules you trust).

Translation is the CALLER's job. ``search_multi`` searches the query once in its own language and once per
requested language, but it does not translate: pass ``translations={lang: text}``. An LLM agent calling this
should pass its own translations. A language without a translation is reported in ``untranslated_langs`` and
is not searched. Optionally pass ``translator=callable(query, lang) -> str | None``.

Search hits are leads, not evidence: they say a URL was listed for a query, nothing about the page content.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import math
import os
import queue
import re
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

import httpx

from . import __version__

UA = f"quick-read/{__version__} (+https://github.com/csakegyruszki/quick-read)"

CACHE_TTL = 6 * 3600
CACHE_VERSION = "1"
ROUTE_BUDGET = 8.0
TOTAL_BUDGET = 10.0
RRF_K = 60
ROUTE_W = 4.0            # a rank-1 route hit (4/61) outranks three backends agreeing on rank 1 (3/61)
GUARD_PENALTY = 0.1      # single-backend hit with almost no query terms: score x0.1
GUARD_MIN_STEMS = 3      # the guard only applies to queries with at least this many content stems
GUARD_MIN_OVERLAP = 0.2  # fraction of the query stems that must appear in the hit's title/snippet/URL
MULTI_BUDGET = 15.0      # seconds for a whole search_multi call
TRANSLATE_BUDGET = 6.0   # seconds for the optional caller-supplied translator
MAX_VARIANTS = 6         # the original query plus at most five translations
ORIG_W = 0.7             # RRF weight of the original-language variant when translations exist
PARALLEL_MCP_URL = "https://search.parallel.ai/mcp"

# ---------------------------------------------------------------- language table
# ISO 639-1 -> (English name, ddgs region, SearXNG `language=`). "wt-wt" is ddgs "worldwide" (used where DDG
# has no region of its own); a SearXNG value of None sends no language. The English name doubles as the hint
# for backends without a language parameter (the Parallel objective is told which language to find).
LANGS: dict[str, tuple[str, str, str | None]] = {
    "en": ("English", "wt-wt", None), "hu": ("Hungarian", "hu-hu", "hu"),
    "de": ("German", "de-de", "de"), "fr": ("French", "fr-fr", "fr"), "es": ("Spanish", "es-es", "es"),
    "it": ("Italian", "it-it", "it"), "pt": ("Portuguese", "pt-pt", "pt"), "nl": ("Dutch", "nl-nl", "nl"),
    "pl": ("Polish", "pl-pl", "pl"), "cs": ("Czech", "cz-cs", "cs"), "sk": ("Slovak", "sk-sk", "sk"),
    "sl": ("Slovenian", "sl-sl", "sl"), "hr": ("Croatian", "hr-hr", "hr"), "sr": ("Serbian", "rs-sr", "sr"),
    "bs": ("Bosnian", "wt-wt", "bs"), "mk": ("Macedonian", "wt-wt", "mk"), "bg": ("Bulgarian", "bg-bg", "bg"),
    "ro": ("Romanian", "ro-ro", "ro"), "el": ("Greek", "gr-el", "el"), "sq": ("Albanian", "wt-wt", "sq"),
    "tr": ("Turkish", "tr-tr", "tr"), "ru": ("Russian", "ru-ru", "ru"), "uk": ("Ukrainian", "ua-uk", "uk"),
    "be": ("Belarusian", "wt-wt", "be"), "lt": ("Lithuanian", "lt-lt", "lt"), "lv": ("Latvian", "lv-lv", "lv"),
    "et": ("Estonian", "ee-et", "et"), "fi": ("Finnish", "fi-fi", "fi"), "sv": ("Swedish", "se-sv", "sv"),
    "da": ("Danish", "dk-da", "da"), "no": ("Norwegian", "no-no", "no"), "is": ("Icelandic", "wt-wt", "is"),
    "ca": ("Catalan", "ct-ca", "ca"), "ar": ("Arabic", "xa-ar", "ar"), "he": ("Hebrew", "il-he", "he"),
    "fa": ("Persian", "wt-wt", "fa"), "ur": ("Urdu", "wt-wt", "ur"), "hi": ("Hindi", "wt-wt", "hi"),
    "bn": ("Bengali", "wt-wt", "bn"), "ta": ("Tamil", "wt-wt", "ta"), "th": ("Thai", "th-th", "th"),
    "vi": ("Vietnamese", "vn-vi", "vi"), "id": ("Indonesian", "id-id", "id"), "ms": ("Malay", "my-ms", "ms"),
    "tl": ("Filipino", "ph-tl", "tl"), "zh": ("Chinese", "cn-zh", "zh"), "ja": ("Japanese", "jp-jp", "ja"),
    "ko": ("Korean", "kr-kr", "ko"), "ka": ("Georgian", "wt-wt", "ka"), "hy": ("Armenian", "wt-wt", "hy"),
    "az": ("Azerbaijani", "wt-wt", "az"), "kk": ("Kazakh", "wt-wt", "kk"), "uz": ("Uzbek", "wt-wt", "uz"),
    "sw": ("Swahili", "wt-wt", "sw"), "af": ("Afrikaans", "wt-wt", "af"),
}
LANG_ALIASES = {"iw": "he", "in": "id", "nb": "no", "nn": "no", "jw": "id", "tc": "zh", "sc": "zh"}


def norm_lang(code: str | None) -> str | None:
    """'RU', 'ru-RU', 'zh_CN', 'iw' -> 'ru' | 'ru' | 'zh' | 'he'. '' / None -> None. Unknown codes pass
    through (lower-cased primary subtag): they get the wildcard region, never an error."""
    c = re.split(r"[-_]", (code or "").strip().lower())[0]
    return LANG_ALIASES.get(c, c) or None


def lang_params(lang: str | None) -> dict:
    """lang -> {name, ddgs_region, searx_lang}. A language not in LANGS gets wt-wt and language=<code>
    (SearXNG ignores values it does not know); its name is the code itself."""
    lang = norm_lang(lang)
    if lang in LANGS:
        n, d, s = LANGS[lang]
        return {"name": n, "ddgs_region": d, "searx_lang": s}
    return {"name": lang or "", "ddgs_region": "wt-wt", "searx_lang": lang}


# Unicode ranges (code point lo, hi) per script; Ukrainian-only Cyrillic letters are checked before generic Cyrillic.
_SCRIPTS = [("he", [(0x0590, 0x05FF)]), ("ar", [(0x0600, 0x06FF), (0x0750, 0x077F)]), ("ja", [(0x3040, 0x30FF)]),
            ("ko", [(0xAC00, 0xD7AF), (0x1100, 0x11FF)]), ("zh", [(0x4E00, 0x9FFF)]), ("el", [(0x0370, 0x03FF)]),
            ("th", [(0x0E00, 0x0E7F)]), ("hi", [(0x0900, 0x097F)]), ("ka", [(0x10A0, 0x10FF)]),
            ("hy", [(0x0530, 0x058F)]),
            ("uk", [(c, c) for c in (0x0456, 0x0457, 0x0454, 0x0491, 0x0406, 0x0407, 0x0404, 0x0490)]),
            ("ru", [(0x0400, 0x04FF)])]


def script_lang(q: str) -> str:
    """Language implied by the writing system of the query ('' for Latin script). A coarse hint so a query
    typed in Cyrillic, Hebrew, Arabic or CJK is searched with that region, not the English default. Cyrillic
    is 'ru' unless it carries Ukrainian-only letters; it cannot tell ru from bg / sr / be (a region hint)."""
    cps = [ord(c) for c in (q or "")]
    for lang, ranges in _SCRIPTS:
        if any(lo <= cp <= hi for cp in cps for lo, hi in ranges):
            return lang
    return ""


# ---------------------------------------------------------------- text helpers

def fold(s: str | None) -> str:
    """Lower-case and strip combining marks (accents, Hebrew points)."""
    s = unicodedata.normalize("NFKD", (s or "").lower())
    return "".join(c for c in s if not unicodedata.combining(c))


STOP = set("""a an the of and or for to in on at by with from is are was were be as it its this that these those
how what when where which who why do does did not no vs about into over under""".split())


def stems(text: str | None) -> list[str]:
    """Content terms of a text, truncated to 5 characters (a crude, language-neutral stem). Words of any
    script count (\\w); languages written without spaces (CJK) yield one long token, so the relevance guard
    does not apply to them."""
    return [t[:5] for t in re.findall(r"\w+", fold(text)) if t not in STOP and (len(t) > 2 or t.isdigit())]


# ---------------------------------------------------------------- URL normalisation + locale twins

_TRACK = re.compile(r"^(utm_|fbclid|gclid|yclid|mc_cid|mc_eid|ref$|ref_src)", re.I)


def norm_url(u: str | None) -> str:
    """Merge key: no scheme, no www./m./amp., percent-decoded, no trailing slash or fragment, no tracking
    parameters, parameters sorted, lower-cased (some sites differ only in case)."""
    u = (u or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    p = urlsplit(u)
    host = re.sub(r"^(www|m|amp)\.", "", (p.hostname or "").lower())
    try:
        port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
    except ValueError:
        port = ""
    path = re.sub(r"/{2,}", "/", unquote(p.path)).rstrip("/")     # "/" -> "": https://x.org/ and https://x.org match
    q = sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not _TRACK.match(k))
    return (host + port + path + ("?" + urlencode(q) if q else "")).lower()


# `/docs/en/x` and `/docs/ru/x` (or `x?hl=en` / `x?hl=ru`) are ONE page in two languages: they merge into one
# result (scores add up), the variant matching the query language is shown (else `en`, else the first seen)
# and the others are listed in `alt_urls`. Only a path segment that is an ISO 639-1 code from LANGS (`xx` or
# `xx-YY`) and the parameters hl= / lang= / locale= (when the value is such a code) count.
_LOCALE_PARAMS = ("hl", "lang", "locale")
_LOCALE_SEG = re.compile(r"^([a-z]{2})(?:[-_][a-z]{2})?$")


def locale_key(u: str | None) -> tuple[str, str | None]:
    """-> (merge key, locale code | None). The key is norm_url() with the first locale path segment replaced
    by `*` and the locale parameters removed; a URL without any locale part has key == norm_url(u)."""
    n = norm_url(u)
    if not n:
        return "", None
    hostpath, _, q = n.partition("?")
    host, slash, path = hostpath.partition("/")
    segs = path.split("/") if slash else []
    loc = None
    for i, s in enumerate(segs):
        m = _LOCALE_SEG.match(s)
        if m and m.group(1) in LANGS:
            loc, segs[i] = m.group(1), "*"
            break
    kept = []
    for kv in (q.split("&") if q else []):
        k, _, v = kv.partition("=")
        if k in _LOCALE_PARAMS and norm_lang(unquote(v)) in LANGS:
            loc = loc or norm_lang(unquote(v))
            continue
        kept.append(kv)
    return host + ("/" + "/".join(segs) if slash else "") + ("?" + "&".join(kept) if kept else ""), loc


# ---------------------------------------------------------------- publication date (never guessed)

_NUM_DATE = re.compile(r"(?<!\d)((?:19|20)\d\d)\s*[-./]\s*(\d{1,2})\s*[-./]\s*(\d{1,2})(?!\d)")
_EN_MON = (r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|"
           r"oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)")
_EN_MD = re.compile(r"\b" + _EN_MON + r"\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+((?:19|20)\d\d)\b", re.I)
_EN_DM = re.compile(r"\b(\d{1,2})(?:st|nd|rd|th)?\s+(?:of\s+)?" + _EN_MON + r"\.?,?\s+((?:19|20)\d\d)\b", re.I)
_EN_NUM = {m: i for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}


def iso_date(s) -> str:
    """'2026-10-05' / '2026-10-05T10:00:00Z' -> '2026-10-05'; anything else, or an impossible date -> ''."""
    m = re.match(r"^\s*(\d{4})-(\d{2})-(\d{2})(?!\d)", str(s or ""))
    if not m:
        return ""
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()
    except ValueError:
        return ""


def full_dates(text: str | None, today: date | None = None) -> list[str]:
    """Distinct COMPLETE (year, month, day) dates in `text` as ISO strings: year-first numeric forms
    (2026-05-28, 2026/05/28, 2026. 05. 28.) and English ones ('Oct 9, 2026', '9th of October 2026').
    Partial dates are ignored, and so are dates after `today` (an announced event is not a publication date)."""
    today = today or datetime.now(timezone.utc).date()
    text = text or ""
    found = {(int(m.group(1)), int(m.group(2)), int(m.group(3))) for m in _NUM_DATE.finditer(text)}
    for m in _EN_MD.finditer(text):
        found.add((int(m.group(3)), _EN_NUM[m.group(1)[:3].lower()], int(m.group(2))))
    for m in _EN_DM.finditer(text):
        found.add((int(m.group(3)), _EN_NUM[m.group(2)[:3].lower()], int(m.group(1))))
    out = set()
    for y, mo, d in found:
        try:
            dt = date(y, mo, d)
        except ValueError:
            continue
        if dt <= today:
            out.add(dt.isoformat())
    return sorted(out)


def infer_date(url: str | None, snippet: str | None, today: date | None = None) -> tuple[str, str]:
    """-> (iso date | '', source). source: 'url' (exactly one complete date in the URL), 'snippet' (none in the
    URL, exactly one in the snippet) or 'none'. Several different dates mean ambiguous, hence unknown. A
    snippet date is a lead (a meeting agenda names the meeting date, not the publication date), which is why
    the source is labelled."""
    for text, src in ((unquote(url or ""), "url"), (snippet or "", "snippet")):
        ds = full_dates(text, today)
        if len(ds) == 1:
            return ds[0], src
        if len(ds) > 1:
            return "", "none"
    return "", "none"


def annotate_dates(results: list[dict], today: date | None = None) -> list[dict]:
    """Set publish_date + date_source on every result lacking date_source. An engine-supplied date
    (date_source 'engine', set by the backend) is kept as is."""
    for e in results:
        if "date_source" in e:
            continue
        if e.get("publish_date"):
            e["date_source"] = "engine"
            continue
        e["publish_date"], e["date_source"] = infer_date(e.get("url"), e.get("snippet"), today)
    return results


# ---------------------------------------------------------------- merge: RRF + relevance guard

def demote_irrelevant(merged: list[dict], query: str, penalty: float = GUARD_PENALTY) -> list[dict]:
    """Relevance guard: a hit found by ONE backend only that shares (almost) no content stems with the query
    (title + snippet + URL text) is scaled by `penalty`, so it falls below multi-source and route hits.
    Applies only to queries with >= GUARD_MIN_STEMS content stems; route hits are never demoted."""
    qs = set(stems(query))
    if len(qs) < GUARD_MIN_STEMS:
        return merged
    for e in merged:
        if len(e["sources"]) != 1 or e["sources"][0].startswith("route:"):
            continue
        text = f"{e.get('title', '')} {e.get('snippet', '')} {unquote(e['url'])}"
        if len(qs & set(stems(text))) / len(qs) < GUARD_MIN_OVERLAP:
            e["score"] = round(e["score"] * penalty, 5)
            e["demoted"] = True
    return sorted(merged, key=lambda e: -e["score"])        # stable: equal scores keep RRF order


def rrf_merge(ranked: dict[str, list[dict]], weights: dict[str, float] | None = None, k_rrf: int = RRF_K,
              prefer=None) -> list[dict]:
    """ranked: {source: [{url, title, snippet, [conf]} ...]} in rank order. Returns the merged list sorted by
    RRF score; the best rank per source is kept. weights: {source: multiplier}; an item's `conf` scales its
    contribution. Locale twins of one page (see locale_key) merge into one entry: `prefer` (a language code,
    a list of codes, or a callable entry -> list) picks the displayed variant, else `en`, else the first
    seen; the rest are `alt_urls`. The first backend-supplied `publish_date` (+ `date_source`) is carried
    onto the entry. Sources named `route:*` pin their URL form as the display URL."""
    weights = weights or {}
    entries: dict[str, dict] = {}
    order = 0
    for src, items in ranked.items():
        w = weights.get(src, 1.0)
        for rank, it in enumerate(items, 1):
            key, loc = locale_key(it.get("url"))
            if not key:
                continue
            e = entries.get(key)
            if e is None:
                e = entries[key] = {"url": it["url"], "title": "", "snippet": "", "sources": [],
                                    "rank_by_source": {}, "score": 0.0, "_o": order, "_var": {}}
                order += 1
            for u, loc_u in [(it["url"], loc)] + [(a, locale_key(a)[1]) for a in (it.get("alt_urls") or [])]:
                e["_var"].setdefault(norm_url(u), (u, loc_u))
            if it.get("publish_date") and not e.get("publish_date"):
                e["publish_date"], e["date_source"] = it["publish_date"], it.get("date_source") or "engine"
            if src in e["rank_by_source"]:        # same URL twice in one source: keep the best rank only
                continue
            e["rank_by_source"][src] = rank
            e["sources"].append(src)
            e["score"] += w * it.get("conf", 1.0) / (k_rrf + rank)
            if not e["title"] and it.get("title"):
                e["title"] = it["title"]
            if not e["snippet"] and it.get("snippet"):
                e["snippet"] = it["snippet"]
            if src.startswith("route:"):
                e["url"] = it["url"]
                e["_pin"] = True
    out = sorted(entries.values(), key=lambda e: (-e["score"], e["_o"]))
    for e in out:
        e.pop("_o")
        e["score"] = round(e["score"], 5)
        var, pinned = list(e.pop("_var").values()), e.pop("_pin", False)
        if len(var) > 1:                            # locale variants of one page
            if not pinned:
                want = prefer(e) if callable(prefer) else ([prefer] if isinstance(prefer, str) else list(prefer or []))
                for lang in [x for x in want if x] + ["en"]:
                    hit = next((u for u, lg in var if lg == lang), None)
                    if hit:
                        e["url"] = hit
                        break
            e["alt_urls"] = [u for u, _ in var if norm_url(u) != norm_url(e["url"])]
    return out


# ---------------------------------------------------------------- fan-out with per-job time budgets

def fanout(jobs: dict[str, tuple[Callable[[], list], float]], total: float = TOTAL_BUDGET):
    """jobs {name: (fn, budget_s)} -> ({name: items}, timings, errors). Every job runs in its own daemon
    thread; one that overruns min(its budget, total) is dropped and reported (its thread finishes unobserved).
    An exception in a job is recorded, never raised."""
    q: queue.Queue = queue.Queue()
    t0 = time.monotonic()

    def work(name, fn):
        t = time.monotonic()
        try:
            res = ("ok", fn())
        except Exception as e:                      # a failing backend must not break the search
            res = ("err", f"{type(e).__name__}: {str(e)[:160]}")
        q.put((name, res[0], res[1], time.monotonic() - t))

    for name, (fn, _) in jobs.items():
        threading.Thread(target=work, args=(name, fn), daemon=True).start()
    deadline = {n: min(b, total) for n, (_, b) in jobs.items()}
    pending = set(jobs)
    final, timings, errors = {}, {}, {}
    while pending:
        wait = max(0.0, min(deadline[n] for n in pending) - (time.monotonic() - t0))
        try:
            name, status, payload, dt = q.get(timeout=wait + 0.002)
        except queue.Empty:
            now = time.monotonic() - t0
            for n in [n for n in pending if now >= deadline[n] - 0.005]:
                pending.discard(n)
                timings[n] = round(now, 2)
                errors[n] = f"timeout>{jobs[n][1]:g}s (dropped)"
            continue
        if name not in pending:                     # arrived after it was dropped
            continue
        pending.discard(name)
        timings[name] = round(dt, 2)
        if status == "ok":
            final[name] = payload
        else:
            errors[name] = payload
    return final, timings, errors


_LAST: dict[str, float] = {}
_LAST_LOCK = threading.Lock()


def polite(key: str, gap: float = 1.0) -> None:
    """At least `gap` seconds between calls per key (backend name); the slot is reserved under a lock."""
    with _LAST_LOCK:
        now = time.monotonic()
        wait = max(0.0, _LAST.get(key, -1e9) + gap - now)
        _LAST[key] = now + wait
    if wait:
        time.sleep(wait)


# ---------------------------------------------------------------- plugin interfaces: backends and routes

@dataclass
class Backend:
    """A search backend. ``fn(query, k, lang)`` returns rows ``{url, title, snippet}`` in rank order, plus an
    optional ``publish_date`` (ISO) with ``date_source: "engine"``. ``lang`` is an ISO 639-1 code. It may raise:
    the failure is recorded in ``errors`` and the other backends carry on. ``available()`` says whether the
    backend is usable in this environment (None = always); only available backends are in the default set
    (when ``default`` is True). ``egress`` labels who sees the query."""
    name: str
    fn: Callable[[str, int, str | None], list[dict]]
    budget: float = 8.0
    egress: str = ""
    weight: float = 1.0
    available: Callable[[], bool] | None = None
    default: bool = True


@dataclass
class Route:
    """A source route: a rule that recognises a query and answers it directly (a statute number, a package
    name, an identifier ...). ``match(query)`` decides whether the route fires; ``fn(query)`` returns rows
    ``{url, title, snippet, conf}`` (``conf`` 0..1 scales the route's weight). Route hits enter the merge with
    ``weight`` (default ROUTE_W) and are never demoted by the relevance guard. A route must only claim what it
    verified (e.g. "this URL exists"), nothing about content. ``egress`` is the host it contacts at query time
    (None = a local index, nothing leaves the machine)."""
    name: str
    match: Callable[[str], bool]
    fn: Callable[[str], list[dict]]
    egress: str | None = None
    budget: float = ROUTE_BUDGET
    weight: float = ROUTE_W


BACKENDS: dict[str, Backend] = {}
ROUTES: dict[str, Route] = {}


def register_backend(name: str, fn, *, budget: float = 8.0, egress: str | None = None, weight: float = 1.0,
                     available=None, default: bool = True, replace: bool = False) -> Backend:
    """Add a backend (the "custom" hook). Raises ValueError on a duplicate name unless ``replace=True``."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name or "") or name.startswith("route:"):
        raise ValueError(f"bad backend name {name!r}")
    if name in BACKENDS and not replace:
        raise ValueError(f"backend {name!r} already registered")
    BACKENDS[name] = Backend(name, fn, budget, egress if egress is not None else f"custom:{name}", weight,
                             available, default)
    return BACKENDS[name]


def register_route(name: str, match, fn, *, egress: str | None = None, budget: float = ROUTE_BUDGET,
                   weight: float = ROUTE_W, replace: bool = False) -> Route:
    """Add a source route. Raises ValueError on a duplicate name unless ``replace=True``."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name or ""):
        raise ValueError(f"bad route name {name!r}")
    if name in ROUTES and not replace:
        raise ValueError(f"route {name!r} already registered")
    ROUTES[name] = Route(name, match, fn, egress, budget, weight)
    return ROUTES[name]


_PLUGINS_DONE = False


def load_plugins(force: bool = False) -> list[str]:
    """Import the modules named in QUICK_READ_SEARCH_PLUGINS (comma separated, once per process). Importing
    runs the module's code, so list only code you trust; a module registers its backends/routes on import."""
    global _PLUGINS_DONE
    if _PLUGINS_DONE and not force:
        return []
    _PLUGINS_DONE = True
    mods = [m.strip() for m in os.environ.get("QUICK_READ_SEARCH_PLUGINS", "").split(",") if m.strip()]
    for m in mods:
        importlib.import_module(m)
    return mods


# ---------------------------------------------------------------- built-in backends

def _make_client(timeout: float) -> httpx.Client:
    """The single httpx seam for the search backends (tests substitute a mock transport). The endpoints are
    ones the caller configured or the fixed public one, not attacker-supplied URLs, so, unlike page
    fetching, no address policy is applied and environment proxies are honoured."""
    return httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": UA})


def _ddgs_available() -> bool:
    return importlib.util.find_spec("ddgs") is not None


def be_ddgs(q: str, k: int, lang: str | None) -> list[dict]:
    try:
        from ddgs import DDGS
    except ImportError as e:
        raise RuntimeError('ddgs is not installed: pip install "quick-read[search]"') from e
    polite("ddgs")
    try:
        d = DDGS(timeout=7)
    except TypeError:
        d = DDGS()
    region = lang_params(lang)["ddgs_region"] if lang not in (None, "en") else "wt-wt"
    try:
        rows = list(d.text(q, region=region, max_results=k))
    except Exception as e:
        if region == "wt-wt" or "egion" not in str(e):
            raise
        rows = list(d.text(q, region="wt-wt", max_results=k))      # DDG has no such region code: worldwide
    return [{"url": r.get("href", ""), "title": r.get("title", ""), "snippet": (r.get("body") or "")[:300]}
            for r in rows]


def _searxng_base() -> str:
    return os.environ.get("QUICK_READ_SEARXNG_URL", "").strip().rstrip("/")


def _searxng_available() -> bool:
    return bool(_searxng_base())


def be_searxng(q: str, k: int, lang: str | None) -> list[dict]:
    base = _searxng_base()
    if not re.match(r"^https?://", base):
        raise RuntimeError("QUICK_READ_SEARXNG_URL is not set to an http(s) URL")
    polite("searxng")
    params = {"q": q, "format": "json"}
    sl = lang_params(lang)["searx_lang"] if lang not in (None, "en") else None
    if sl:
        params["language"] = sl
    engines = os.environ.get("QUICK_READ_SEARXNG_ENGINES", "").strip()
    if engines:
        params["engines"] = engines
    with _make_client(5.5) as c:
        r = c.get(base + "/search", params=params, headers={"Accept": "application/json"})
    if r.status_code == 403:
        raise RuntimeError("HTTP 403 (is the json format enabled in the instance's settings.yml?)")
    r.raise_for_status()
    out = []
    for x in (r.json().get("results") or []):
        url = x.get("url") or ""
        if not url.startswith(("http://", "https://")):
            continue
        row = {"url": url, "title": x.get("title") or "", "snippet": (x.get("content") or "")[:300]}
        if iso_date(x.get("publishedDate")):                 # engine-supplied
            row["publish_date"], row["date_source"] = iso_date(x["publishedDate"]), "engine"
        out.append(row)
        if len(out) >= k:
            break
    return out


def _parallel_call(tool: str, arguments: dict, timeout: float) -> list:
    """JSON-RPC handshake against the public Parallel Search MCP endpoint (initialize, initialized,
    tools/call); returns the `result.content` list. No API key is sent."""
    hdr = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

    def parse(r):
        t = r.text
        if t.lstrip().startswith("{"):
            return json.loads(t)
        for line in t.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
        return {}

    with _make_client(timeout) as c:
        r = c.post(PARALLEL_MCP_URL, headers=hdr, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "quick-read", "version": __version__}}})
        r.raise_for_status()
        h2 = dict(hdr)
        sid = r.headers.get("mcp-session-id")
        if sid:
            h2["Mcp-Session-Id"] = sid
        c.post(PARALLEL_MCP_URL, headers=h2, json={"jsonrpc": "2.0", "method": "notifications/initialized",
                                                    "params": {}})
        r = c.post(PARALLEL_MCP_URL, headers=h2, json={
            "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": tool, "arguments": arguments}})
        r.raise_for_status()
    return parse(r).get("result", {}).get("content", [])


def be_parallel(q: str, k: int, lang: str | None) -> list[dict]:
    polite("parallel")
    objective = q
    if lang not in (None, "en"):          # no language parameter: say it in the objective
        objective = f"Find pages written in {lang_params(lang)['name'] or lang}. Query: {q}"
    content = _parallel_call("web_search", {"objective": objective, "search_queries": [q[:200]]}, timeout=20)
    if not content:
        return []
    data = json.loads(content[0].get("text", "{}"))
    out = []
    for x in (data.get("results") or [])[:k]:
        ex = x.get("excerpts") or x.get("snippet") or ""
        if isinstance(ex, list):
            ex = " ".join(ex)
        row = {"url": x.get("url", ""), "title": x.get("title", ""), "snippet": str(ex)[:300]}
        if iso_date(x.get("publish_date")):          # the page date Parallel reports (often null: none is invented)
            row["publish_date"], row["date_source"] = iso_date(x["publish_date"]), "engine"
        out.append(row)
    return out


register_backend("ddgs", be_ddgs, budget=8.0, egress="duckduckgo", available=_ddgs_available)
register_backend("searxng", be_searxng, budget=6.0, egress="searxng-instance", available=_searxng_available)
register_backend("parallel", be_parallel, budget=8.0, egress="parallel", default=False)


def default_backends() -> list[str]:
    """QUICK_READ_SEARCH_BACKENDS (comma separated) if set, else every default backend that is available."""
    env = [b.strip() for b in os.environ.get("QUICK_READ_SEARCH_BACKENDS", "").split(",") if b.strip()]
    if env:
        return env
    return [n for n, b in BACKENDS.items() if b.default and (b.available is None or b.available())]


# ---------------------------------------------------------------- cache

def cache_dir() -> Path:
    """$QUICK_READ_STATE_DIR/search or ~/.cache/quick-read/search. Holds query text and result lists."""
    env = os.environ.get("QUICK_READ_STATE_DIR")
    return (Path(env) if env else Path.home() / ".cache" / "quick-read") / "search"


def _cache_path(q: str, k: int, lang: str, backends: list[str], routes: list[str]) -> Path:
    key = json.dumps([q, k, lang, sorted(backends), sorted(routes), CACHE_VERSION], ensure_ascii=False)
    return cache_dir() / (hashlib.sha1(key.encode("utf-8")).hexdigest() + ".json")


# ---------------------------------------------------------------- search

def search(query: str, k: int = 10, lang: str | None = None, use_cache: bool = True, backends=None,
           routes: bool = True) -> dict:
    """Federated search. ``lang``: ISO 639-1 code of the query (None = guessed from the script, else 'en').
    ``backends``: names to use (default: ``default_backends()``). ``routes``: run registered routes whose
    ``match`` fires. Returns ``{query, lang, backends, routes_triggered, results, timings, errors, cached, ts}``;
    each result has ``url, title, snippet, sources, rank_by_source, egress, score, publish_date, date_source``
    and, for locale twins, ``alt_urls``; a demoted single-source hit has ``demoted: True``. Never raises on a
    backend failure (see ``errors``); a registered-name typo raises ValueError."""
    t_start = time.monotonic()
    load_plugins()
    lang = norm_lang(lang) or script_lang(query) or "en"
    names = list(backends) if backends is not None else default_backends()
    unknown = [n for n in names if n not in BACKENDS]
    if unknown:
        raise ValueError(f"unknown backend(s): {', '.join(unknown)} (registered: {', '.join(BACKENDS)})")
    triggered = []
    if routes:
        for rn, rt in ROUTES.items():
            try:
                if rt.match(query):
                    triggered.append(rn)
            except Exception:
                pass                                   # a broken matcher must not break the search
    cp = _cache_path(query, k, lang, names, triggered)
    if use_cache:
        try:
            if cp.exists() and time.time() - cp.stat().st_mtime < CACHE_TTL:
                d = json.loads(cp.read_text(encoding="utf-8"))
                d["cached"] = True
                return d
        except (OSError, ValueError):
            pass                                       # unreadable cache entry: search again
    jobs = {}
    for n in names:
        b = BACKENDS[n]
        jobs[n] = ((lambda b=b: b.fn(query, k, lang)), b.budget)
    for rn in triggered:
        rt = ROUTES[rn]
        jobs["route:" + rn] = ((lambda rt=rt: rt.fn(query)), rt.budget)
    final, timings, errors = fanout(jobs) if jobs else ({}, {}, {})
    if not names:
        errors["backends"] = ("no search backend available: install ddgs (pip install \"quick-read[search]\"), "
                              "set QUICK_READ_SEARXNG_URL, or name backends explicitly")
    weights = {f"route:{rn}": ROUTES[rn].weight for rn in triggered if f"route:{rn}" in final}
    weights.update({n: BACKENDS[n].weight for n in final if n in BACKENDS and BACKENDS[n].weight != 1.0})
    ranked = {n: final[n] for n in sorted(final, key=lambda n: (not n.startswith("route:"), n))}
    merged = demote_irrelevant(rrf_merge(ranked, weights, prefer=lang), query)[:k]
    annotate_dates(merged)
    for e in merged:
        eg = set()
        for s in e["sources"]:
            if s.startswith("route:"):
                rt = ROUTES.get(s[6:])
                eg.add(("direct:" + rt.egress) if rt and rt.egress else "local")
            else:
                eg.add(BACKENDS[s].egress if s in BACKENDS else s)
        e["egress"] = sorted(eg)
    timings["total"] = round(time.monotonic() - t_start, 2)
    out = {"query": query, "lang": lang, "backends": names, "routes_triggered": triggered, "results": merged,
           "timings": timings, "errors": errors, "cached": False,
           "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if use_cache and final:                            # never cache a total failure
        try:
            cp.parent.mkdir(parents=True, exist_ok=True)
            cp.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass
    return out


# ---------------------------------------------------------------- multilingual fan-out

def _resolve_translations(query, wanted, supplied, translator, deadline):
    """-> ({lang: (text, origin)}, [untranslated langs]). Per language: (a) the caller's own translation
    (origin 'caller'), (b) the optional `translator(query, lang)` callable (threads, hard deadline; origin
    'translator'), (c) not translated."""
    got = {lg: (supplied[lg], "caller") for lg in wanted if lg in supplied}
    missing = [lg for lg in wanted if lg not in got]
    if missing and translator:
        res: dict = {}
        ths = []

        def one(lg):
            try:
                res[lg] = translator(query, lg)
            except Exception:
                res[lg] = None                 # a failing translator means not translated, not a crashed search
        for lg in missing:
            th = threading.Thread(target=one, args=(lg,), daemon=True)
            th.start()
            ths.append(th)
        for th in ths:
            th.join(max(0.0, deadline - time.monotonic()))
        for lg in missing:
            t = res.get(lg)
            if isinstance(t, str) and t.strip():
                got[lg] = (t.strip(), "translator")
    return got, [lg for lg in wanted if lg not in got]


def merge_variants(variants: list[dict], k: int, orig_lang: str) -> list[dict]:
    """variants: [{lang, query, origin, results[]}] (results = search() merged lists). RRF across variants
    (the original-language variant weighs ORIG_W when translations exist). Every result carries `lang` and
    `query_variant` of the variant that ranked it best, `variants` (all that found it) and `rank_by_variant`;
    `sources`, `rank_by_source` and `egress` are the union over variants."""
    ranked, by_label = {}, {}
    for v in variants:
        ranked[v["lang"]] = [{"url": e["url"], "title": e.get("title", ""), "snippet": e.get("snippet", ""),
                              "alt_urls": e.get("alt_urls") or [], "publish_date": e.get("publish_date", ""),
                              "date_source": e.get("date_source", "")}
                             for e in v["results"]]
        by_label[v["lang"]] = {locale_key(e["url"])[0]: e for e in v["results"]}
    weights = {orig_lang: ORIG_W} if len(variants) > 1 else {}
    qtext = {v["lang"]: v["query"] for v in variants}

    def _prefer(e):          # locale twins: the language of the variant that ranked the page best, then the original's
        return [min((r, lg == orig_lang, lg) for lg, r in e["rank_by_source"].items())[2], orig_lang]
    merged = rrf_merge(ranked, weights, prefer=_prefer)[:k]
    for e in merged:
        key = locale_key(e["url"])[0]
        found = [(e["rank_by_source"][lg], lg == orig_lang, lg) for lg in e["sources"]]   # sources == variant langs here
        best = min(found)                                                                 # lowest rank; translation first on a tie
        backends, egress, rbs = set(), set(), {}
        for lg in e["sources"]:
            it = by_label[lg][key]
            backends.update(it.get("sources", []))
            egress.update(it.get("egress", []))
            for b, r in (it.get("rank_by_source") or {}).items():
                rbs[b] = min(rbs.get(b, r), r)
        if e.get("publish_date") in (None, ""):                  # rrf_merge carried the first non-empty date, if any
            e["publish_date"], e["date_source"] = "", "none"
        elif e.get("date_source") in (None, "", "none"):
            e["date_source"] = "engine"
        e["rank_by_variant"] = dict(e["rank_by_source"])
        e["variants"] = list(e["sources"])
        e["sources"], e["rank_by_source"], e["egress"] = sorted(backends), rbs, sorted(egress)
        e["lang"], e["query_variant"] = best[2], qtext[best[2]]
    return merged


def search_multi(query: str, langs=None, translations: dict | None = None, k: int = 10, use_cache: bool = True,
                 budget: float = MULTI_BUDGET, translator=None, orig_lang: str | None = None, backends=None,
                 routes: bool = True, search_fn=None) -> dict:
    """Language-agnostic fan-out: the query is searched once in its own language and once per requested
    language, in parallel, then merged with RRF. ``langs``: ISO 639-1 codes. ``translations``: ``{lang: text}``
    written by the CALLER (an LLM agent should pass its own); a language listed in ``translations`` is searched
    even if it is not in ``langs``. A requested language without a translation is translated by ``translator``
    if one is given, else reported in ``untranslated_langs`` and NOT searched (the original query still runs).
    At most MAX_VARIANTS - 1 extra languages are searched; the rest are listed in ``skipped_langs``. Returns
    the search() shape plus ``variants`` (per-language meta), ``langs``, ``untranslated_langs``,
    ``skipped_langs``; each result carries ``lang`` and ``query_variant``."""
    t0 = time.monotonic()
    deadline = t0 + budget
    search_fn = search_fn or search
    load_plugins()
    unknown = [n for n in (backends or []) if n not in BACKENDS]
    if unknown and search_fn is search:             # a typo is a caller error: raise, do not report per variant
        raise ValueError(f"unknown backend(s): {', '.join(unknown)} (registered: {', '.join(BACKENDS)})")
    orig = norm_lang(orig_lang) or script_lang(query) or "en"
    supplied = {}
    for lg, t in (translations or {}).items():
        if norm_lang(lg) and str(t or "").strip():
            supplied[norm_lang(lg)] = str(t).strip()
    wanted = list(dict.fromkeys(lg for lg in [norm_lang(x) for x in (langs or [])] + list(supplied)
                                if lg and lg != orig))
    skipped = wanted[MAX_VARIANTS - 1:]
    wanted = wanted[:MAX_VARIANTS - 1]
    t_tr = time.monotonic()
    got, untranslated = _resolve_translations(query, wanted, supplied, translator,
                                              min(deadline, t_tr + TRANSLATE_BUDGET))
    t_tr = time.monotonic() - t_tr
    plan = [{"lang": orig, "query": query, "origin": "original"}]
    plan += [{"lang": lg, "query": got[lg][0], "origin": got[lg][1]} for lg in wanted if lg in got]
    res: dict = {}
    errors: dict = {}

    def run(v):
        try:
            res[v["lang"]] = search_fn(v["query"], k, lang=v["lang"], use_cache=use_cache, backends=backends,
                                       routes=routes and v["lang"] == orig)
        except Exception as e:
            errors[v["lang"]] = f"{type(e).__name__}: {str(e)[:160]}"
    ths = []
    for v in plan:
        th = threading.Thread(target=run, args=(v,), daemon=True)
        th.start()
        ths.append(th)
    for th in ths:
        th.join(max(0.0, deadline - time.monotonic()))
    done, meta = [], []
    for v in plan:
        r = res.get(v["lang"])
        if r is None:
            errors.setdefault(v["lang"], f"timeout>{budget:g}s (dropped)")
        else:
            done.append({**v, "results": r.get("results", [])})
        meta.append({"lang": v["lang"], "query": v["query"], "origin": v["origin"],
                     "n": len(r["results"]) if r else 0, "timings": (r or {}).get("timings", {}),
                     "errors": (r or {}).get("errors", {}), "cached": bool((r or {}).get("cached"))})
    merged = merge_variants(done, k, orig)
    all_err = {f"{lg}:{b}": m for lg, r in res.items() for b, m in (r.get("errors") or {}).items()}
    all_err.update({f"{lg}": m for lg, m in errors.items()})
    return {"query": query, "lang": orig, "langs": wanted, "variants": meta, "untranslated_langs": untranslated,
            "skipped_langs": skipped, "routes_triggered": (res.get(orig) or {}).get("routes_triggered", []),
            "results": merged, "errors": all_err,
            "cached": bool(done) and all(m["cached"] for m in meta if m["n"]),
            "timings": {"total": round(time.monotonic() - t0, 2), "translate": round(t_tr, 2)},
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}


# ---------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    for st in (sys.stdout, sys.stderr):
        if hasattr(st, "reconfigure"):
            st.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(prog="quick_read search", description="Federated multilingual web search.")
    ap.add_argument("query")
    ap.add_argument("--langs", default="", help="comma separated ISO 639-1 codes to search in addition")
    ap.add_argument("--translation", "--tr", action="append", default=[], metavar="LANG=TEXT",
                    help="your translation of the query for LANG (repeatable); required for LANG to be searched")
    ap.add_argument("--lang", default=None, help="language of the query itself (default: guessed)")
    ap.add_argument("--backends", default=None, help="comma separated backend names (default: all available)")
    ap.add_argument("--k", type=int, default=10)
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    tr = {}
    for x in a.translation:
        lg, sep, text = x.partition("=")
        if not sep or not lg.strip() or not text.strip():
            ap.error(f"--translation expects LANG=TEXT, got {x!r}")
        tr[lg.strip()] = text.strip()
    try:
        r = search_multi(a.query, [x for x in a.langs.split(",") if x.strip()], tr, a.k,
                         use_cache=not a.no_cache, orig_lang=a.lang,
                         backends=[b.strip() for b in a.backends.split(",") if b.strip()] if a.backends else None)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=1))
    else:
        print(f"Q: {r['query']}  lang={r['lang']} total={r['timings']['total']}s"
              f"  untranslated={r['untranslated_langs'] or '-'}  errors={r['errors'] or '-'}")
        for v in r["variants"]:
            print(f"  [{v['lang']}/{v['origin']}] n={v['n']} {v['query']}")
        for i, e in enumerate(r["results"], 1):
            d = f"  {e['publish_date']} ({e['date_source']})" if e.get("publish_date") else ""
            print(f"{i:>2}. [{e['lang']}] {e['title'][:90]}\n    {e['url']}{d}\n    via {','.join(e['sources'])}"
                  f" score={e['score']}")
    return 0 if r["results"] else 1


if __name__ == "__main__":
    sys.exit(main())
