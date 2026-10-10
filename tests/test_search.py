"""Offline tests for quick_read.search. No live network: backends are replaced by stubs, and the three
built-in backends are exercised through httpx.MockTransport / a stand-in ``ddgs`` module answering with
response shapes recorded on 2026-10-10 (Parallel Search MCP result envelope, SearXNG JSON results).

Ranked URL lists in ``fixtures/search_recorded_rows.json`` were returned by three real backends for one
English query on 2026-10-10 (URLs only).

Run: python -m pytest tests/test_search.py -v
"""
import json
import re
import sys
import time
import types
from datetime import date
from pathlib import Path

import httpx
import pytest

from quick_read import search as S

HERE = Path(__file__).resolve().parent
REC = json.loads((HERE / "fixtures" / "search_recorded_rows.json").read_text(encoding="utf-8"))
REC_RANKED = {b: [{"url": u} for u in urls] for b, urls in REC["ranked"].items()}
TODAY = date(2026, 10, 10)

EN = "https://docs.example.org/en/guide"
RU = "https://docs.example.org/ru/guide"
OTHER = "https://docs.example.org/en/reference"


@pytest.fixture(autouse=True)
def clean(monkeypatch, tmp_path):
    """Empty registries, a private cache dir, no politeness sleeps, no env leakage."""
    monkeypatch.setattr(S, "BACKENDS", {})
    monkeypatch.setattr(S, "ROUTES", {})
    monkeypatch.setattr(S, "_PLUGINS_DONE", True)
    monkeypatch.setattr(S, "polite", lambda *a, **k: None)
    monkeypatch.setenv("QUICK_READ_STATE_DIR", str(tmp_path / "state"))
    for v in ("QUICK_READ_SEARCH_BACKENDS", "QUICK_READ_SEARCH_PLUGINS", "QUICK_READ_SEARXNG_URL",
              "QUICK_READ_SEARXNG_ENGINES"):
        monkeypatch.delenv(v, raising=False)


def stub(items, seconds=0.0, calls=None):
    def fn(q, k, lang):
        if calls is not None:
            calls.append((q, k, lang))
        if seconds:
            time.sleep(seconds)
        return items
    return fn


def job(items, seconds=0.0):
    def fn():
        if seconds:
            time.sleep(seconds)
        return items
    return fn


# ---------------------------------------------------------------- norm_url

class TestNormUrl:
    def test_scheme_and_schemeless_share_one_key(self):
        assert S.norm_url("http://x.org/a") == S.norm_url("https://x.org/a") == S.norm_url("x.org/a/") == "x.org/a"

    @pytest.mark.parametrize("u", ["https://www.x.org/a", "https://m.x.org/a", "https://amp.x.org/a"])
    def test_www_m_amp_prefix_stripped(self, u):
        assert S.norm_url(u) == "x.org/a"

    def test_trailing_slash_stripped(self):
        assert S.norm_url("https://x.org/a/b/") == "x.org/a/b"

    def test_tracking_params_dropped_other_params_kept(self):
        assert S.norm_url("https://x.org/a?utm_source=x&id=5&fbclid=zz&ref=abc&refid=9") == "x.org/a?id=5&refid=9"

    def test_query_order_is_irrelevant(self):
        assert S.norm_url("https://x.org/a?b=2&a=1") == S.norm_url("https://x.org/a?a=1&b=2")

    def test_percent_encoding_decoded(self):
        assert S.norm_url("https://x.org/%C3%B1a/") == S.norm_url("https://x.org/ña") == "x.org/ña"

    def test_case_insensitive(self):
        assert S.norm_url("https://X.org/Doc/AB-1") == S.norm_url("https://x.org/doc/ab-1")

    def test_default_port_dropped_other_kept(self):
        assert S.norm_url("http://x.org:80/a") == "x.org/a"
        assert S.norm_url("http://x.org:8080/a") == "x.org:8080/a"

    def test_fragment_dropped_and_repeated_slashes_collapsed(self):
        assert S.norm_url("https://x.org/a#sec") == "x.org/a"
        assert S.norm_url("https://x.org//a///b") == "x.org/a/b"

    @pytest.mark.parametrize("u", ["", "   ", None])
    def test_empty_input_gives_empty_key(self, u):
        assert S.norm_url(u) == ""

    def test_root_slash_has_same_key_as_bare_host(self):
        assert S.norm_url("https://www.X.org/") == S.norm_url("https://x.org")

    def test_invalid_port_does_not_raise(self):
        assert S.norm_url("http://x.org:99999999/a") == "x.org/a"


# ---------------------------------------------------------------- rrf_merge

class TestRrf:
    A, B, C = "https://a.org/x", "https://b.org/y", "https://c.org/z"

    def test_score_order_and_arithmetic(self):
        out = S.rrf_merge({"p": [{"url": self.A}, {"url": self.B}], "d": [{"url": self.B}, {"url": self.C}]})
        assert [e["url"] for e in out] == [self.B, self.A, self.C]
        assert out[0]["score"] == round(1 / 61 + 1 / 62, 5)
        assert out[1]["score"] == round(1 / 61, 5)
        assert out[2]["score"] == round(1 / 62, 5)

    def test_ranks_kept_per_source(self):
        out = {e["url"]: e for e in S.rrf_merge({"p": [{"url": self.A}, {"url": self.B}], "d": [{"url": self.B}]})}
        assert out[self.B]["rank_by_source"] == {"p": 2, "d": 1}
        assert out[self.B]["sources"] == ["p", "d"]

    def test_dedup_across_backends_by_normalized_url(self):
        out = S.rrf_merge({"p": [{"url": "https://www.A.org/x/"}], "d": [{"url": "http://a.org/x?utm_source=q"}]})
        assert len(out) == 1 and out[0]["sources"] == ["p", "d"]
        assert out[0]["score"] == round(2 / 61, 5)

    def test_same_url_twice_in_one_source_keeps_best_rank(self):
        out = S.rrf_merge({"p": [{"url": self.A}, {"url": self.B}, {"url": "https://www.a.org/x/"}]})
        a = next(e for e in out if e["url"] == self.A)
        assert a["rank_by_source"] == {"p": 1} and a["score"] == round(1 / 61, 5)

    def test_route_rank1_beats_three_agreeing_backends(self):
        ranked = {"route:r": [{"url": self.C, "conf": 1.0}],
                  "p": [{"url": self.A}], "d": [{"url": self.A}], "s": [{"url": self.A}]}
        out = S.rrf_merge(ranked, {"route:r": S.ROUTE_W})
        assert [e["url"] for e in out] == [self.C, self.A]
        assert out[0]["score"] == round(4 / 61, 5) and out[1]["score"] == round(3 / 61, 5)

    def test_route_conf_scales_its_score(self):
        out = S.rrf_merge({"route:r": [{"url": self.C, "conf": 0.5}]}, {"route:r": S.ROUTE_W})
        assert out[0]["score"] == round(4 * 0.5 / 61, 5)

    def test_route_url_form_wins_as_display_url(self):
        out = S.rrf_merge({"p": [{"url": "https://www.A.org/x/"}], "route:r": [{"url": "https://a.org/x"}]},
                          {"route:r": S.ROUTE_W})
        assert out[0]["url"] == "https://a.org/x"

    def test_recorded_rows_from_three_real_backends(self):
        out = S.rrf_merge(REC_RANKED)
        all_keys = {S.norm_url(x["url"]) for items in REC_RANKED.values() for x in items}
        assert len(out) == len(all_keys)
        top = out[0]
        assert top["url"] == "https://home.treasury.gov/news/press-releases/jy1296"
        assert top["score"] == round(3 / 61, 5) and sorted(top["sources"]) == ["ddgs", "parallel", "searxng"]
        kramer = next(e for e in out if "hsfkramer" in e["url"])
        assert kramer["rank_by_source"] == {"ddgs": 2, "searxng": 3}
        assert kramer["score"] == round(1 / 62 + 1 / 63, 5)
        scores = [e["score"] for e in out]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------- locale twins

class TestLocale:
    def test_path_locale_variants_share_a_key(self):
        (ke, le), (kr, lr) = S.locale_key(EN), S.locale_key(RU)
        assert ke == kr and (le, lr) == ("en", "ru")

    def test_region_suffix_and_param_variants(self):
        assert S.locale_key("https://x.example/en-US/a")[0] == S.locale_key("https://x.example/de/a")[0]
        assert S.locale_key("https://x.example/en-US/a")[1] == "en"
        k1, l1 = S.locale_key("https://x.example/a?id=5&hl=en")
        k2, l2 = S.locale_key("https://x.example/a?hl=ru&id=5")
        assert k1 == k2 and (l1, l2) == ("en", "ru")
        assert S.locale_key("https://x.example/a?id=5&lang=de")[0] == k1

    @pytest.mark.parametrize("u", ["https://x.org/a/b?x=1", "https://x.example/docs/cli-reference",
                                   "https://x.example/a?lang=python", "https://x.example/zz/a",
                                   "https://x.example/eng/a", "https://x.example/"])
    def test_non_locale_urls_untouched(self, u):
        key, loc = S.locale_key(u)
        assert key == S.norm_url(u) and loc is None

    def test_empty(self):
        assert S.locale_key("") == ("", None)

    def two(self):
        return {"p": [{"url": RU, "title": "ru"}, {"url": EN, "title": "en"}], "d": [{"url": EN, "title": "en"}]}

    def test_twins_merge_into_one_entry_scores_add_up(self):
        out = S.rrf_merge(self.two(), prefer="en")
        assert len(out) == 1 and out[0]["url"] == EN and out[0]["alt_urls"] == [RU]
        assert out[0]["sources"] == ["p", "d"]
        assert out[0]["score"] > S.rrf_merge({"p": [{"url": EN}]})[0]["score"]

    def test_query_language_decides_then_en_then_first_seen(self):
        assert S.rrf_merge(self.two(), prefer="ru")[0]["url"] == RU
        assert S.rrf_merge(self.two(), prefer="ru")[0]["alt_urls"] == [EN]
        assert S.rrf_merge(self.two(), prefer="hu")[0]["url"] == EN         # no hu twin: en
        assert S.rrf_merge(self.two())[0]["url"] == EN                      # no preference: en
        de, fr = "https://x.example/de/a", "https://x.example/fr/a"
        out = S.rrf_merge({"p": [{"url": fr}, {"url": de}]}, prefer="hu")[0]
        assert (out["url"], out["alt_urls"]) == (fr, [de])                  # no en twin either: first seen

    def test_lone_url_has_no_alt_urls_and_plain_duplicates_are_not_alts(self):
        out = S.rrf_merge({"p": [{"url": "http://www.x.example/en/a/"}], "q": [{"url": "https://x.example/en/a"}]})
        assert len(out) == 1 and "alt_urls" not in out[0]

    def test_route_url_stays_pinned(self):
        out = S.rrf_merge({"route:r": [{"url": RU}], "d": [{"url": EN}]}, prefer="en")
        assert out[0]["url"] == RU and out[0]["alt_urls"] == [EN]

    def test_search_keeps_the_query_language_twin(self):
        S.register_backend("p", stub([{"url": RU, "title": "ru", "snippet": "s"},
                                      {"url": EN, "title": "en", "snippet": "s"},
                                      {"url": OTHER, "title": "ref", "snippet": "s"}]))
        r = S.search("plugin guide", 10, use_cache=False, routes=False)
        assert [e["url"] for e in r["results"]] == [EN, OTHER]
        assert r["results"][0]["alt_urls"] == [RU]
        r = S.search("plugin guide", 10, lang="ru", use_cache=False, routes=False)
        assert r["results"][0]["url"] == RU

    def test_merge_variants_prefers_the_variant_that_ranked_it_best(self):
        def hit(u, t):
            return {"url": u, "title": t, "snippet": "s", "sources": ["ddgs"], "rank_by_source": {"ddgs": 1},
                    "egress": ["duckduckgo"], "score": 0.02}
        v = [{"lang": "en", "query": "q", "origin": "original", "results": [hit(EN, "en")]},
             {"lang": "ru", "query": "q-ru", "origin": "caller",
              "results": [hit("https://x.example/other", "o"), hit(RU, "ru")]}]
        m = next(e for e in S.merge_variants(v, 10, "en") if "docs.example" in e["url"])
        assert m["url"] == EN and m["alt_urls"] == [RU] and m["variants"] == ["en", "ru"]
        v[0]["results"] = [hit("https://x.example/zzz", "z")]
        solo = next(e for e in S.merge_variants(v, 10, "en") if "docs.example" in e["url"])
        assert (solo["url"], solo["lang"]) == (RU, "ru")


# ---------------------------------------------------------------- dates

class TestDates:
    SNIPPET = "Oct 24, 2021 - A short video about the story, uploaded by a user"

    def test_iso_date_only_accepts_iso(self):
        assert S.iso_date("2026-10-05") == "2026-10-05"
        assert S.iso_date("2026-10-05T10:00:00Z") == "2026-10-05"
        for bad in (None, "", "None", "2026-13-01", "2026-02-30", "Oct 5, 2026", "2026.10.05", "20261005"):
            assert S.iso_date(bad) == "", bad

    def test_full_dates_forms(self):
        assert S.full_dates("https://x.org/2026/10/09/story", TODAY) == ["2026-10-09"]
        assert S.full_dates("published 2026. 10. 09.", TODAY) == ["2026-10-09"]
        assert S.full_dates("9 October 2026", TODAY) == ["2026-10-09"]
        assert S.full_dates("on 3rd of March, 2026", TODAY) == ["2026-03-03"]
        assert S.full_dates(self.SNIPPET, TODAY) == ["2021-10-24"]

    def test_partial_future_and_impossible_dates_are_not_dates(self):
        assert S.full_dates("October 2026", TODAY) == []
        assert S.full_dates("October 15", TODAY) == []
        assert S.full_dates("/sanctions/2023-02/", TODAY) == []
        assert S.full_dates("meeting on October 15, 2026", TODAY) == []     # announced, after today
        assert S.full_dates("2026-02-30", TODAY) == []

    def test_infer_date_source_label(self):
        assert S.infer_date("https://x.org/2026/10/09/story", "", TODAY) == ("2026-10-09", "url")
        assert S.infer_date("https://x.org/v", self.SNIPPET, TODAY) == ("2021-10-24", "snippet")
        assert S.infer_date("https://x.org/2026/10/09/s", "Oct 24, 2021 - x", TODAY) == ("2026-10-09", "url")

    def test_unknown_or_ambiguous_stays_empty(self):
        assert S.infer_date(OTHER, "Exit codes: 0 on success", TODAY) == ("", "none")
        assert S.infer_date("https://x.org/a", "Oct 24, 2021 and Nov 2, 2022", TODAY) == ("", "none")
        assert S.infer_date("", "", TODAY) == ("", "none")

    def test_recorded_urls(self):
        # URLs from the recorded rows: one carries a full date, the others only a month or none
        assert S.infer_date("https://www.themoscowtimes.com/2026/10/08/uk-expands-sanctions-to-cover-90-of-"
                            "russian-oil-output-shadow-fleet-and-finance-networks-a93922", "", TODAY) \
            == ("2026-10-08", "url")
        assert S.infer_date("https://www.arnoldporter.com/en/perspectives/advisories/2024/03/us-imposes-sanctions",
                            "", TODAY) == ("", "none")
        assert S.infer_date("https://www.hsfkramer.com/notes/sanctions/2023-02/treasury-expands", "", TODAY) \
            == ("", "none")

    def test_annotate_keeps_engine_dates_and_labels_the_rest(self):
        rows = [{"url": OTHER, "snippet": "x", "publish_date": "2026-10-05", "date_source": "engine"},
                {"url": OTHER + "2", "snippet": "x"},
                {"url": "https://x.org/v", "snippet": self.SNIPPET},
                {"url": OTHER + "3", "snippet": "x", "publish_date": "2025-01-02"}]
        S.annotate_dates(rows, TODAY)
        assert [(r["publish_date"], r["date_source"]) for r in rows] == [
            ("2026-10-05", "engine"), ("", "none"), ("2021-10-24", "snippet"), ("2025-01-02", "engine")]

    def test_search_results_always_carry_date_source(self):
        S.register_backend("d", stub([{"url": "https://x.org/v", "title": "t", "snippet": self.SNIPPET},
                                      {"url": OTHER, "title": "c", "snippet": "nothing here"}]))
        r = S.search("short video story", 5, use_cache=False, routes=False)
        by = {e["url"]: e for e in r["results"]}
        assert (by["https://x.org/v"]["publish_date"], by["https://x.org/v"]["date_source"]) == ("2021-10-24", "snippet")
        assert (by[OTHER]["publish_date"], by[OTHER]["date_source"]) == ("", "none")

    def test_engine_date_survives_the_multilingual_merge(self):
        def hit(u, **kw):
            return {"url": u, "title": "t", "snippet": "s", "sources": ["parallel"],
                    "rank_by_source": {"parallel": 1}, "egress": ["parallel"], "score": 0.02, **kw}
        v = [{"lang": "en", "query": "q", "origin": "original", "results": [hit(EN)]},
             {"lang": "ru", "query": "q-ru", "origin": "caller",
              "results": [hit(RU, publish_date="2026-10-05", date_source="engine"),
                          hit("https://x.example/o", publish_date="2021-10-24", date_source="snippet")]}]
        m = {S.locale_key(e["url"])[0]: e for e in S.merge_variants(v, 10, "en")}
        twin = m[S.locale_key(EN)[0]]                           # EN and RU are one result
        assert (twin["publish_date"], twin["date_source"]) == ("2026-10-05", "engine")
        o = m[S.locale_key("https://x.example/o")[0]]
        assert (o["publish_date"], o["date_source"]) == ("2021-10-24", "snippet")
        v[1]["results"] = [hit(RU)]
        m2 = S.merge_variants(v, 10, "en")[0]
        assert (m2["publish_date"], m2["date_source"]) == ("", "none")


# ---------------------------------------------------------------- budgets

class TestBudgets:
    def test_slow_job_dropped_at_its_own_budget(self):
        t0 = time.monotonic()
        final, _t, errors = S.fanout({"fast": (job([{"url": "https://a.org/1"}]), 2.0),
                                      "slow": (job([{"url": "https://b.org/2"}], seconds=1.5), 0.3)})
        assert set(final) == {"fast"}
        assert errors["slow"] == "timeout>0.3s (dropped)"
        assert time.monotonic() - t0 < 1.2

    def test_total_budget_caps_a_job_with_larger_own_budget(self):
        t0 = time.monotonic()
        final, _t, errors = S.fanout({"slow": (job([], seconds=1.5), 30.0)}, total=0.3)
        assert final == {} and errors["slow"] == "timeout>30s (dropped)"
        assert time.monotonic() - t0 < 1.2

    def test_exception_is_recorded_not_raised(self):
        def boom():
            raise RuntimeError("boom")
        final, _t, errors = S.fanout({"b": (boom, 1.0)})
        assert final == {} and errors["b"] == "RuntimeError: boom"

    def test_late_result_of_a_dropped_job_is_ignored(self):
        final, _t, errors = S.fanout({"slow": (job([{"url": "https://a.org/1"}], seconds=0.4), 0.1),
                                      "fast": (job([{"url": "https://b.org/1"}], seconds=0.7), 1.5)})
        assert set(final) == {"fast"} and "slow" in errors

    def test_search_drops_slow_backend_and_stays_under_budget(self):
        S.register_backend("fast", stub([{"url": "https://a.org/1", "title": "T"}]), budget=2.0)
        S.register_backend("slow", stub([{"url": "https://b.org/2"}], seconds=1.5), budget=0.3)
        out = S.search("some query", backends=["fast", "slow"], routes=False, use_cache=False)
        assert [r["url"] for r in out["results"]] == ["https://a.org/1"]
        assert out["errors"]["slow"].startswith("timeout>0.3s")
        assert out["timings"]["total"] < 1.5


# ---------------------------------------------------------------- search(): orchestration, cache, guard

class TestSearch:
    def test_backend_exception_recorded_not_raised(self):
        def boom(q, k, lang):
            raise RuntimeError("boom")
        S.register_backend("b", boom)
        out = S.search("some query", backends=["b"], routes=False, use_cache=False)
        assert out["errors"]["b"] == "RuntimeError: boom" and out["results"] == []

    def test_cache_hit_skips_backends_and_failure_is_not_cached(self):
        calls = []
        S.register_backend("p", stub([{"url": "https://a.org/1", "title": "T", "snippet": "S"}], calls=calls))
        first = S.search("some query", backends=["p"], routes=False)
        second = S.search("some query", backends=["p"], routes=False)
        assert first["cached"] is False and second["cached"] is True and len(calls) == 1

        def boom(q, k, lang):
            raise RuntimeError("boom")
        S.register_backend("bad", boom)
        before = len(list(S.cache_dir().glob("*.json")))
        failed = S.search("another query", backends=["bad"], routes=False)
        assert failed["results"] == [] and len(list(S.cache_dir().glob("*.json"))) == before

    def test_cache_key_depends_on_backend_set(self):
        S.register_backend("p", stub([{"url": "https://a.org/1"}]))
        S.register_backend("q", stub([{"url": "https://b.org/1"}]))
        a = S.search("some query", backends=["p"], routes=False)
        b = S.search("some query", backends=["q"], routes=False)
        assert b["cached"] is False and [r["url"] for r in b["results"]] == ["https://b.org/1"]
        assert [r["url"] for r in a["results"]] == ["https://a.org/1"]

    def test_unreadable_cache_entry_is_ignored(self):
        S.register_backend("p", stub([{"url": "https://a.org/1"}]))
        S.search("some query", backends=["p"], routes=False)
        for f in S.cache_dir().glob("*.json"):
            f.write_text("{not json", encoding="utf-8")
        assert S.search("some query", backends=["p"], routes=False)["cached"] is False

    def test_unknown_backend_is_a_value_error(self):
        with pytest.raises(ValueError, match="unknown backend"):
            S.search("q", backends=["nope"])

    def test_no_available_backend_is_reported_not_silent(self):
        out = S.search("some query", use_cache=False)
        assert out["results"] == [] and "no search backend available" in out["errors"]["backends"]

    def test_default_backends_follow_availability_and_env(self, monkeypatch):
        S.register_backend("here", stub([]), available=lambda: True)
        S.register_backend("absent", stub([]), available=lambda: False)
        S.register_backend("optin", stub([]), default=False)
        assert S.default_backends() == ["here"]
        monkeypatch.setenv("QUICK_READ_SEARCH_BACKENDS", "optin, here")
        assert S.default_backends() == ["optin", "here"]

    def test_register_rejects_duplicates_and_bad_names(self):
        S.register_backend("x", stub([]))
        with pytest.raises(ValueError):
            S.register_backend("x", stub([]))
        S.register_backend("x", stub([]), replace=True)
        for bad in ("", "route:x", "a b"):
            with pytest.raises(ValueError):
                S.register_backend(bad, stub([]))
        S.register_route("r", lambda q: True, lambda q: [])
        with pytest.raises(ValueError):
            S.register_route("r", lambda q: True, lambda q: [])

    def test_custom_backend_weight_and_egress(self):
        S.register_backend("heavy", stub([{"url": "https://a.org/1", "title": "alpha beta gamma"}]), weight=1.3,
                           egress="my-index")
        S.register_backend("plain", stub([{"url": "https://b.org/1", "title": "alpha beta gamma"}]))
        out = S.search("alpha beta gamma", backends=["heavy", "plain"], routes=False, use_cache=False)
        assert [r["url"] for r in out["results"]] == ["https://a.org/1", "https://b.org/1"]
        assert out["results"][0]["score"] == round(1.3 / 61, 5)
        assert out["results"][0]["egress"] == ["my-index"]

    def test_route_fires_and_merges_with_route_weight(self):
        url = "https://refs.example.org/item/42"
        S.register_backend("p", stub([{"url": url, "title": "Item 42", "snippet": "s"}]))
        S.register_route("item", lambda q: "item 42" in q.lower(),
                         lambda q: [{"url": url, "title": "Item 42", "snippet": "listed", "conf": 1.0}],
                         egress="refs.example.org")
        out = S.search("find item 42", backends=["p"], use_cache=False)
        assert out["routes_triggered"] == ["item"] and len(out["results"]) == 1
        r = out["results"][0]
        assert sorted(r["sources"]) == ["p", "route:item"]
        assert r["score"] == round(1 / 61 + S.ROUTE_W / 61, 5)
        assert r["egress"] == ["custom:p", "direct:refs.example.org"]

    def test_route_without_egress_is_local_and_broken_matcher_is_skipped(self):
        S.register_route("loc", lambda q: True, lambda q: [{"url": "https://a.org/1", "title": "t", "snippet": "s"}])

        def bad(q):
            raise RuntimeError("x")
        S.register_route("bad", bad, lambda q: [])
        out = S.search("anything", backends=[], routes=True, use_cache=False)
        assert out["routes_triggered"] == ["loc"] and out["results"][0]["egress"] == ["local"]

    def test_routes_can_be_switched_off(self):
        S.register_route("loc", lambda q: True, lambda q: [{"url": "https://a.org/1"}])
        assert S.search("anything", backends=[], routes=False, use_cache=False)["routes_triggered"] == []

    def test_lang_is_guessed_from_the_script_else_english(self):
        calls = []
        S.register_backend("p", stub([], calls=calls))
        S.search("проверка запроса", backends=["p"],
                 routes=False, use_cache=False)
        S.search("plain latin query", backends=["p"], routes=False, use_cache=False)
        S.search("plain latin query", lang="DE-at", backends=["p"], routes=False, use_cache=False)
        assert [c[2] for c in calls] == ["ru", "en", "de"]


class TestRelevanceGuard:
    def mk(self, sources, title="", snippet="", url="https://a.org/x"):
        return {"url": url, "title": title, "snippet": snippet, "sources": sources, "score": 0.016}

    Q = "sanctions evasion military supplies"

    def test_single_source_offtopic_is_demoted_below_multi_source(self):
        off = self.mk(["p"], title="Weekend recipes", url="https://a.org/recipes")
        multi = self.mk(["p", "d"], title="Weekend recipes", url="https://a.org/recipes2")
        multi["score"] = 0.032
        out = S.demote_irrelevant([off, multi], self.Q)
        assert out[0] is multi and off["demoted"] is True and off["score"] == round(0.016 * S.GUARD_PENALTY, 5)

    def test_single_source_ontopic_is_kept(self):
        e = self.mk(["p"], title="Sanctions on evasion of military supplies")
        assert S.demote_irrelevant([e], self.Q)[0].get("demoted") is None

    def test_route_hits_and_short_queries_are_never_demoted(self):
        e = self.mk(["route:r"], title="unrelated")
        assert "demoted" not in S.demote_irrelevant([e], self.Q)[0]
        e = self.mk(["p"], title="unrelated")
        assert "demoted" not in S.demote_irrelevant([e], "two words")[0]

    def test_guard_works_on_non_latin_queries(self):
        q = "проверка запроса поиска данных"
        e = self.mk(["p"], title="cats and dogs")
        assert S.demote_irrelevant([e], q)[0]["demoted"] is True


# ---------------------------------------------------------------- multilingual

class TestMulti:
    def setup_method(self):
        pass

    def test_script_and_language_helpers(self):
        assert S.script_lang("привет") == "ru"
        assert S.script_lang("привіт") == "uk"
        assert S.script_lang("שלום") == "he"
        assert S.script_lang("hello") == ""
        assert [S.norm_lang(c) for c in ("RU", "ru-RU", "zh_CN", "iw", "", None)] == ["ru", "ru", "zh", "he", None, None]
        assert S.lang_params("ru") == {"name": "Russian", "ddgs_region": "ru-ru", "searx_lang": "ru"}
        assert S.lang_params("xx") == {"name": "xx", "ddgs_region": "wt-wt", "searx_lang": "xx"}
        assert S.lang_params("en")["searx_lang"] is None

    def backend(self, by_query, calls):
        def fn(q, k, lang):
            calls.append((q, lang))
            return by_query.get(q, [])
        S.register_backend("p", fn)

    def test_caller_translations_are_searched_and_merged(self):
        calls = []
        self.backend({"sanctions evasion": [{"url": "https://a.org/1", "title": "alpha"}, {"url": "https://b.org/2"}],
                      "RU-TEXT": [{"url": "https://c.org/3", "title": "gamma"}, {"url": "https://b.org/2"}]}, calls)
        r = S.search_multi("sanctions evasion", langs=["ru"], translations={"ru": "RU-TEXT"}, use_cache=False)
        assert sorted(calls) == [("RU-TEXT", "ru"), ("sanctions evasion", "en")]
        assert [(v["lang"], v["origin"], v["n"]) for v in r["variants"]] == [("en", "original", 2), ("ru", "caller", 2)]
        assert r["untranslated_langs"] == [] and r["langs"] == ["ru"]
        by = {e["url"]: e for e in r["results"]}
        assert r["results"][0]["url"] == "https://b.org/2"                       # found by both variants
        assert by["https://b.org/2"]["variants"] == ["en", "ru"]
        assert by["https://c.org/3"]["lang"] == "ru" and by["https://c.org/3"]["query_variant"] == "RU-TEXT"
        # original-language variant weighs ORIG_W: a's rank-1 (en) is worth less than c's rank-1 (ru)
        assert by["https://a.org/1"]["score"] == round(S.ORIG_W / 61, 5)
        assert by["https://c.org/3"]["score"] == round(1 / 61, 5)

    def test_translation_alone_adds_its_language(self):
        calls = []
        self.backend({}, calls)
        r = S.search_multi("query text", translations={"he": "HE-TEXT"}, use_cache=False)
        assert r["langs"] == ["he"] and ("HE-TEXT", "he") in calls

    def test_language_without_translation_is_reported_not_searched(self):
        calls = []
        self.backend({}, calls)
        r = S.search_multi("query text", langs=["ru", "he"], translations={"he": "HE-TEXT"}, use_cache=False)
        assert r["untranslated_langs"] == ["ru"]
        assert sorted(c[1] for c in calls) == ["en", "he"]

    def test_optional_translator_fills_gaps_and_failures_are_survivable(self):
        calls = []
        self.backend({}, calls)

        def tr(q, lang):
            if lang == "de":
                raise RuntimeError("down")
            return f"{q}-{lang}"
        r = S.search_multi("query text", langs=["ru", "de", "fr"], translations={"fr": "FR-TEXT"}, translator=tr,
                           use_cache=False)
        origins = {v["lang"]: v["origin"] for v in r["variants"]}
        assert origins == {"en": "original", "fr": "caller", "ru": "translator"}
        assert r["untranslated_langs"] == ["de"]

    def test_variant_cap_lists_the_skipped_languages(self):
        calls = []
        self.backend({}, calls)
        langs = ["ru", "de", "fr", "es", "it", "pl", "cs"]
        r = S.search_multi("query text", langs=langs, translations={lg: lg.upper() for lg in langs}, use_cache=False)
        assert len(r["variants"]) == S.MAX_VARIANTS and r["skipped_langs"] == ["pl", "cs"]

    def test_routes_run_only_for_the_original_variant(self):
        seen = []
        S.register_backend("p", stub([]))
        S.register_route("r", lambda q: seen.append(q) or False, lambda q: [])
        S.search_multi("orig text", langs=["ru"], translations={"ru": "RU-TEXT"}, use_cache=False)
        assert seen == ["orig text"]

    def test_a_failing_variant_is_reported_and_does_not_drop_the_others(self):
        def fake(q, k, lang, **kw):
            if lang == "ru":
                raise RuntimeError("boom")
            return {"results": [{"url": "https://a.org/1", "title": "t", "snippet": "", "sources": ["p"],
                                 "rank_by_source": {"p": 1}, "egress": [], "score": 0.01}], "timings": {}, "errors": {}}
        r = S.search_multi("query text", langs=["ru"], translations={"ru": "x"}, search_fn=fake, use_cache=False)
        assert r["errors"]["ru"].startswith("RuntimeError: boom") and len(r["results"]) == 1

    def test_slow_variant_is_dropped_at_the_multi_budget(self):
        def fake(q, k, lang, **kw):
            if lang == "ru":
                time.sleep(1.0)
            return {"results": [], "timings": {}, "errors": {}}
        t0 = time.monotonic()
        r = S.search_multi("query text", langs=["ru"], translations={"ru": "x"}, search_fn=fake, budget=0.3)
        assert time.monotonic() - t0 < 0.9 and r["errors"]["ru"] == "timeout>0.3s (dropped)"


# ---------------------------------------------------------------- built-in backends (recorded response shapes)

def mock_client(monkeypatch, handler):
    monkeypatch.setattr(S, "_make_client", lambda timeout: httpx.Client(
        transport=httpx.MockTransport(handler), timeout=timeout, headers={"User-Agent": S.UA}))


class TestSearxng:
    SHAPE = {"results": [
        {"url": "https://a.example/1", "title": "t1", "content": "c1", "engines": ["bing"],
         "publishedDate": "2026-10-05T10:00:00"},
        {"url": "https://a.example/2", "title": "t2", "content": "c2", "engines": ["bing"], "publishedDate": None},
        {"title": "no url", "content": "x"},
        {"url": "javascript:alert(1)", "title": "bad scheme"}]}

    def test_rows_dates_and_params(self, monkeypatch):
        monkeypatch.setenv("QUICK_READ_SEARXNG_URL", "http://127.0.0.1:8080/")
        monkeypatch.setenv("QUICK_READ_SEARXNG_ENGINES", "bing,brave")
        seen = []

        def handler(req):
            seen.append(req)
            return httpx.Response(200, json=self.SHAPE)
        mock_client(monkeypatch, handler)
        out = S.be_searxng("query", 5, "ru")
        assert [o["url"] for o in out] == ["https://a.example/1", "https://a.example/2"]
        assert (out[0]["publish_date"], out[0]["date_source"]) == ("2026-10-05", "engine")
        assert "publish_date" not in out[1]
        q = dict(seen[0].url.params)
        assert str(seen[0].url).startswith("http://127.0.0.1:8080/search?") and q["format"] == "json"
        assert q["language"] == "ru" and q["engines"] == "bing,brave"

    def test_english_sends_no_language_and_k_caps(self, monkeypatch):
        monkeypatch.setenv("QUICK_READ_SEARXNG_URL", "https://s.example")
        seen = []
        mock_client(monkeypatch, lambda req: seen.append(req) or httpx.Response(200, json=self.SHAPE))
        assert len(S.be_searxng("query", 1, "en")) == 1
        assert "language" not in dict(seen[0].url.params)

    def test_missing_url_and_403_give_clear_errors(self, monkeypatch):
        with pytest.raises(RuntimeError, match="QUICK_READ_SEARXNG_URL"):
            S.be_searxng("q", 5, "en")
        monkeypatch.setenv("QUICK_READ_SEARXNG_URL", "https://s.example")
        mock_client(monkeypatch, lambda req: httpx.Response(403))
        with pytest.raises(RuntimeError, match="json format"):
            S.be_searxng("q", 5, "en")

    def test_available_only_with_the_env_var(self, monkeypatch):
        assert S._searxng_available() is False
        monkeypatch.setenv("QUICK_READ_SEARXNG_URL", "https://s.example")
        assert S._searxng_available() is True


class TestParallel:
    ENVELOPE = {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": json.dumps({
        "search_id": "search_x", "results": [
            {"url": "https://docs.python.org/3/library/asyncio.html", "title": "asyncio documentation",
             "publish_date": None, "excerpts": ["first excerpt", "second excerpt"]},
            {"url": "https://a.example/dated", "title": "dated", "publish_date": "2026-10-05T00:00:00Z",
             "excerpts": ["x"]}]})}]}}

    def handler(self, seen, sse=False):
        def h(req):
            body = json.loads(req.content)
            seen.append((body.get("method"), req.headers.get("mcp-session-id"), body))
            if body["method"] == "initialize":
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}},
                                      headers={"mcp-session-id": "sess-1"})
            if body["method"] == "notifications/initialized":
                return httpx.Response(202)
            if sse:
                return httpx.Response(200, text="event: message\ndata: " + json.dumps(self.ENVELOPE) + "\n\n")
            return httpx.Response(200, json=self.ENVELOPE)
        return h

    @pytest.mark.parametrize("sse", [False, True])
    def test_handshake_rows_and_dates(self, monkeypatch, sse):
        seen = []
        mock_client(monkeypatch, self.handler(seen, sse))
        out = S.be_parallel("asyncio docs", 5, "en")
        assert [s[0] for s in seen] == ["initialize", "notifications/initialized", "tools/call"]
        assert seen[2][1] == "sess-1"                                   # session id carried to the call
        assert "Authorization" not in httpx.Headers() and seen[2][2]["params"]["name"] == "web_search"
        assert out[0]["snippet"] == "first excerpt second excerpt" and "publish_date" not in out[0]
        assert (out[1]["publish_date"], out[1]["date_source"]) == ("2026-10-05", "engine")

    def test_foreign_language_is_named_in_the_objective(self, monkeypatch):
        seen = []
        mock_client(monkeypatch, self.handler(seen))
        S.be_parallel("query", 5, "ru")
        assert seen[2][2]["params"]["arguments"]["objective"].startswith("Find pages written in Russian.")

    def test_not_in_the_default_set(self):
        S.register_backend("parallel", S.be_parallel, default=False)
        assert "parallel" not in S.default_backends()


class TestDdgs:
    def fake_module(self, monkeypatch, rows, fail_region=False):
        calls = []

        class DDGS:
            def __init__(self, timeout=None):
                pass

            def text(self, q, region="wt-wt", max_results=10):
                calls.append(region)
                if fail_region and region != "wt-wt":
                    raise RuntimeError("Invalid region code")
                return rows
        monkeypatch.setitem(sys.modules, "ddgs", types.SimpleNamespace(DDGS=DDGS))
        return calls

    ROWS = [{"href": "https://a.example/1", "title": "t", "body": "b" * 400}]

    def test_rows_region_and_snippet_cap(self, monkeypatch):
        calls = self.fake_module(monkeypatch, self.ROWS)
        out = S.be_ddgs("q", 5, "ru")
        assert calls == ["ru-ru"] and out[0]["url"] == "https://a.example/1" and len(out[0]["snippet"]) == 300
        assert S.be_ddgs("q", 5, "en") and calls[-1] == "wt-wt"

    def test_unknown_region_falls_back_to_worldwide(self, monkeypatch):
        calls = self.fake_module(monkeypatch, self.ROWS, fail_region=True)
        assert S.be_ddgs("q", 5, "ru") and calls == ["ru-ru", "wt-wt"]

    def test_missing_package_gives_the_install_hint(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "ddgs", None)               # import raises ImportError
        with pytest.raises(RuntimeError, match="quick-read\\[search\\]"):
            S.be_ddgs("q", 5, "en")


# ---------------------------------------------------------------- plugins, example route, CLI

def readme_route_example():
    text = (HERE.parent / "README.md").read_text(encoding="utf-8")
    for block in re.findall(r"```python\n(.*?)```", text, re.S):
        if "register_route(" in block:
            return block
    raise AssertionError("README has no route example")


class TestPluginsAndCli:
    def test_plugin_module_registers_on_load(self, monkeypatch, tmp_path):
        (tmp_path / "qr_plugin_demo.py").write_text(
            "from quick_read.search import register_backend\n"
            "register_backend('demo', lambda q, k, lang: [{'url': 'https://a.example/1', 'title': q}])\n",
            encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path))
        monkeypatch.setenv("QUICK_READ_SEARCH_PLUGINS", "qr_plugin_demo")
        monkeypatch.setattr(S, "_PLUGINS_DONE", False)
        out = S.search("demo query", use_cache=False, routes=False)
        sys.modules.pop("qr_plugin_demo", None)
        assert out["backends"] == ["demo"] and out["results"][0]["url"] == "https://a.example/1"

    def test_readme_route_example_works(self):
        ns = {}
        exec(compile(readme_route_example(), "README.md", "exec"), ns)
        assert "pep" in S.ROUTES
        S.register_backend("none", stub([]))
        r = S.search("what changed in PEP 8", backends=["none"], use_cache=False)
        assert r["routes_triggered"] == ["pep"]
        assert r["results"][0]["url"] == "https://peps.python.org/pep-0008/"
        assert S.search("no number here", backends=["none"], use_cache=False)["routes_triggered"] == []

    def run_cli(self, argv, capsys):
        from quick_read.__main__ import main
        code = main(argv)
        return code, capsys.readouterr().out

    def test_search_subcommand_json(self, capsys):
        calls = []
        S.register_backend("p", stub([{"url": "https://a.example/1", "title": "alpha"}], calls=calls))
        code, out = self.run_cli(["search", "sanctions evasion", "--langs", "ru,he", "--translation",
                                  "ru=RU TEXT = with equals", "--backends", "p", "--no-cache", "--json"], capsys)
        data = json.loads(out)
        assert code == 0 and data["untranslated_langs"] == ["he"]
        assert ("RU TEXT = with equals", "ru") in [(q, lg) for q, _, lg in calls]
        assert data["results"][0]["url"] == "https://a.example/1"

    def test_search_subcommand_text_and_exit_code(self, capsys):
        S.register_backend("p", stub([]))
        code, out = self.run_cli(["search", "nothing found", "--backends", "p", "--no-cache"], capsys)
        assert code == 1 and out.startswith("Q: nothing found")

    def test_bad_translation_and_unknown_backend(self, capsys):
        with pytest.raises(SystemExit) as e:
            self.run_cli(["search", "q", "--translation", "ru"], capsys)
        assert e.value.code == 2
        code, _ = self.run_cli(["search", "q", "--backends", "nope"], capsys)
        assert code == 2

    def test_url_mode_is_unchanged(self):
        import quick_read.__main__ as m
        ap_src = Path(m.__file__).read_text(encoding="utf-8")
        assert 'ap.add_argument("url")' in ap_src

    def test_package_exports(self):
        import quick_read
        assert quick_read.federated_search is S.search and quick_read.search_multi is S.search_multi
        assert hasattr(quick_read.search, "register_route")                # the submodule is not shadowed
