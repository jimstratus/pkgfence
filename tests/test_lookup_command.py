"""Tests for scripts/lookup_command.py — run_lookup routing beyond the parser."""
import concurrent.futures
import json
from unittest.mock import MagicMock, patch

from scripts.lookup_command import (
    _lookup_cve,
    _lookup_ghsa,
    _lookup_mal,
    run_lookup,
)


def test_run_lookup_adhoc_when_state_missing(tmp_path):
    missing = tmp_path / "no-such-state"
    out = run_lookup("CVE-2019-10744", no_web=True, state_dir=missing,
                     output_format="json")
    data = json.loads(out)
    assert data["type"] == "cve"
    assert "_adhoc" in data["advisory"]
    assert data["sources_consulted"] == []


def test_run_lookup_cve_routes_and_renders_json(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    with patch("scripts.lookup_command._lookup_cve", return_value={
        "kev": True, "epss": {"score": 0.5}, "ghsa": None,
    }) as lookup:
        with patch("scripts.lookup_command.web_search") as web:
            out = run_lookup(
                "CVE-2019-10744", no_web=True, state_dir=state,
                output_format="json",
            )
    lookup.assert_called_once_with("CVE-2019-10744", state)
    web.assert_not_called()
    data = json.loads(out)
    assert data["advisory"]["kev"] is True
    assert data["sources_consulted"] == ["kev", "epss", "ghsa"]


def test_run_lookup_mal_routes_to_osv(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    with patch("scripts.lookup_command._lookup_mal",
               return_value={"osv": {"id": "MAL-2024-1234"}}) as lookup:
        out = run_lookup(
            "MAL-2024-1234", no_web=True, state_dir=state, output_format="json",
        )
    lookup.assert_called_once_with("MAL-2024-1234", state)
    assert json.loads(out)["sources_consulted"] == ["osv"]


def test_run_lookup_with_web_appends_web_source(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    with patch("scripts.lookup_command._lookup_cve", return_value={"kev": False}):
        with patch("scripts.lookup_command.web_search",
                   return_value={"abstract": "x", "related_topics": []}) as web:
            out = run_lookup(
                "CVE-2019-10744", no_web=False, timeout=3, state_dir=state,
                output_format="json",
            )
    web.assert_called_once()
    assert "web" in json.loads(out)["sources_consulted"]


def test_lookup_cve_tolerates_timeouts(tmp_path):
    state = tmp_path / "state"
    state.mkdir()

    class SlowFuture:
        def result(self, timeout=None):
            raise concurrent.futures.TimeoutError()

    with patch("scripts.lookup_command.KEVClient") as K:
        with patch("scripts.lookup_command.EPSSClient") as E:
            with patch("scripts.lookup_command.GHSAHTTPClient") as G:
                with patch("scripts.lookup_command.concurrent.futures.ThreadPoolExecutor") as Ex:
                    kev, epss, ghsa = MagicMock(), MagicMock(), MagicMock()
                    K.return_value, E.return_value, G.return_value = kev, epss, ghsa
                    pool = MagicMock()
                    pool.__enter__.return_value = pool
                    pool.__exit__.return_value = False
                    pool.submit.side_effect = [
                        SlowFuture(), SlowFuture(), SlowFuture(),
                    ]
                    Ex.return_value = pool
                    result = _lookup_cve("CVE-2019-10744", state)

    assert result == {"kev": None, "epss": None, "ghsa": None}


def test_lookup_ghsa_enriches_cve_side_channels(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    with patch("scripts.lookup_command.GHSAHTTPClient") as G:
        with patch("scripts.lookup_command.KEVClient") as K:
            with patch("scripts.lookup_command.EPSSClient") as E:
                ghsa = MagicMock()
                ghsa.fetch.return_value = {
                    "ghsa_id": "GHSA-jf85-cpcp-j695",
                    "cve_id": "CVE-2019-10744",
                }
                G.return_value = ghsa
                kev = MagicMock()
                kev.is_known_exploited.return_value = True
                K.return_value = kev
                epss = MagicMock()
                epss.lookup.return_value = {"score": 0.9}
                E.return_value = epss
                result = _lookup_ghsa("GHSA-jf85-cpcp-j695", state)

    assert result["ghsa"]["cve_id"] == "CVE-2019-10744"
    assert result["kev"] is True
    assert result["epss"]["score"] == 0.9


def test_lookup_mal_uses_osv_client(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    with patch("scripts.lookup_command.OSVClient") as O:
        osv = MagicMock()
        osv.get_vuln.return_value = {"id": "MAL-2024-1234"}
        O.return_value = osv
        result = _lookup_mal("MAL-2024-1234", state)
    assert result == {"osv": {"id": "MAL-2024-1234"}}
    O.assert_called_once()
    # cache dir should nest under state/cache/osv
    assert O.call_args.kwargs["cache_dir"] == state / "cache" / "osv"
