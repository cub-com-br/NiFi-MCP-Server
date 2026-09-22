"""Tests for processor-scoped provenance: extra searchTerms, search-options, attribute projection."""

from __future__ import annotations

import requests

import pytest

from nifi_mcp_server.client import NiFiClient, to_nifi_provenance_date
from nifi_mcp_server.server import _project_event_attributes


PROCESSOR_ID = "88e026cc-d71a-32fc-dc98-065d01fe622d"
QUERY_ID = "q-proc-1"


def _client(httpserver) -> NiFiClient:
    return NiFiClient(base_url=httpserver.url_for(""), session=requests.Session(), timeout_seconds=5)


def _finished(events):
    return {
        "provenance": {
            "id": QUERY_ID,
            "finished": True,
            "results": {"provenanceEvents": events, "total": str(len(events)), "totalCount": len(events)},
        }
    }


def _register_query(httpserver, events):
    httpserver.expect_ordered_request("/provenance", method="POST").respond_with_json(
        {"provenance": {"id": QUERY_ID, "finished": False}}
    )
    httpserver.expect_ordered_request(f"/provenance/{QUERY_ID}", method="GET").respond_with_json(_finished(events))
    httpserver.expect_ordered_request(f"/provenance/{QUERY_ID}", method="DELETE").respond_with_json({})


def test_query_provenance_by_processor_default_search_terms(httpserver):
    _register_query(httpserver, [{"eventId": 1, "componentId": PROCESSOR_ID}])

    client = _client(httpserver)
    results = client.query_provenance_by_processor(PROCESSOR_ID, max_results=5, poll_interval_s=0.01)

    assert results["totalCount"] == 1
    httpserver.check_assertions()

    post_req = next(log[0] for log in httpserver.log if log[0].method == "POST")
    body = post_req.get_json()
    assert body["provenance"]["request"]["searchTerms"] == {"ProcessorID": {"value": PROCESSOR_ID}}
    assert body["provenance"]["request"]["maxResults"] == 5
    assert "startDate" not in body["provenance"]["request"]
    assert "endDate" not in body["provenance"]["request"]


def test_query_provenance_by_processor_merges_search_terms(httpserver):
    _register_query(httpserver, [])

    client = _client(httpserver)
    client.query_provenance_by_processor(
        PROCESSOR_ID, search_terms={"apiClientId": "prolotes", "apiEnterpriseId": 4}, poll_interval_s=0.01
    )

    post_req = next(log[0] for log in httpserver.log if log[0].method == "POST")
    body = post_req.get_json()
    assert body["provenance"]["request"]["searchTerms"] == {
        "ProcessorID": {"value": PROCESSOR_ID},
        "apiClientId": {"value": "prolotes"},
        "apiEnterpriseId": {"value": "4"},  # non-str values are stringified
    }


def test_query_provenance_search_options(httpserver):
    payload = {"provenanceOptions": {"searchableFields": [{"id": "apiClientId", "field": "apiClientId"}]}}
    httpserver.expect_request("/provenance/search-options", method="GET").respond_with_json(payload)

    client = _client(httpserver)
    assert client.query_provenance_search_options() == payload
    httpserver.check_assertions()


def test_project_event_attributes_whitelist():
    data = {
        "provenanceEvents": [
            {
                "eventId": 1,
                "attributes": [
                    {"name": "apiClientId", "value": "prolotes"},
                    {"name": "erpIntegrationSettings", "value": "<huge json>"},
                ],
            }
        ]
    }
    out = _project_event_attributes(data, ["apiClientId"])
    assert out["provenanceEvents"][0]["attributes"] == [{"name": "apiClientId", "value": "prolotes"}]


def test_project_event_attributes_none_is_noop():
    data = {"provenanceEvents": [{"attributes": [{"name": "x", "value": "y"}]}]}
    assert _project_event_attributes(data, None) == data


def test_query_provenance_by_processor_passes_date_window(httpserver):
    _register_query(httpserver, [])

    client = _client(httpserver)
    client.query_provenance_by_processor(
        PROCESSOR_ID,
        start_date="2026-09-20T00:00:00Z",
        end_date="2026-09-21",
        poll_interval_s=0.01,
    )

    post_req = next(log[0] for log in httpserver.log if log[0].method == "POST")
    request = post_req.get_json()["provenance"]["request"]
    assert request["startDate"] == "09/20/2026 00:00:00 UTC"
    assert request["endDate"] == "09/21/2026 00:00:00 UTC"


def test_query_provenance_by_processor_only_start_date(httpserver):
    _register_query(httpserver, [])

    client = _client(httpserver)
    client.query_provenance_by_processor(PROCESSOR_ID, start_date="2026-09-20", poll_interval_s=0.01)

    post_req = next(log[0] for log in httpserver.log if log[0].method == "POST")
    request = post_req.get_json()["provenance"]["request"]
    assert request["startDate"] == "09/20/2026 00:00:00 UTC"
    assert "endDate" not in request


@pytest.mark.parametrize(
    "iso, expected",
    [
        ("2026-09-20T00:00:00Z", "09/20/2026 00:00:00 UTC"),
        ("2026-09-20T03:00:00-03:00", "09/20/2026 06:00:00 UTC"),  # offset → UTC
        ("2026-09-20T23:30:00+02:00", "09/20/2026 21:30:00 UTC"),
        ("2026-09-20", "09/20/2026 00:00:00 UTC"),  # bare date = midnight UTC
        ("2026-09-20T12:30:00", "09/20/2026 12:30:00 UTC"),  # naive = UTC
        ("2026-09-20T12:30:45.123456Z", "09/20/2026 12:30:45 UTC"),  # sub-second dropped
    ],
)
def test_to_nifi_provenance_date(iso, expected):
    assert to_nifi_provenance_date(iso) == expected


@pytest.mark.parametrize("bad", ["20/09/2026", "09/20/2026 00:00:00 UTC", "yesterday", ""])
def test_to_nifi_provenance_date_rejects_non_iso(bad):
    with pytest.raises(ValueError, match="ISO 8601"):
        to_nifi_provenance_date(bad)
