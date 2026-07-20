"""Tests for processor-scoped provenance: extra searchTerms, search-options, attribute projection."""

from __future__ import annotations

import requests

from nifi_mcp_server.client import NiFiClient
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
