"""Tests for FlowFile-UUID provenance + lineage client methods."""

from __future__ import annotations

import pytest
import requests

from nifi_mcp_server.client import NiFiClient, NiFiError


FLOWFILE_UUID = "fb08963b-493c-4771-b5a2-bcd6b4135234"
QUERY_ID = "q-1234"


def _client(httpserver) -> NiFiClient:
    return NiFiClient(base_url=httpserver.url_for(""), session=requests.Session(), timeout_seconds=5)


def test_query_provenance_by_flowfile_submits_polls_deletes(httpserver):
    submit_body = {"provenance": {"id": QUERY_ID, "finished": False}}
    poll_unfinished = {"provenance": {"id": QUERY_ID, "finished": False}}
    poll_finished = {
        "provenance": {
            "id": QUERY_ID,
            "finished": True,
            "results": {
                "provenanceEvents": [
                    {"eventId": 1, "eventType": "ROUTE", "flowFileUuid": FLOWFILE_UUID}
                ],
                "total": "1",
                "totalCount": 1,
            },
        }
    }

    httpserver.expect_ordered_request("/provenance", method="POST").respond_with_json(submit_body)
    httpserver.expect_ordered_request(f"/provenance/{QUERY_ID}", method="GET").respond_with_json(poll_unfinished)
    httpserver.expect_ordered_request(f"/provenance/{QUERY_ID}", method="GET").respond_with_json(poll_finished)
    httpserver.expect_ordered_request(f"/provenance/{QUERY_ID}", method="DELETE").respond_with_json({})

    client = _client(httpserver)
    results = client.query_provenance_by_flowfile(FLOWFILE_UUID, max_results=10, poll_interval_s=0.01)

    assert results == poll_finished["provenance"]["results"]
    httpserver.check_assertions()

    # Verify the POST body carried the FlowFileUUID searchTerm.
    post_req = next(log[0] for log in httpserver.log if log[0].method == "POST")
    body = post_req.get_json()
    assert body["provenance"]["request"]["searchTerms"] == {"FlowFileUUID": {"value": FLOWFILE_UUID}}
    assert body["provenance"]["request"]["maxResults"] == 10


def test_query_provenance_by_flowfile_timeout_still_deletes(httpserver):
    httpserver.expect_oneshot_request("/provenance", method="POST").respond_with_json(
        {"provenance": {"id": QUERY_ID, "finished": False}}
    )
    httpserver.expect_request(f"/provenance/{QUERY_ID}", method="GET").respond_with_json(
        {"provenance": {"id": QUERY_ID, "finished": False}}
    )
    httpserver.expect_oneshot_request(f"/provenance/{QUERY_ID}", method="DELETE").respond_with_json({})

    client = _client(httpserver)
    with pytest.raises(NiFiError, match="did not finish"):
        client.query_provenance_by_flowfile(
            FLOWFILE_UUID, max_results=5, poll_interval_s=0.01, poll_timeout_s=0.05
        )

    delete_methods = [log[0].method for log in httpserver.log if log[0].method == "DELETE"]
    assert delete_methods == ["DELETE"]


def test_query_lineage_by_flowfile_submits_polls_deletes(httpserver):
    submit_body = {"lineage": {"id": QUERY_ID, "finished": False}}
    poll_finished = {
        "lineage": {
            "id": QUERY_ID,
            "finished": True,
            "results": {
                "nodes": [{"id": "n1", "type": "FLOWFILE", "flowFileUuid": FLOWFILE_UUID}],
                "links": [],
            },
        }
    }

    httpserver.expect_oneshot_request("/provenance/lineage", method="POST").respond_with_json(submit_body)
    httpserver.expect_oneshot_request(f"/provenance/lineage/{QUERY_ID}", method="GET").respond_with_json(poll_finished)
    httpserver.expect_oneshot_request(f"/provenance/lineage/{QUERY_ID}", method="DELETE").respond_with_json({})

    client = _client(httpserver)
    results = client.query_lineage_by_flowfile(FLOWFILE_UUID, poll_interval_s=0.01)

    assert results == poll_finished["lineage"]["results"]
    httpserver.check_assertions()

    post_req = next(log[0] for log in httpserver.log if log[0].method == "POST")
    body = post_req.get_json()
    assert body["lineage"]["request"] == {
        "lineageRequestType": "FLOWFILE",
        "uuid": FLOWFILE_UUID,
    }
