"""Tests for version-control / local-modifications client methods + summary helper."""

from __future__ import annotations

import pytest
import requests

from nifi_mcp_server.client import NiFiClient, NiFiError
from nifi_mcp_server.server import _summarize_local_modifications


PG_ID = "abc-1234-pg"


def _client(httpserver) -> NiFiClient:
    return NiFiClient(
        base_url=httpserver.url_for(""),
        session=requests.Session(),
        timeout_seconds=5,
    )


# ---------- client: get_version_control_info ----------


def test_get_version_control_info_happy_path(httpserver):
    payload = {
        "versionControlInformation": {
            "groupId": PG_ID,
            "registryId": "reg-1",
            "bucketId": "bkt-1",
            "flowId": "flw-1",
            "version": 3,
            "state": "LOCALLY_MODIFIED",
            "stateExplanation": "Local changes have been made",
        }
    }
    httpserver.expect_oneshot_request(
        f"/versions/process-groups/{PG_ID}", method="GET"
    ).respond_with_json(payload)

    result = _client(httpserver).get_version_control_info(PG_ID)
    assert result == payload
    httpserver.check_assertions()


def test_get_version_control_info_404_raises_nifierror(httpserver):
    httpserver.expect_request(
        f"/versions/process-groups/{PG_ID}", method="GET"
    ).respond_with_data("Process group is not under version control", status=404)

    with pytest.raises(NiFiError) as exc:
        _client(httpserver).get_version_control_info(PG_ID)
    assert exc.value.status_code == 404


# ---------- client: get_local_modifications ----------


def test_get_local_modifications_happy_path(httpserver):
    payload = {
        "componentDifferences": [
            {
                "componentType": "PROCESSOR",
                "componentId": "p-1",
                "componentName": "GetFile",
                "processGroupId": PG_ID,
                "differences": [
                    {"differenceType": "PROPERTY_CHANGED", "difference": "Input Directory changed"},
                    {"differenceType": "POSITION_CHANGED", "difference": "Moved"},
                ],
            },
            {
                "componentType": "CONNECTION",
                "componentId": "c-1",
                "componentName": "success",
                "processGroupId": PG_ID,
                "differences": [
                    {"differenceType": "BACKPRESSURE_THRESHOLD_CHANGED", "difference": "10000 → 5000"},
                ],
            },
        ]
    }
    httpserver.expect_oneshot_request(
        f"/versions/process-groups/{PG_ID}/local-modifications", method="GET"
    ).respond_with_json(payload)

    result = _client(httpserver).get_local_modifications(PG_ID)
    assert result == payload
    httpserver.check_assertions()


# ---------- helper: _summarize_local_modifications ----------


def test_summarize_local_modifications_groups_and_counts():
    raw = {
        "componentDifferences": [
            {
                "componentType": "PROCESSOR",
                "componentId": "p-1",
                "componentName": "GetFile",
                "processGroupId": PG_ID,
                "differences": [
                    {"differenceType": "PROPERTY_CHANGED", "difference": "x"},
                    {"differenceType": "PROPERTY_CHANGED", "difference": "y"},
                    {"differenceType": "POSITION_CHANGED", "difference": "z"},
                ],
            },
            {
                "componentType": "PROCESSOR",
                "componentId": "p-2",
                "componentName": "PutFile",
                "processGroupId": PG_ID,
                "differences": [
                    {"differenceType": "PROPERTY_CHANGED", "difference": "q"},
                ],
            },
            {
                "componentType": "CONNECTION",
                "componentId": "c-1",
                "componentName": "success",
                "processGroupId": PG_ID,
                "differences": [
                    {"differenceType": "BACKPRESSURE_THRESHOLD_CHANGED", "difference": "x"},
                ],
            },
        ]
    }

    summary = _summarize_local_modifications(raw)

    assert summary["componentCount"] == 3
    assert summary["totalDifferences"] == 5
    assert summary["differenceTypeHistogram"] == {
        "PROPERTY_CHANGED": 3,
        "POSITION_CHANGED": 1,
        "BACKPRESSURE_THRESHOLD_CHANGED": 1,
    }
    assert summary["byComponentType"]["PROCESSOR"]["count"] == 2
    assert summary["byComponentType"]["CONNECTION"]["count"] == 1

    processors = summary["byComponentType"]["PROCESSOR"]["components"]
    assert {c["id"] for c in processors} == {"p-1", "p-2"}
    p1 = next(c for c in processors if c["id"] == "p-1")
    assert p1["name"] == "GetFile"
    assert p1["change_count"] == 3
    # raw difference strings should NOT appear in summary
    assert "differences" not in p1


def test_summarize_local_modifications_empty():
    summary = _summarize_local_modifications({"componentDifferences": []})
    assert summary == {
        "componentCount": 0,
        "totalDifferences": 0,
        "differenceTypeHistogram": {},
        "byComponentType": {},
    }


def test_summarize_local_modifications_missing_key():
    # NiFi may omit the key entirely when nothing changed.
    summary = _summarize_local_modifications({})
    assert summary["componentCount"] == 0
    assert summary["totalDifferences"] == 0
