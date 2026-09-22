"""Tests for the get_processor_provenance MCP tool wiring (server layer)."""

from __future__ import annotations

import asyncio

from nifi_mcp_server.server import create_server


class _RecordingClient:
    """Stands in for NiFiClient; records provenance kwargs, returns an empty result."""

    def __init__(self):
        self.calls = []

    def query_provenance_by_processor(self, processor_id, **kwargs):
        self.calls.append((processor_id, kwargs))
        return {"provenanceEvents": [], "total": "0", "totalCount": 0}

    def query_provenance_by_flowfile(self, flowfile_uuid, **kwargs):
        self.calls.append((flowfile_uuid, kwargs))
        return {"provenanceEvents": [], "total": "0", "totalCount": 0}


def _call(app, name, arguments):
    return asyncio.run(app.call_tool(name, arguments))


def test_get_processor_provenance_forwards_date_window():
    nifi = _RecordingClient()
    app = create_server(nifi, readonly=True)

    _call(
        app,
        "get_processor_provenance",
        {"processor_id": "d93ce923", "start_date": "2026-09-20", "end_date": "2026-09-21T00:00:00Z"},
    )

    assert nifi.calls == [
        ("d93ce923", {"max_results": 5, "search_terms": None, "start_date": "2026-09-20", "end_date": "2026-09-21T00:00:00Z"})
    ]


def test_get_processor_provenance_defaults_have_no_window():
    nifi = _RecordingClient()
    app = create_server(nifi, readonly=True)

    _call(app, "get_processor_provenance", {"processor_id": "d93ce923"})

    (_, kwargs), = nifi.calls
    assert kwargs["start_date"] is None
    assert kwargs["end_date"] is None


def test_get_flowfile_provenance_forwards_date_window():
    nifi = _RecordingClient()
    app = create_server(nifi, readonly=True)

    _call(
        app,
        "get_flowfile_provenance",
        {"flowfile_uuid": "ff-1", "start_date": "2026-09-20", "end_date": "2026-09-21T00:00:00Z"},
    )

    assert nifi.calls == [
        ("ff-1", {"max_results": 10, "start_date": "2026-09-20", "end_date": "2026-09-21T00:00:00Z"})
    ]


def test_get_flowfile_provenance_defaults_have_no_window():
    nifi = _RecordingClient()
    app = create_server(nifi, readonly=True)

    _call(app, "get_flowfile_provenance", {"flowfile_uuid": "ff-1"})

    (_, kwargs), = nifi.calls
    assert kwargs["start_date"] is None
    assert kwargs["end_date"] is None
