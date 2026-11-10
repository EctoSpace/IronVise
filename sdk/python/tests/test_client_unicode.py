"""Non-ASCII and URL-sensitive input through every ``LedgerClient`` method.

An identifier must reach the server as exactly one path segment, whatever it
contains: a ``/`` that is not encoded selects a different route, a ``?`` or
``#`` cuts the path short, and a ``%`` that is not encoded makes the server
decode something the caller never sent. Text in request and response bodies
must survive the JSON round trip byte for byte.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from _endpoints import BY_NAME, ENDPOINTS, Endpoint
from ironvise_sdk.client import LedgerClient, LedgerSdkError

pytestmark = pytest.mark.asyncio

BASE = "http://ledger.test"

#: identifier -> its single-segment percent-encoding, written out by hand so
#: the test does not share an encoder with the code under test.
IDENTIFIERS = {
    "a b/c?d#e%f": "a%20b%2Fc%3Fd%23e%25f",
    "100%": "100%25",
    "%2F": "%252F",
    "ünïcødé-会话": "%C3%BCn%C3%AFc%C3%B8d%C3%A9-%E4%BC%9A%E8%AF%9D",
    "🦀-🔒": "%F0%9F%A6%80-%F0%9F%94%92",
    "שלום-مرحبا": "%D7%A9%D7%9C%D7%95%D7%9D-%D9%85%D8%B1%D8%AD%D8%A8%D8%A7",
    "‮gnp.exe": "%E2%80%AEgnp.exe",
    "x+y=z&k": "x%2By%3Dz%26k",
}

#: Strings for JSON bodies: RTL, an override character, emoji (outside the
#: BMP), combining marks, NUL, quotes and backslashes, and URL metacharacters.
TEXTS = [
    "naïve café - 会话",
    "🦀🔒 audit 👩‍💻",
    "שלום עולם / مرحبا بالعالم",
    "‮exe.gnp",
    "é vs é",
    'quote " backslash \\ nul \x00 newline \n',
    "a b/c?d#e%f&g=h",
]

PATH_ENDPOINTS = [e for e in ENDPOINTS if "{}" in e.template]


def _ok(body: object = None) -> httpx.Response:
    return httpx.Response(200, json=body if body is not None else {})


async def _send(ep: Endpoint, ident: str) -> httpx.Request:
    """Call *ep* against a catch-all mock and return the request it made."""
    route = respx.route().mock(return_value=httpx.Response(500, text="stop"))
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError):
            await ep.call(client, ident)
    return route.calls.last.request


@respx.mock
@pytest.mark.parametrize(("ident", "encoded"), IDENTIFIERS.items(), ids=list(IDENTIFIERS.values()))
@pytest.mark.parametrize("ep", PATH_ENDPOINTS, ids=[e.name for e in PATH_ENDPOINTS])
async def test_identifier_is_sent_as_one_percent_encoded_segment(ep: Endpoint, ident: str, encoded: str) -> None:
    request = await _send(ep, ident)
    assert request.url.raw_path == ep.template.format(encoded).encode("ascii")
    assert request.url.path == ep.template.format(ident)
    assert request.url.query == b""


@respx.mock
@pytest.mark.parametrize("ident", ["", ".", ".."])
@pytest.mark.parametrize("ep", PATH_ENDPOINTS, ids=[e.name for e in PATH_ENDPOINTS])
async def test_a_dot_segment_identifier_stays_inside_its_segment(ep: Endpoint, ident: str) -> None:
    """``delete_policy("..")`` must not become ``DELETE /api``: it is refused unsent."""
    route = respx.route().mock(return_value=httpx.Response(500, text="stop"))
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError) as excinfo:
            await ep.call(client, ident)
    assert str(excinfo.value).startswith(f"{ep.op}: ")
    assert f"must not be {ident!r}" in str(excinfo.value)
    assert ep.param in str(excinfo.value)
    assert excinfo.value.status_code is None
    assert not route.called


@respx.mock
@pytest.mark.parametrize(
    ("ident", "encoded"),
    [("a.b", "a.b"), ("...", "..."), (".hidden", ".hidden"), ("..x", "..x"), ("x..", "x.."), ("./..", ".%2F..")],
)
@pytest.mark.parametrize("ep", PATH_ENDPOINTS, ids=[e.name for e in PATH_ENDPOINTS])
async def test_an_identifier_containing_dots_is_one_segment(ep: Endpoint, ident: str, encoded: str) -> None:
    request = await _send(ep, ident)
    assert request.url.raw_path == ep.template.format(encoded).encode("ascii")
    assert request.url.path == ep.template.format(ident)


@respx.mock
@pytest.mark.parametrize("ident", [*IDENTIFIERS, "a&session_id=other"])
async def test_get_events_sends_the_session_id_as_one_query_value(ident: str) -> None:
    request = await _send(BY_NAME["get_events"], ident)
    assert request.url.path == "/api/events"
    assert request.url.params.get_list("session_id") == [ident]
    assert list(request.url.params.keys()) == ["session_id"]


@respx.mock
@pytest.mark.parametrize("audience", ["https://verifier.example/a b?c#d", "did:web:例え.jp"])
async def test_verify_session_vc_audience_round_trips(audience: str) -> None:
    route = respx.route().mock(return_value=_ok({"valid": True}))
    async with LedgerClient(BASE) as client:
        await client.verify_session_vc("s", audience=audience)
    assert route.calls.last.request.url.params.get_list("audience") == [audience]


@respx.mock
@pytest.mark.parametrize("text", TEXTS)
async def test_request_bodies_round_trip_through_json(text: str, sample_session: dict) -> None:
    route = respx.route().mock(return_value=_ok(sample_session))
    sent: list[dict] = []
    async with LedgerClient(BASE) as client:
        await client.create_session(text, record=True)
        sent.append({"goal": text, "record": True})

        route.mock(return_value=_ok({"id": 1, "payload_hash": "a" * 64, "sequence": 1}))
        payload = {"observation": text, "path": f"/tmp/{text}", "nested": [{text: text}]}
        await client.append_event("s", payload)
        sent.append(payload)

        route.mock(return_value=_ok({"decision": "allow"}))
        await client.verify_intent("s", "read_file", {"path": text}, justification=text, reasoning=text)
        sent.append(
            {"action": "read_file", "params": {"path": text}, "justification": text, "reasoning": text}
        )

        route.mock(return_value=_ok({"reply": text}))
        assert await client.chat("s", text) == {"reply": text}
        sent.append({"message": text})

    bodies = [json.loads(call.request.content.decode("utf-8")) for call in route.calls]
    assert bodies == sent
    for call in route.calls:
        assert call.request.headers["content-type"] == "application/json"


@respx.mock
@pytest.mark.parametrize("text", TEXTS)
async def test_save_policy_sends_utf8_text(text: str) -> None:
    route = respx.route().mock(return_value=httpx.Response(204))
    async with LedgerClient(BASE) as client:
        await client.save_policy("p", f'name = "{text}"\n')
    request = route.calls.last.request
    assert request.content == f'name = "{text}"\n'.encode("utf-8")
    assert request.headers["content-type"] == "text/plain; charset=utf-8"


@respx.mock
@pytest.mark.parametrize("text", TEXTS)
async def test_response_text_round_trips(text: str) -> None:
    respx.get(f"{BASE}/api/reports/s").mock(return_value=_ok({"summary": text, text: [text]}))
    respx.get(f"{BASE}/api/policies/p").mock(
        return_value=httpx.Response(
            200, content=text.encode("utf-8"), headers={"content-type": "text/plain; charset=utf-8"}
        )
    )
    respx.get(f"{BASE}/api/certificates/s").mock(return_value=httpx.Response(200, content=text.encode("utf-8")))
    async with LedgerClient(BASE) as client:
        assert await client.get_report("s") == {"summary": text, text: [text]}
        assert await client.get_policy("p") == text
        assert await client.export_certificate("s") == text.encode("utf-8")


@respx.mock
async def test_error_message_keeps_a_non_ascii_server_message() -> None:
    message = "Sitzung „🦀“ ist versiegelt - שלום"
    respx.route().mock(return_value=httpx.Response(409, json={"error": message}))
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError) as excinfo:
            await client.append_event("s", {"observation": "x"})
    assert str(excinfo.value) == f"append_event: HTTP 409: {message}"


@respx.mock
async def test_stream_events_reassembles_characters_and_events_split_across_chunks() -> None:
    wire = 'data: {"observation": "🦀 שלום"}\n\ndata: {"observation": "naïve"}\n\n'.encode("utf-8")
    crab = wire.index("🦀".encode("utf-8"))
    boundary = wire.index(b"\n\n")
    # Split inside the four-byte crab, and between the two newlines that end an event.
    cuts = [0, crab + 2, boundary + 1, len(wire)]

    async def chunks():
        for start, end in zip(cuts, cuts[1:]):
            yield wire[start:end]

    respx.route().mock(
        return_value=httpx.Response(200, content=chunks(), headers={"content-type": "text/event-stream"})
    )
    async with LedgerClient(BASE) as client:
        events = await BY_NAME["stream_events"].call(client, "s")
    assert events == [{"observation": "🦀 שלום"}, {"observation": "naïve"}]
