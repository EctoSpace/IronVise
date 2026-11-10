import httpx
import pytest
import respx
from ironvise_sdk.client import LedgerClient

class Chunks(httpx.AsyncByteStream):
    def __init__(self, body: str):
        self.body = body
    async def __aiter__(self):
        for byte in self.body.encode("utf-8"):
            yield bytes([byte])

@pytest.mark.asyncio
@pytest.mark.parametrize("nl", ["\n", "\r\n", "\r"])
@pytest.mark.parametrize("bom", ["", "\ufeff"])
@respx.mock
async def test_stream_line_endings_chunk_boundaries_and_multiline_data(nl, bom):
    body = bom + f'event: delta{nl}data: {{"text":{nl}data: "hé👋"}}{nl}{nl}: keepalive{nl}{nl}event: done{nl}data: {{"reply":"hé👋"}}{nl}{nl}'
    respx.post("http://ledger.test/api/chat/stream").mock(return_value=httpx.Response(200, stream=Chunks(body)))
    async with LedgerClient("http://ledger.test") as client:
        events = [event async for event in client.ask_stream("hi")]
    assert events == [{"type":"delta", "text":"hé👋"}, {"type":"done", "reply":"hé👋"}]

@pytest.mark.asyncio
@respx.mock
async def test_multiline_data_is_not_silently_joined_into_a_different_number():
    respx.get("http://ledger.test/api/stream").mock(return_value=httpx.Response(200, text='data: {"n":1\ndata: 2}\n\ndata: {"n":3}\n\n'))
    async with LedgerClient("http://ledger.test") as client:
        events = [event async for event in client.stream_events()]
    assert events == [{"n":3}]


@pytest.mark.asyncio
@pytest.mark.parametrize("session", [None, "session-id"])
@respx.mock
async def test_closing_chat_generator_immediately_closes_its_http_stream(session):
    class OpenStream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            yield b'event: delta\ndata: {"text":"hello"}\n\n'

        async def aclose(self):
            self.closed = True

    stream = OpenStream()
    path = "/api/chat/stream" if session is None else f"/api/sessions/{session}/chat/stream"
    respx.post("http://ledger.test" + path).mock(return_value=httpx.Response(200, stream=stream))
    async with LedgerClient("http://ledger.test") as client:
        events = client.ask_stream("hi") if session is None else client.chat_stream(session, "hi")
        assert await anext(events) == {"type": "delta", "text": "hello"}
        await events.aclose()
        assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("separator", ["\v", "\f", "\x85", "\u2028", "\u2029"])
@respx.mock
async def test_unicode_separators_inside_json_do_not_split_sse_lines(separator):
    import json

    text = f"before{separator}after"
    frame = "data: " + json.dumps({"text": text}, ensure_ascii=False) + "\n\n"
    respx.get("http://ledger.test/api/stream").mock(
        return_value=httpx.Response(200, stream=Chunks(frame))
    )
    async with LedgerClient("http://ledger.test") as client:
        events = [event async for event in client.stream_events()]
    assert events == [{"text": text}]
