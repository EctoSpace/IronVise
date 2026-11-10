"""Webhook verifier tests.

The cases come from ``sdk/fixtures/webhook-v1.json``, which the Rust server's
own test generates and pins. The TypeScript SDK reads the same file, so the
server and both verifiers agree on the scheme by construction rather than by
three people reading the same paragraph. Nothing here needs a network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from ironvise_sdk import (
    MemoryReplayCache,
    ReplayCache,
    WebhookVerdict,
    derive_receiver_key,
    verify_webhook,
)

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "webhook-v1.json"
FIXTURE: dict[str, Any] = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
CASES: list[dict[str, Any]] = FIXTURE["cases"]
TOLERANCE: int = FIXTURE["tolerance_secs"]

DELIVERY = "X-EctoLedger-Delivery"
TIMESTAMP = "X-EctoLedger-Timestamp"
SIGNATURE = "X-EctoLedger-Signature-V1"


def case_named(name: str) -> dict[str, Any]:
    return next(c for c in CASES if c["name"] == name)


def cache_at(now: float) -> MemoryReplayCache:
    """A cache whose clock is pinned, so a fixed fixture timestamp never ages out."""
    return MemoryReplayCache(lambda: now)


def run(case: dict[str, Any], cache: ReplayCache, **overrides: Any) -> WebhookVerdict:
    args: dict[str, Any] = {
        "receiver_key": case["receiver_key"],
        "receiver_url": case["receiver_url"],
        "headers": case["headers"],
        "body": case["body"],
        "now": case["now"],
        "tolerance_secs": TOLERANCE,
        "cache": cache,
    }
    args.update(overrides)
    return verify_webhook(**args)


def outcome(verdict: WebhookVerdict) -> str:
    """The reason a verdict was refused, or ``"ok"``."""
    return "ok" if verdict.ok else str(verdict.reason)


VALID = case_named("valid")


class TestFixture:
    def test_is_the_v1_scheme_and_has_cases_to_run(self) -> None:
        assert FIXTURE["scheme"] == "ectoledger-webhook-v1"
        assert len(CASES) >= 6
        assert TOLERANCE == 300

    @pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
    def test_case(self, case: dict[str, Any]) -> None:
        verdict = run(case, cache_at(case["now"]))
        assert outcome(verdict) == case["expect"]
        if verdict.ok:
            assert verdict.delivery_id == case["headers"][DELIVERY]
            assert verdict.reason is None
        else:
            assert verdict.delivery_id is None

    def test_derives_every_receiver_key_the_server_derived(self) -> None:
        for case in CASES:
            assert derive_receiver_key(FIXTURE["secret"], case["receiver_url"]) == case["receiver_key"]
        # ...and the same bytes give the same key.
        assert (
            derive_receiver_key(FIXTURE["secret"].encode(), VALID["receiver_url"])
            == VALID["receiver_key"]
        )

    def test_two_receivers_get_two_keys(self) -> None:
        other = case_named("presented to another receiver")
        assert VALID["receiver_key"] != other["receiver_key"]

    def test_second_presentation_is_refused(self) -> None:
        case = case_named(FIXTURE["replay"]["case"])
        cache = cache_at(case["now"])
        seen = [outcome(run(case, cache)) for _ in range(FIXTURE["replay"]["presentations"])]
        assert seen == FIXTURE["replay"]["expect"]
        assert seen == ["ok", "replayed"]


class TestVerifyWebhook:
    def test_forged_delivery_does_not_block_the_genuine_one(self) -> None:
        cache = cache_at(VALID["now"])
        # Same delivery id as the genuine delivery, signature made up.
        forged = {**VALID["headers"], SIGNATURE: "00" * 32}
        first = run(VALID, cache, headers=forged)
        assert first == WebhookVerdict(ok=False, reason="bad_signature")
        assert len(cache) == 0
        assert outcome(run(VALID, cache)) == "ok"

    def test_stale_delivery_does_not_spend_the_id_either(self) -> None:
        cache = cache_at(VALID["now"])
        assert outcome(run(VALID, cache, now=VALID["now"] + 10_000)) == "stale"
        assert len(cache) == 0
        assert outcome(run(VALID, cache)) == "ok"

    @pytest.mark.parametrize("transform", [str.lower, str.upper], ids=["lower", "upper"])
    def test_finds_headers_whatever_case_the_framework_gave_them(self, transform: Any) -> None:
        headers = {transform(k): v for k, v in VALID["headers"].items()}
        verdict = run(VALID, cache_at(VALID["now"]), headers=headers)
        assert verdict == WebhookVerdict(ok=True, delivery_id=VALID["headers"][DELIVERY])

    def test_accepts_any_mapping(self) -> None:
        from types import MappingProxyType

        headers = MappingProxyType({k.lower(): v for k, v in VALID["headers"].items()})
        assert run(VALID, cache_at(VALID["now"]), headers=headers).ok

    @pytest.mark.parametrize("missing", [DELIVERY, TIMESTAMP, SIGNATURE])
    def test_missing_header(self, missing: str) -> None:
        headers = {k: v for k, v in VALID["headers"].items() if k != missing}
        verdict = run(VALID, cache_at(VALID["now"]), headers=headers)
        assert verdict == WebhookVerdict(ok=False, reason="missing_headers")

    def test_empty_header_value_counts_as_missing(self) -> None:
        for name in (DELIVERY, SIGNATURE):
            headers = {**VALID["headers"], name: ""}
            assert outcome(run(VALID, cache_at(VALID["now"]), headers=headers)) == "missing_headers"

    @pytest.mark.parametrize(
        "timestamp",
        [
            "",
            "abc",
            "1.5",
            "1e9",
            "0x10",
            "1_000",
            " 1790700000",
            "1790700000 ",
            "1790700000\n",
            "١٢٣",  # Arabic-Indic digits: int() would take them
            "1" * 5000,  # int() past its digit limit raises; this must not
        ],
    )
    def test_timestamp_that_is_not_an_integer_is_missing_headers(self, timestamp: str) -> None:
        headers = {**VALID["headers"], TIMESTAMP: timestamp}
        verdict = run(VALID, cache_at(VALID["now"]), headers=headers)
        assert verdict == WebhookVerdict(ok=False, reason="missing_headers")

    def test_non_string_header_value_counts_as_missing(self) -> None:
        headers: dict[str, Any] = {**VALID["headers"], DELIVERY: ["a", "b"]}
        assert outcome(run(VALID, cache_at(VALID["now"]), headers=headers)) == "missing_headers"

    def test_checks_the_timestamp_before_the_signature(self) -> None:
        # A tampered body *and* an old timestamp: the cheap check answers first.
        verdict = run(VALID, cache_at(0), body="{}", now=VALID["now"] + 10_000)
        assert outcome(verdict) == "stale"

    def test_accepts_exactly_the_tolerance_and_refuses_one_second_more(self) -> None:
        sent_at = int(VALID["headers"][TIMESTAMP])
        for now in (sent_at + TOLERANCE, sent_at - TOLERANCE):
            assert outcome(run(VALID, cache_at(now), now=now)) == "ok"
        assert outcome(run(VALID, cache_at(sent_at), now=sent_at + TOLERANCE + 1)) == "stale"
        assert outcome(run(VALID, cache_at(sent_at), now=sent_at - TOLERANCE - 1)) == "stale"

    def test_honours_a_custom_tolerance(self) -> None:
        # `now` is ten seconds after the delivery was signed.
        assert outcome(run(VALID, cache_at(VALID["now"]), tolerance_secs=5)) == "stale"
        assert outcome(run(VALID, cache_at(VALID["now"]), tolerance_secs=10)) == "ok"

    def test_compares_the_signature_exactly_case_and_length_matter(self) -> None:
        sig = VALID["headers"][SIGNATURE]
        for bad in (sig.upper(), sig[:-2], sig + "00", "0" + sig[1:], "é" * 64):
            headers = {**VALID["headers"], SIGNATURE: bad}
            verdict = run(VALID, cache_at(VALID["now"]), headers=headers)
            assert verdict == WebhookVerdict(ok=False, reason="bad_signature"), bad

    @pytest.mark.parametrize(
        "change",
        [
            {DELIVERY: "3f2b8c1e-5d4a-4c3b-9e8f-7a6b5c4d3e30"},
            {TIMESTAMP: "1790700001"},
        ],
        ids=["id", "timestamp"],
    )
    def test_signature_is_bound_to_the_id_and_the_timestamp(self, change: dict[str, str]) -> None:
        headers = {**VALID["headers"], **change}
        verdict = run(VALID, cache_at(VALID["now"]), headers=headers)
        assert verdict == WebhookVerdict(ok=False, reason="bad_signature")

    def test_body_may_be_bytes_and_matches_the_str_form(self) -> None:
        body = VALID["body"].encode("utf-8")
        assert run(VALID, cache_at(VALID["now"]), body=body).ok
        assert outcome(run(VALID, cache_at(VALID["now"]), body=body + b" ")) == "bad_signature"

    def test_non_ascii_body_and_url_round_trip(self) -> None:
        url = "https://siem.example/ectoledger/café"
        key = derive_receiver_key(FIXTURE["secret"], url)
        body = '{"note":"naïve ☃"}'
        headers = _sign(key, url, "unicode-delivery", str(int(VALID["now"])), body.encode("utf-8"))
        verdict = verify_webhook(
            receiver_key=key,
            receiver_url=url,
            headers=headers,
            body=body,
            now=VALID["now"],
            cache=cache_at(VALID["now"]),
        )
        assert verdict == WebhookVerdict(ok=True, delivery_id="unicode-delivery")

    def test_remembers_an_accepted_id_until_timestamp_plus_tolerance(self) -> None:
        added: list[tuple[str, float]] = []

        class Spy:
            def has(self, delivery_id: str, /) -> bool:
                return False

            def add(self, delivery_id: str, expires_at: float, /) -> None:
                added.append((delivery_id, expires_at))

        assert outcome(run(VALID, Spy())) == "ok"
        assert added == [(VALID["headers"][DELIVERY], 1790700000 + TOLERANCE)]

    def test_uses_the_system_clock_when_now_is_not_given(self) -> None:
        # Signed here, independently of the module under test, following the spec.
        url = "https://siem.example/ectoledger"
        key = derive_receiver_key(FIXTURE["secret"], url)
        body = '{"live":true}'
        headers = _sign(key, url, "clock-test-delivery", str(int(time.time())), body.encode())
        cache = MemoryReplayCache()

        def verify() -> WebhookVerdict:
            return verify_webhook(
                receiver_key=key, receiver_url=url, headers=headers, body=body, cache=cache
            )

        assert verify() == WebhookVerdict(ok=True, delivery_id="clock-test-delivery")
        assert verify() == WebhookVerdict(ok=False, reason="replayed")

    @pytest.mark.parametrize("key", ["", "abc", "zz" * 32, VALID["receiver_key"] + "00", "é" * 64])
    def test_a_receiver_key_that_is_not_64_hex_characters_raises(self, key: str) -> None:
        with pytest.raises(ValueError):
            run(VALID, cache_at(VALID["now"]), receiver_key=key)

    def test_arguments_are_keyword_only(self) -> None:
        with pytest.raises(TypeError):
            verify_webhook(VALID["receiver_key"], VALID["receiver_url"])  # type: ignore[call-arg]

    def test_verdict_is_frozen(self) -> None:
        verdict = WebhookVerdict(ok=True, delivery_id="x")
        with pytest.raises(AttributeError):
            verdict.ok = False  # type: ignore[misc]

    def test_concurrent_presentations_of_one_delivery_admit_exactly_one(self) -> None:
        cache = cache_at(VALID["now"])
        verdicts: list[str] = []
        barrier = threading.Barrier(16)

        def present() -> None:
            barrier.wait()
            verdicts.append(outcome(run(VALID, cache)))

        threads = [threading.Thread(target=present) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(verdicts) == ["ok"] + ["replayed"] * 15


class TestEdgeCases:
    """Headers, bodies and timestamps a real receiver will eventually be handed."""

    URL = "https://siem.example/ectoledger"
    NOW = 1_790_700_010

    def signed(self, body: bytes, *, delivery_id: str = "edge-delivery", timestamp: str = "1790700000") -> dict[str, str]:
        key = derive_receiver_key(FIXTURE["secret"], self.URL)
        return _sign(key, self.URL, delivery_id, timestamp, body)

    def verify(self, headers: Any, body: str | bytes, **overrides: Any) -> WebhookVerdict:
        args: dict[str, Any] = {
            "receiver_key": derive_receiver_key(FIXTURE["secret"], self.URL),
            "receiver_url": self.URL,
            "headers": headers,
            "body": body,
            "now": self.NOW,
            "cache": cache_at(self.NOW),
        }
        args.update(overrides)
        return verify_webhook(**args)

    @pytest.mark.parametrize(
        "renamed",
        ["X-EctoLedger-Signature", "X-EctoLedger-Signature-V2", "X-Ectoledger-Signature-V1 ", "Signature"],
    )
    def test_signature_under_another_header_name_is_missing(self, renamed: str) -> None:
        headers = {k: v for k, v in VALID["headers"].items() if k != SIGNATURE}
        headers[renamed] = VALID["headers"][SIGNATURE]
        assert outcome(run(VALID, cache_at(VALID["now"]), headers=headers)) == "missing_headers"

    def test_raw_byte_header_names_are_not_read(self) -> None:
        """ASGI hands headers over as bytes; the verifier wants a str mapping."""
        headers = {k.lower().encode(): v.encode() for k, v in VALID["headers"].items()}
        assert outcome(run(VALID, cache_at(VALID["now"]), headers=headers)) == "missing_headers"

    @pytest.mark.parametrize(
        "decorate",
        [lambda s: f" {s}", lambda s: f"{s}\n", lambda s: f"sha256={s}", lambda s: f"v1={s}"],
        ids=["leading-space", "trailing-newline", "sha256-prefix", "v1-prefix"],
    )
    def test_a_decorated_signature_is_refused(self, decorate: Any) -> None:
        headers = {**VALID["headers"], SIGNATURE: decorate(VALID["headers"][SIGNATURE])}
        assert outcome(run(VALID, cache_at(VALID["now"]), headers=headers)) == "bad_signature"

    @pytest.mark.parametrize(
        "tampered",
        [
            '{"event_kind":"tripwire_rejection","session_id":"s2"}',
            '{"session_id":"s1","event_kind":"tripwire_rejection"}',
            '{"event_kind": "tripwire_rejection", "session_id": "s1"}',
            '{"event_kind":"tripwire_rejection","session_id":"s1"}\n',
            "",
        ],
        ids=["value", "key-order", "whitespace", "trailing-newline", "empty"],
    )
    def test_a_body_that_parses_the_same_but_differs_in_bytes_is_refused(self, tampered: str) -> None:
        assert outcome(run(VALID, cache_at(VALID["now"]), body=tampered)) == "bad_signature"

    @pytest.mark.parametrize(
        "body",
        [
            '{"note":"🦀🔒 👩‍💻"}',
            '{"note":"שלום עולם / مرحبا"}',
            '{"note":"‮exe.gnp"}',
            '{"path":"/a b/c?d#e%f"}',
            '{"nul":"\u0000"}',
        ],
        ids=["emoji", "rtl", "rtl-override", "url-metacharacters", "nul"],
    )
    def test_unicode_body_verifies_as_str_bytes_bytearray_and_memoryview(self, body: str) -> None:
        raw = body.encode("utf-8")
        headers = self.signed(raw)
        for form in (body, raw, bytearray(raw), memoryview(raw)):
            assert self.verify(headers, form) == WebhookVerdict(ok=True, delivery_id="edge-delivery"), type(form)

    def test_unicode_normalisation_changes_the_bytes_and_so_the_signature(self) -> None:
        composed = '{"name":"café"}'
        decomposed = '{"name":"café"}'
        headers = self.signed(composed.encode("utf-8"))
        assert self.verify(headers, composed).ok
        assert self.verify(headers, decomposed) == WebhookVerdict(ok=False, reason="bad_signature")

    def test_a_body_decoded_with_the_wrong_charset_is_refused(self) -> None:
        raw = '{"note":"naïve 🦀"}'.encode("utf-8")
        headers = self.signed(raw)
        mojibake = raw.decode("latin-1")
        assert self.verify(headers, mojibake) == WebhookVerdict(ok=False, reason="bad_signature")

    def test_a_non_ascii_delivery_id_verifies_and_is_then_refused_as_a_replay(self) -> None:
        body = b'{"ok":true}'
        headers = self.signed(body, delivery_id="délivery-🦀-שלום")
        cache = cache_at(self.NOW)
        assert self.verify(headers, body, cache=cache) == WebhookVerdict(ok=True, delivery_id="délivery-🦀-שלום")
        assert self.verify(headers, body, cache=cache) == WebhookVerdict(ok=False, reason="replayed")

    @pytest.mark.parametrize(
        "url",
        [
            "https://siem.example/ectoledger/",
            "https://SIEM.example/ectoledger",
            "https://siem.example/ectoledger?x=1",
            "https://siem.example/ecto%6Cedger",
            "http://siem.example/ectoledger",
        ],
        ids=["trailing-slash", "host-case", "query", "percent-encoded", "scheme"],
    )
    def test_receiver_url_must_match_exactly(self, url: str) -> None:
        """The URL is signed as a string; no normalisation makes two spellings equal."""
        assert outcome(run(VALID, cache_at(VALID["now"]), receiver_url=url)) == "bad_signature"

    @pytest.mark.parametrize("timestamp", ["0", "-1", "-0", "-1790700000", "9" * 19])
    def test_an_integer_timestamp_far_from_now_is_stale(self, timestamp: str) -> None:
        body = b"{}"
        headers = self.signed(body, timestamp=timestamp)
        assert self.verify(headers, body) == WebhookVerdict(ok=False, reason="stale")

    @pytest.mark.parametrize("timestamp", ["+1790700000", "1790700000.0", "１７９０７０００００"])
    def test_a_timestamp_with_a_sign_fraction_or_fullwidth_digits_is_missing_headers(self, timestamp: str) -> None:
        body = b"{}"
        headers = self.signed(body, timestamp=timestamp)
        assert self.verify(headers, body) == WebhookVerdict(ok=False, reason="missing_headers")

    def test_zero_tolerance_accepts_only_the_exact_second(self) -> None:
        body = b"{}"
        headers = self.signed(body)
        assert self.verify(headers, body, now=1_790_700_000, tolerance_secs=0).ok
        assert outcome(self.verify(headers, body, now=1_790_700_001, tolerance_secs=0)) == "stale"


def _sign(key_hex: str, url: str, delivery_id: str, timestamp: str, body: bytes) -> dict[str, str]:
    """Sign a delivery per the spec, without using the code under test."""
    message = b"\n".join(
        [
            b"ectoledger-webhook-v1",
            delivery_id.encode(),
            timestamp.encode(),
            url.encode(),
            body,
        ]
    )
    sig = hmac.new(bytes.fromhex(key_hex), message, hashlib.sha256).hexdigest()
    return {DELIVERY: delivery_id, TIMESTAMP: timestamp, SIGNATURE: sig}


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class TestMemoryReplayCache:
    def test_remembers_an_id_until_its_expiry_then_forgets_it(self) -> None:
        clock = _Clock(1000)
        cache = MemoryReplayCache(clock)
        cache.add("a", 1300)
        assert cache.has("a")
        assert not cache.has("b")

        clock.now = 1300  # the expiry second itself still counts: the delivery is still fresh
        assert cache.has("a")

        clock.now = 1301
        assert not cache.has("a")

    def test_evicts_expired_ids_so_memory_does_not_grow_without_bound(self) -> None:
        clock = _Clock(1000)
        cache = MemoryReplayCache(clock)
        cache.add("a", 1100)
        cache.add("b", 1200)
        cache.add("c", 1300)
        assert len(cache) == 3

        clock.now = 1150
        assert len(cache) == 2
        clock.now = 1250
        assert len(cache) == 1
        clock.now = 5000
        assert len(cache) == 0

    def test_sweeps_on_add_so_a_receiver_that_never_asks_for_size_stays_bounded(self) -> None:
        clock = _Clock(0)
        cache = MemoryReplayCache(clock)
        for i in range(100):
            clock.now = i * 10
            cache.add(f"id-{i}", clock.now + 300)
        # Only the ids from the last 300 seconds are still held.
        assert len(cache) <= 31

    def test_forgets_an_accepted_id_once_its_window_has_passed(self) -> None:
        # In practice the timestamp check refuses a delivery that old first;
        # the cache alone must not hold ids forever.
        clock = _Clock(VALID["now"])
        cache = MemoryReplayCache(clock)
        assert outcome(run(VALID, cache)) == "ok"
        assert outcome(run(VALID, cache)) == "replayed"
        clock.now = VALID["now"] + 400
        assert not cache.has(VALID["headers"][DELIVERY])

    def test_defaults_to_the_system_clock(self) -> None:
        cache = MemoryReplayCache()
        now = time.time()
        cache.add("future", now + 60)
        cache.add("past", now - 60)
        assert cache.has("future")
        assert not cache.has("past")

    def test_satisfies_the_replay_cache_protocol(self) -> None:
        cache: ReplayCache = MemoryReplayCache()
        cache.add("x", time.time() + 1)
        assert cache.has("x")
