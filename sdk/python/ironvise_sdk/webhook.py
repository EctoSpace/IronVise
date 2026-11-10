"""Receiver-side verification of IronVise webhook deliveries.

Scheme ``ectoledger-webhook-v1``. When the server has ``WEBHOOK_HMAC_SECRET``
set, every POST carries:

* ``X-EctoLedger-Delivery``      a unique id for this delivery,
* ``X-EctoLedger-Timestamp``     unix seconds, as a decimal string,
* ``X-EctoLedger-Signature-V1``  64 lowercase hex characters.

The signature is ``HMAC-SHA256`` under the *receiver's own key* over
``"ectoledger-webhook-v1" \\n id \\n timestamp \\n receiver_url \\n body``. That
key is derived from the server secret and the receiver's URL, so a delivery
captured at one receiver fails at every other, and no receiver can sign a
delivery for another. Get yours with ``ironvise webhook-key --url <url>``.

Pinned to ``sdk/fixtures/webhook-v1.json``, which the Rust server generates.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

__all__ = [
    "MemoryReplayCache",
    "ReplayCache",
    "WebhookVerdict",
    "derive_receiver_key",
    "verify_webhook",
]

# Domain separation for the two uses of the server secret.
_RECEIVER_KEY_CONTEXT = "ectoledger-webhook-key-v1"
_SIGNATURE_CONTEXT = "ectoledger-webhook-v1"

_HEADER_DELIVERY = "x-ectoledger-delivery"
_HEADER_TIMESTAMP = "x-ectoledger-timestamp"
_HEADER_SIGNATURE = "x-ectoledger-signature-v1"

# ``[0-9]``, not ``\d``: ``\d`` also matches other scripts' digits. At most 19
# digits (an i64, as the server writes it): ``int()`` on a header of thousands
# of digits is slow, and refuses outright past a limit.
_INTEGER = re.compile(r"-?[0-9]{1,19}")
_KEY_HEX = re.compile(r"[0-9a-fA-F]{64}")

# Serialises the "seen it? / remember it" step, so two threads presenting the
# same delivery cannot both pass.
_replay_lock = threading.Lock()


@dataclass(frozen=True)
class WebhookVerdict:
    """The outcome of :func:`verify_webhook`.

    ``ok`` is true and ``delivery_id`` is set for an accepted delivery.
    Otherwise ``reason`` is one of ``"missing_headers"``, ``"stale"``,
    ``"bad_signature"`` or ``"replayed"``.
    """

    ok: bool
    reason: str | None = None
    delivery_id: str | None = None


class ReplayCache(Protocol):
    """Remembers delivery ids so a captured delivery cannot be presented twice.

    :func:`verify_webhook` checks ``has`` and then calls ``add`` under a lock, so
    an in-process cache needs no locking of its own for that. A cache shared
    between processes (Redis, a database) needs an atomic set-if-absent behind
    ``add``, or a check of its own.
    """

    def has(self, delivery_id: str, /) -> bool:
        """True if ``delivery_id`` was added and has not yet expired."""
        ...

    def add(self, delivery_id: str, expires_at: float, /) -> None:
        """Remember ``delivery_id`` until ``expires_at`` (unix seconds)."""
        ...


class MemoryReplayCache:
    """In-process :class:`ReplayCache`. Expired ids are evicted.

    Memory is bounded by the deliveries seen inside one tolerance window. It
    does not survive a restart and is not shared between processes: run more
    than one receiver process and each needs a shared cache instead.

    ``clock`` returns the current time in unix seconds; tests pass their own.
    """

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._seen: dict[str, float] = {}
        self._last_sweep = float("-inf")
        self._lock = threading.Lock()

    def has(self, delivery_id: str, /) -> bool:
        with self._lock:
            expires_at = self._seen.get(delivery_id)
            return expires_at is not None and expires_at >= self._clock()

    def add(self, delivery_id: str, expires_at: float, /) -> None:
        with self._lock:
            self._sweep()
            self._seen[delivery_id] = expires_at

    def __len__(self) -> int:
        """Number of ids currently remembered (expired ones are evicted first)."""
        with self._lock:
            self._sweep(force=True)
            return len(self._seen)

    def _sweep(self, *, force: bool = False) -> None:
        """Drop expired ids, at most once a second unless ``force``d."""
        now = self._clock()
        if not force and now - self._last_sweep < 1:
            return
        self._last_sweep = now
        for delivery_id in [i for i, exp in self._seen.items() if exp < now]:
            del self._seen[delivery_id]


def derive_receiver_key(secret: str | bytes, receiver_url: str) -> str:
    """Derive the key one receiver verifies with, as 64 lowercase hex characters.

    ``HMAC-SHA256(secret, "ectoledger-webhook-key-v1\\n" + receiver_url)``. This
    is what ``ironvise webhook-key --url <url>`` prints. It is for operators:
    it needs the server secret, which a receiver must never hold.
    ``receiver_url`` must be exactly the URL the webhook is configured with.
    """
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    message = f"{_RECEIVER_KEY_CONTEXT}\n{receiver_url}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _header(headers: Mapping[str, str], lower_name: str) -> str | None:
    """Case-insensitive header lookup; a non-string value counts as absent."""
    for name, value in headers.items():
        if isinstance(name, str) and name.lower() == lower_name:
            return value if isinstance(value, str) else None
    return None


def verify_webhook(
    *,
    receiver_key: str,
    receiver_url: str,
    headers: Mapping[str, str],
    body: str | bytes,
    cache: ReplayCache,
    now: float | None = None,
    tolerance_secs: int = 300,
) -> WebhookVerdict:
    """Verify one webhook delivery.

    ``receiver_key`` is this receiver's key (64 hex characters, from
    ``ironvise webhook-key --url``); ``receiver_url`` is this receiver's URL,
    exactly as the webhook is configured on the server. ``headers`` is any
    mapping of request headers, in any name casing. ``body`` is the raw request
    body exactly as received, not re-serialised JSON. ``now`` is the current
    time in unix seconds and defaults to the system clock.

    Checks run in this order, and the order matters: the delivery id is
    remembered only after the signature has passed, so a forged request cannot
    fill the replay cache or use up a genuine delivery's id.

    1. a header is missing, or the timestamp is not an integer: ``missing_headers``
    2. the timestamp is more than ``tolerance_secs`` from ``now``: ``stale``
    3. the signature does not match (constant-time compare): ``bad_signature``
    4. the delivery id was already seen: ``replayed``

    Raises ``ValueError`` if ``receiver_key`` is not 64 hex characters: that is
    a configuration mistake, not something a sender can cause.

    Example::

        cache = MemoryReplayCache()  # one for the life of the process
        verdict = verify_webhook(
            receiver_key=os.environ["WEBHOOK_KEY"],
            receiver_url="https://siem.example/ironvise",
            headers=request.headers,
            body=request.get_data(),
            cache=cache,
        )
        if not verdict.ok:
            abort(401, verdict.reason)
    """
    if not _KEY_HEX.fullmatch(receiver_key):
        raise ValueError("receiver_key must be 64 hex characters")

    delivery_id = _header(headers, _HEADER_DELIVERY)
    timestamp = _header(headers, _HEADER_TIMESTAMP)
    signature = _header(headers, _HEADER_SIGNATURE)
    if (
        not delivery_id
        or not signature
        or timestamp is None
        or not _INTEGER.fullmatch(timestamp)
    ):
        return WebhookVerdict(ok=False, reason="missing_headers")

    current = time.time() if now is None else now
    sent_at = int(timestamp)
    if abs(current - sent_at) > tolerance_secs:
        return WebhookVerdict(ok=False, reason="stale")

    raw_body = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    message = b"\n".join(
        [
            _SIGNATURE_CONTEXT.encode(),
            delivery_id.encode("utf-8"),
            timestamp.encode(),
            receiver_url.encode("utf-8"),
            raw_body,
        ]
    )
    expected = hmac.new(
        bytes.fromhex(receiver_key), message, hashlib.sha256
    ).hexdigest()
    # Bytes, not str: compare_digest raises TypeError on a non-ASCII str, and
    # the header is attacker-controlled.
    if not hmac.compare_digest(signature.encode("utf-8"), expected.encode()):
        return WebhookVerdict(ok=False, reason="bad_signature")

    with _replay_lock:
        if cache.has(delivery_id):
            return WebhookVerdict(ok=False, reason="replayed")
        cache.add(delivery_id, sent_at + tolerance_secs)
    return WebhookVerdict(ok=True, delivery_id=delivery_id)
