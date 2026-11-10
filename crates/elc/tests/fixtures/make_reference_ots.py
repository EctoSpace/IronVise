#!/usr/bin/env python3
"""Build reference-bitcoin.ots with the OpenTimestamps reference library.

    pip install opentimestamps
    python3 crates/elc/tests/fixtures/make_reference_ots.py

A stamp over the shipped example certificate's ledger tip with two branches:
a pending calendar, and sha256 then a Bitcoin block-header attestation at
height 800000. The block is made up (nothing here touches Bitcoin); the point
is that the bytes come from the reference serializer, so the Rust parser is
checked against another implementation rather than against itself.
"""
import json
import pathlib

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256, OpAppend
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

HERE = pathlib.Path(__file__).resolve().parent
cert = json.loads((HERE.parents[3] / "examples/verified-session/session.elc").read_text())
tip = bytes.fromhex(cert["ledger_tip_hash"])

ts = Timestamp(tip)
pending = ts.ops.add(OpAppend(b"\x01\x02\x03\x04"))
pending.attestations.add(PendingAttestation("https://calendar.example"))
mined = ts.ops.add(OpSHA256())
mined.attestations.add(BitcoinBlockHeaderAttestation(800000))

ctx = BytesSerializationContext()
DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
(HERE / "reference-bitcoin.ots").write_bytes(ctx.getbytes())
print("wrote reference-bitcoin.ots")
