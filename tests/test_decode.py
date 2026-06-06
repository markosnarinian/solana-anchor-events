"""End-to-end tests for the pumpfun_anchor event decoder.

The TradeEvent round-trip reads the discriminator and the field order/types
straight from the IDL JSON, so the test cannot silently drift from the schema:
it Borsh-encodes known values in Python, wraps them in a "Program data:" log
line, and asserts every field decodes back to the value that went in.
"""

import base64
import json
import os
import struct

import pytest

from pumpfun_anchor import EventDecoder

HERE = os.path.dirname(os.path.abspath(__file__))
IDL_PATH = os.path.join(HERE, "pumpfun.json")


@pytest.fixture(scope="module")
def idl():
    with open(IDL_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def decoder():
    with open(IDL_PATH) as f:
        return EventDecoder(f.read())


# --- minimal, independent reference helpers -------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    """Independent base58 encoder (Bitcoin alphabet) for cross-checking pubkeys."""
    n = int.from_bytes(raw, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    pad = 0
    for byte in raw:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def borsh_encode(value, ty):
    """Encode a single value per the Borsh wire format for a given IDL type."""
    if isinstance(ty, str):
        if ty == "bool":
            return b"\x01" if value else b"\x00"
        if ty == "u8":
            return struct.pack("<B", value)
        if ty == "i8":
            return struct.pack("<b", value)
        if ty == "u16":
            return struct.pack("<H", value)
        if ty == "i16":
            return struct.pack("<h", value)
        if ty == "u32":
            return struct.pack("<I", value)
        if ty == "i32":
            return struct.pack("<i", value)
        if ty == "u64":
            return struct.pack("<Q", value)
        if ty == "i64":
            return struct.pack("<q", value)
        if ty == "f32":
            return struct.pack("<f", value)
        if ty == "f64":
            return struct.pack("<d", value)
        if ty == "u128":
            return int(value).to_bytes(16, "little")
        if ty == "i128":
            return int(value).to_bytes(16, "little", signed=True)
        if ty == "pubkey":
            assert len(value) == 32
            return bytes(value)
        if ty == "string":
            data = value.encode("utf-8")
            return struct.pack("<I", len(data)) + data
        if ty == "bytes":
            return struct.pack("<I", len(value)) + bytes(value)
        raise ValueError(f"unsupported scalar idl type: {ty!r}")
    if isinstance(ty, dict):
        if "option" in ty:
            if value is None:
                return b"\x00"
            return b"\x01" + borsh_encode(value, ty["option"])
        if "vec" in ty:
            out = struct.pack("<I", len(value))
            for item in value:
                out += borsh_encode(item, ty["vec"])
            return out
        if "array" in ty:
            inner, _n = ty["array"]
            out = b""
            for item in value:
                out += borsh_encode(item, inner)
            return out
    raise ValueError(f"unsupported idl type: {ty!r}")


def make_value(i, ty):
    """Synthesize a distinct, type-appropriate known value for field index `i`."""
    if ty == "bool":
        return i % 2 == 0
    if ty == "u8":
        return (i * 3 + 1) % 256
    if ty == "i8":
        return -((i % 100) + 1)
    if ty == "u16":
        return (i + 1) * 1000 + 7
    if ty == "i16":
        return -((i + 1) * 100 + 3)
    if ty == "u32":
        return (i + 1) * 100_003 + 7
    if ty == "i32":
        return -((i + 1) * 100_003 + 7)
    if ty == "u64":
        # large enough to exercise the high bytes
        return (i + 1) * 1_234_567_890_123 + 17
    if ty == "i64":
        return -((i + 1) * 987_654_321_987 + 11)
    if ty == "u128":
        return (i + 1) * (2 ** 70) + 12_345
    if ty == "i128":
        return -((i + 1) * (2 ** 70) + 777)
    if ty in ("f32", "f64"):
        return float(i) + 0.5
    if ty == "pubkey":
        return bytes([(i * 7 + j) % 256 for j in range(32)])
    if ty == "string":
        # include multibyte chars to exercise UTF-8 length handling
        return f"ix-{i}-Ω/世"
    if ty == "bytes":
        return bytes([(i + j) % 256 for j in range(3)])
    raise ValueError(f"no known value generator for type {ty!r}")


def struct_fields(idl, name):
    td = next(t for t in idl["types"] if t["name"] == name)
    assert td["type"]["kind"] == "struct"
    return td["type"]["fields"]


# --- tests ----------------------------------------------------------------


def test_event_names(decoder):
    names = decoder.event_names
    assert len(names) == 23
    assert "TradeEvent" in names
    assert "CreateEvent" in names


def test_trade_event_round_trip(idl, decoder):
    event = next(e for e in idl["events"] if e["name"] == "TradeEvent")
    discriminator = bytes(event["discriminator"])
    assert len(discriminator) == 8

    fields = struct_fields(idl, "TradeEvent")

    # Build known values + the Borsh body, both driven entirely by the IDL.
    known = {}
    body = b""
    for i, field in enumerate(fields):
        value = make_value(i, field["type"])
        known[field["name"]] = value
        body += borsh_encode(value, field["type"])

    line = "Program data: " + base64.b64encode(discriminator + body).decode("ascii")

    results = decoder.parse_logs([line])
    assert len(results) == 1
    name, data = results[0]
    assert name == "TradeEvent"

    # Exactly the IDL's fields, no more, no fewer.
    assert set(data.keys()) == {f["name"] for f in fields}

    for field in fields:
        fname, ty = field["name"], field["type"]
        expected = known[fname]
        got = data[fname]
        if ty == "pubkey":
            assert got == b58encode(expected), f"{fname}: {got!r} != {b58encode(expected)!r}"
        elif ty in ("f32", "f64"):
            assert abs(got - expected) < 1e-3, f"{fname}: {got} != {expected}"
        else:
            assert got == expected, f"{fname}: {got!r} != {expected!r}"

    # Spot-check types and that bool decoding handles both True and False.
    assert isinstance(data["is_buy"], bool) and data["is_buy"] == known["is_buy"]
    assert isinstance(data["sol_amount"], int)
    assert isinstance(data["ix_name"], str)
    assert data["ix_name"] == known["ix_name"]
    bool_values = {data[f["name"]] for f in fields if f["type"] == "bool"}
    assert bool_values == {True, False}, f"expected both bool states, got {bool_values}"


def test_non_prefixed_line_skipped(decoder):
    assert decoder.parse_logs(["this is just a normal program log, not data"]) == []
    assert decoder.parse_logs(["Program log: hello world (not base64 event)"]) == []


def test_unknown_discriminator_skipped(decoder):
    # Valid base64, >= 8 bytes, but a discriminator that matches no event.
    payload = bytes([0xFF] * 8) + b"\x00\x00\x00\x00"
    line = "Program data: " + base64.b64encode(payload).decode("ascii")
    assert decoder.parse_logs([line]) == []


def test_too_short_payload_skipped(decoder):
    line = "Program data: " + base64.b64encode(b"\x01\x02\x03").decode("ascii")
    assert decoder.parse_logs([line]) == []


def test_mixed_batch_returns_only_valid_events(idl, decoder):
    event = next(e for e in idl["events"] if e["name"] == "TradeEvent")
    discriminator = bytes(event["discriminator"])
    fields = struct_fields(idl, "TradeEvent")
    body = b"".join(borsh_encode(make_value(i, f["type"]), f["type"]) for i, f in enumerate(fields))
    good = "Program data: " + base64.b64encode(discriminator + body).decode("ascii")

    batch = [
        "random noise",
        "Program data: " + base64.b64encode(bytes([0xAA] * 16)).decode("ascii"),  # unknown disc
        good,
        "Program log: not really base64 @@@",
    ]
    results = decoder.parse_logs(batch)
    assert len(results) == 1
    assert results[0][0] == "TradeEvent"


def test_bad_idl_raises():
    with pytest.raises(ValueError):
        EventDecoder("{not valid json")
