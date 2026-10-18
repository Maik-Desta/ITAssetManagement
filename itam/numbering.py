"""Asset number standard: CC-RRR-BBBB-TTT-NNNNN (slide 16).

The number is issued once, printed on a tamper-evident QR tag and never changes when the asset moves.
"""

from __future__ import annotations

import re

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from itam.enums import AssetType
from itam.models import Branch, NumberSequence

ASSET_NUMBER_RE = re.compile(r"^(?P<cc>[A-Z]{2})-(?P<rrr>[A-Z]{3})-(?P<bbbb>\d{4})-(?P<ttt>[A-Z]{3})-(?P<nnnnn>\d{5})$")


class NumberingError(ValueError):
    pass


def format_asset_number(cc: str, rrr: str, bbbb: str, ttt: str, seq: int) -> str:
    if seq < 1 or seq > 99999:
        raise NumberingError("Sequence exhausted for this prefix (max 99999)")
    number = f"{cc.upper()}-{rrr.upper()}-{bbbb}-{ttt.upper()}-{seq:05d}"
    if not ASSET_NUMBER_RE.match(number):
        raise NumberingError(f"Invalid asset number components: {number}")
    return number


def parse_asset_number(number: str) -> dict[str, str] | None:
    match = ASSET_NUMBER_RE.match((number or "").strip().upper())
    return match.groupdict() if match else None


def is_valid_asset_number(number: str) -> bool:
    parsed = parse_asset_number(number)
    return bool(parsed) and parsed["ttt"] in AssetType._value2member_map_


def next_asset_number(db: Session, branch: Branch, asset_type: str) -> str:
    """Allocate the next number for the branch + type prefix (atomic within the transaction)."""
    if asset_type not in AssetType._value2member_map_:
        raise NumberingError(f"Unknown asset type {asset_type}")
    region = branch.region
    prefix = f"{region.country_code}-{region.code}-{branch.code}-{asset_type}"
    row = db.execute(select(NumberSequence).where(NumberSequence.prefix == prefix).with_for_update()).scalar_one_or_none()
    if row is None:
        row = NumberSequence(prefix=prefix, next_value=1)
        db.add(row)
        db.flush()
    seq = row.next_value
    db.execute(update(NumberSequence).where(NumberSequence.prefix == prefix).values(next_value=seq + 1))
    db.expire(row)
    return format_asset_number(region.country_code, region.code, branch.code, asset_type, seq)


def extract_asset_number(scanned: str) -> str:
    """Accept either a bare number or a QR payload / URL that contains it."""
    text = (scanned or "").strip().upper()
    match = re.search(r"[A-Z]{2}-[A-Z]{3}-\d{4}-[A-Z]{3}-\d{5}", text)
    return match.group(0) if match else text


# ---------------------------------------------------------------------------
# RFID tag encoding (slide 54: "tag encoding scheme ↔ asset number")
# ---------------------------------------------------------------------------
#
# A 96-bit EPC (EPC Gen2 / ISO 18000-63 user-defined) that encodes the asset number itself, so a read can be
# resolved offline and a tag cannot silently point at another record:
#
#   header 8 | CC 2×5 | RRR 3×5 | BBBB 14 | TTT 3×5 | NNNNN 17 | reserved 1 | CRC-16 16   = 96 bits
#
# Letters are stored as A=0 … Z=25. The CRC covers the first 80 bits.

EPC_HEADER = 0xB5


def _crc16(value: int, nbits: int) -> int:
    crc = 0xFFFF
    for byte in value.to_bytes(nbits // 8, "big"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def _letters(text: str) -> int:
    value = 0
    for ch in text:
        value = (value << 5) | (ord(ch) - 65)
    return value


def _unletters(value: int, count: int) -> str:
    return "".join(chr(((value >> (5 * (count - 1 - i))) & 0x1F) + 65) for i in range(count))


def encode_epc(asset_number: str) -> str:
    """Asset number → 24 hex-character EPC."""
    parts = parse_asset_number(asset_number)
    if not parts:
        raise NumberingError(f"Not a valid asset number: {asset_number}")
    body = EPC_HEADER
    for bits, value in ((10, _letters(parts["cc"])), (15, _letters(parts["rrr"])), (14, int(parts["bbbb"])),
                        (15, _letters(parts["ttt"])), (17, int(parts["nnnnn"])), (1, 0)):
        body = (body << bits) | value
    return f"{(body << 16) | _crc16(body, 80):024X}"


def decode_epc(epc: str) -> str | None:
    """EPC → asset number, or None if the tag is not one of ours (wrong header, length or checksum)."""
    text = (epc or "").strip().replace(" ", "").upper()
    if len(text) != 24 or any(ch not in "0123456789ABCDEF" for ch in text):
        return None
    value = int(text, 16)
    body, crc = value >> 16, value & 0xFFFF
    if body >> 72 != EPC_HEADER or _crc16(body, 80) != crc:
        return None
    nnnnn = (body >> 1) & 0x1FFFF
    ttt = (body >> 18) & 0x7FFF
    bbbb = (body >> 33) & 0x3FFF
    rrr = (body >> 47) & 0x7FFF
    cc = (body >> 62) & 0x3FF
    try:
        return format_asset_number(_unletters(cc, 2), _unletters(rrr, 3), f"{bbbb:04d}", _unletters(ttt, 3), nnnnn)
    except NumberingError:
        return None
