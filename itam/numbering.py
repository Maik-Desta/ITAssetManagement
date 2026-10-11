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
