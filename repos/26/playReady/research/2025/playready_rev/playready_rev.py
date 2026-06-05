#!/usr/bin/env python3
"""
PlayReady public key hash revocation checker.

- Fetches Microsoft's revocation XML.
- Extracts the PlayReady Silverlight Runtime revocation list.
- Prints all 32-byte public key hashes (Base64).
- If a hash is provided (argv[1] or prompted), reports whether it's revoked.
- If 'bgroupcert.dat' in directory, extract the hash and reports whether it's revoked.

Compatible with Python 3.8+.
"""

from __future__ import annotations

import base64
import struct
import sys
import uuid
from typing import Iterable, List, Optional

import requests
import xmltodict

# --- Configuration ----------------------------------------------------------------

REV_URL = "https://go.microsoft.com/fwlink/?LinkId=110086"

# GUID for PlayReady Silverlight Runtime (as raw bytes like original code)
GUID_PR_SILVERLIGHT_RUNTIME = bytes([
    0x4E, 0x9D, 0x8C, 0x8A, 0xB6, 0x52, 0x45, 0xA7,
    0x97, 0x91, 0x69, 0x25, 0xA6, 0xB4, 0x79, 0x1F
])

# If construct is available, we’ll use it to parse the binary blob declaratively.
try:
    from construct import Struct as CStruct, Bytes, Int32ub
    _HAS_CONSTRUCT = True
except Exception:
    _HAS_CONSTRUCT = False


# --- Helpers ----------------------------------------------------------------------

def _expected_guid_le_hex(guid_bytes: bytes) -> str:
    """
    The source blob compares the first 16 bytes against UUID(...).bytes_le.
    Keep that exact behavior to match the original script.
    """
    return uuid.UUID(guid_bytes.hex()).bytes_le.hex()


def _parse_revocation_blob_with_construct(blob: bytes) -> Optional[List[bytes]]:
    """
    Parse a revocation list blob using construct (if installed).
    Format per original code:
      [0:16]  GUID
      [16:20] unknown / reserved
      [20:24] entries_count (u32 big-endian)
      [24: ]  entries_count * 32-byte hashes
    """
    if not _HAS_CONSTRUCT:
        return None

    RevHeader = CStruct(
        "type_guid" / Bytes(16),
        "reserved"  / Bytes(4),
        "entries_count" / Int32ub,
    )

    # First parse header to get count
    if len(blob) < 24:
        return []

    header = RevHeader.parse(blob[:24])

    # Verify GUID (same logic/endianness as original)
    if blob[:16].hex() != _expected_guid_le_hex(GUID_PR_SILVERLIGHT_RUNTIME):
        return []

    # Extract entries
    start = 24
    end = start + (header.entries_count * 32)
    if end > len(blob):
        # Truncated blob; be defensive
        end = min(len(blob), start + ((len(blob) - start) // 32) * 32)

    entries = [blob[i:i+32] for i in range(start, end, 32)]
    return entries


def _parse_revocation_blob_manually(blob: bytes) -> List[bytes]:
    """
    Manual parser (no construct). Mirrors the original byte slicing exactly.
    """
    if len(blob) < 24:
        return []

    # GUID check with the same endianness trick as original
    if blob[:16].hex() != _expected_guid_le_hex(GUID_PR_SILVERLIGHT_RUNTIME):
        return []

    # entries_count is big-endian u32 at offset 20
    entries_count = struct.unpack_from(">I", blob, 20)[0]
    cursor = 24
    out: List[bytes] = []
    for _ in range(entries_count):
        if cursor + 32 > len(blob):
            break
        out.append(blob[cursor:cursor+32])
        cursor += 32
    return out


def _iter_revocation_lists(xml_root: dict) -> Iterable[bytes]:
    """
    Yields each decoded revocation list (ListData) as raw bytes.
    Handles the cases where Revocation is a dict or a list of dicts.
    """
    rev = xml_root.get("RevInfo", {}).get("Revocation")
    if rev is None:
        return

    items = rev if isinstance(rev, list) else [rev]
    for item in items:
        data_b64 = item.get("ListData")
        if not data_b64:
            continue
        try:
            yield base64.b64decode(data_b64)
        except Exception:
            continue


def _fetch_revocation_index(url: str = REV_URL) -> dict:
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    # xmltodict produces nested OrderedDict-like structures; dict() is fine
    return xmltodict.parse(resp.text)


def _collect_public_key_hashes(xml_root: dict) -> List[str]:
    """
    Returns Base64-encoded 32-byte public key hashes from the
    PlayReady Silverlight Runtime revocation list.
    """
    hashes_b64: List[str] = []

    for blob in _iter_revocation_lists(xml_root):
        # Try construct first (if available), then fallback
        entries = _parse_revocation_blob_with_construct(blob) if _HAS_CONSTRUCT else None
        if entries is None:
            entries = _parse_revocation_blob_manually(blob)

        if not entries:
            continue

        for entry in entries:
            hashes_b64.append(base64.b64encode(entry).decode("ascii"))

    return hashes_b64


# --- CLI --------------------------------------------------------------------------

def main(argv: List[str]) -> int:
    try:
        xml_root = _fetch_revocation_index(REV_URL)
    except Exception as e:
        print(f"Failed to fetch or parse revocation index: {e}", file=sys.stderr)
        return 2

    publickey_hashes = _collect_public_key_hashes(xml_root)

    # Print the list (like the original)
    if publickey_hashes:
        print("\n".join(publickey_hashes))

    # Determine the input hash
    pubkey_hash: Optional[str] = None
    if len(argv) > 1 and argv[1]:
        pubkey_hash = argv[1].strip()
        print()
        print("Provided hash:", pubkey_hash)
   
    if not pubkey_hash:
        bcert = open("bgroupcert.dat", "rb").read()
        pubkey_hash = base64.b64encode(bcert[0x48:0x68]).decode()
        print()
        print("Calculated hash:", pubkey_hash)

    if not pubkey_hash:
        print("No hash provided.")
        return 1

    if pubkey_hash in publickey_hashes:
        print("one of hashes in CRL match the input hash.")
        print("PlayReady Cert is revoked.")
        return 0
    else:
        print("PlayReady Cert is valid.")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
