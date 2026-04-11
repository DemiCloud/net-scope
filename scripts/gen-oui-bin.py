#!/usr/bin/env python3
"""Convert oui.json (maclookup.app format) to compact binary for embedding.

Binary format — fixed 6-byte records (5-byte key + 1-byte name length),
followed by the variable-length name, sorted ascending by key.

Key layout (5 bytes, big-endian):
  byte 0   MAC byte 0
  byte 1   MAC byte 1
  byte 2   MAC byte 2
  byte 3   (nibble3 << 4) | 0x00   — the 4th hex nibble for MA-M/MA-S;
             0x00 for MA-L (so MA-L sorts before MA-M/MA-S at same OUI)
  byte 4   (nibble4 << 4) | 0x00   — the 9th hex nibble for MA-S/IAB;
             0x00 for MA-L and MA-M

Examples for OUI "AA:BB:CC":
  MA-L  "AA:BB:CC"        → key = AA BB CC 00 00
  MA-M  "AA:BB:CC:D"      → key = AA BB CC D0 00
  MA-S  "AA:BB:CC:DD:E"   → key = AA BB CC DD E0

Lookup (given a full 6-byte MAC):
  1. Build MA-S key from bytes[0..4]+nibble5-upper → binary search
  2. Build MA-M key from bytes[0..2]+nibble3-upper → binary search
  3. Build MA-L key from bytes[0..2]               → binary search
  Return the first match (longest prefix wins).

Usage:
  python3 scripts/gen-oui-bin.py internal/scan/oui.json internal/scan/oui.bin
"""

import json
import pathlib
import sys


def parse_prefix(raw: str) -> bytes | None:
    """Return a 5-byte key or None if the prefix is unparseable."""
    s = raw.replace("-", "").replace(":", "").upper()
    n = len(s)
    try:
        if n == 6:
            # MA-L: bytes 0-2, nibbles 3 and 4 are zero
            b = bytes.fromhex(s)
            return bytes([b[0], b[1], b[2], 0x00, 0x00])

        elif n == 7:
            # MA-M: bytes 0-2 + upper nibble of byte 3; nibble 4 is zero
            b = bytes.fromhex(s[:6])
            nib3 = int(s[6], 16)
            return bytes([b[0], b[1], b[2], nib3 << 4, 0x00])

        elif n == 9:
            # MA-S / IAB: bytes 0-3 + upper nibble of byte 4
            b = bytes.fromhex(s[:8])
            nib4 = int(s[8], 16)
            return bytes([b[0], b[1], b[2], b[3], nib4 << 4])

    except (ValueError, IndexError):
        pass
    return None


def main() -> None:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <oui.json> <oui.bin>", file=sys.stderr)
        sys.exit(1)

    src = pathlib.Path(sys.argv[1])
    dst = pathlib.Path(sys.argv[2])

    entries = json.loads(src.read_bytes())
    records: list[tuple[bytes, bytes]] = []  # (5-byte key, name utf-8)
    counts = {"MA-L": 0, "MA-M": 0, "MA-S": 0, "skip": 0}

    for e in entries:
        name: str = e.get("vendorName", "")
        if not name:
            counts["skip"] += 1
            continue

        key = parse_prefix(e.get("macPrefix", ""))
        if key is None:
            counts["skip"] += 1
            continue

        name_bytes = name.encode("utf-8")[:255]
        records.append((key, name_bytes))

        # Count by prefix length
        n = len(e.get("macPrefix", "").replace("-","").replace(":",""))
        if n == 6:   counts["MA-L"] += 1
        elif n == 7: counts["MA-M"] += 1
        else:        counts["MA-S"] += 1

    # Sort ascending by key.
    records.sort(key=lambda r: r[0])

    # Deduplicate: on equal keys keep the last (shouldn't occur, but be safe).
    deduped: list[tuple[bytes, bytes]] = []
    for rec in records:
        if deduped and deduped[-1][0] == rec[0]:
            deduped[-1] = rec
        else:
            deduped.append(rec)

    out = bytearray()
    for key, name_bytes in deduped:
        out += key + bytes([len(name_bytes)]) + name_bytes

    dst.write_bytes(bytes(out))

    total = len(deduped)
    print(f"gen-oui-bin: {total:,} entries "
          f"(MA-L:{counts['MA-L']:,} MA-M:{counts['MA-M']:,} "
          f"MA-S/IAB:{counts['MA-S']:,}) → {len(out):,} bytes ({dst})")
    if counts["skip"]:
        print(f"gen-oui-bin: {counts['skip']:,} entries skipped (no name or bad prefix)")


if __name__ == "__main__":
    main()
