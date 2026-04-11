#!/usr/bin/env python3
"""Convert oui.json (maclookup.app format) to compact binary for embedding.

Binary format (no header, records packed end-to-end):
  [3 bytes MAC prefix] [1 byte name length] [N bytes vendor name UTF-8]

Only MA-L (3-octet) prefixes are written; MA-M/MA-S are silently skipped
because the lookup key is always a 3-byte prefix from the MAC address.

Usage:
  python3 scripts/gen-oui-bin.py internal/scan/oui.json internal/scan/oui.bin
"""

import json
import pathlib
import sys


def main() -> None:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <oui.json> <oui.bin>", file=sys.stderr)
        sys.exit(1)

    src = pathlib.Path(sys.argv[1])
    dst = pathlib.Path(sys.argv[2])

    entries = json.loads(src.read_bytes())
    out = bytearray()
    skipped = 0

    for e in entries:
        prefix: str = e.get("macPrefix", "")
        name: str = e.get("vendorName", "")
        if not name:
            continue

        # Normalise separator — could be "AA:BB:CC" or "AA-BB-CC"
        parts = prefix.replace("-", ":").split(":")
        if len(parts) != 3:
            # MA-M (/28) and MA-S (/36) prefixes have more octets; skip them.
            # Lookup is always done with a 3-octet OUI, so they are useless.
            skipped += 1
            continue

        try:
            b = bytes(int(p, 16) for p in parts)
        except ValueError:
            skipped += 1
            continue

        name_bytes = name.encode("utf-8")
        if len(name_bytes) > 255:
            name_bytes = name_bytes[:255]

        out += b + bytes([len(name_bytes)]) + name_bytes

    dst.write_bytes(bytes(out))

    count = len(entries) - skipped
    print(f"gen-oui-bin: {count:,} MA-L entries → {len(out):,} bytes  ({dst})")
    if skipped:
        print(f"gen-oui-bin: {skipped:,} non-MA-L entries skipped")


if __name__ == "__main__":
    main()
