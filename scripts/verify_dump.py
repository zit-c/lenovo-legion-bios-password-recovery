#!/usr/bin/env python3
"""Inspect an ordinary local image. No hardware access or credential decoding."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

EXPECTED_SIZE = 16 * 1024 * 1024
MAX_SIZE = 64 * 1024 * 1024


def positions(data, marker):
    offset = data.find(marker)
    while offset != -1:
        yield offset
        offset = data.find(marker, offset + 1)


def inspect_bytes(data):
    """Return non-credential metadata; do not include a filesystem path."""
    volumes = []
    for signature in positions(data, b"_FVH"):
        start = signature - 0x28
        if start < 0 or start + 0x38 > len(data):
            continue
        length = struct.unpack_from("<Q", data, start + 0x20)[0]
        header_length = struct.unpack_from("<H", data, start + 0x30)[0]
        bounds_ok = (0x38 <= header_length <= length and header_length % 2 == 0
                     and start + length <= len(data))
        checksum_ok = False
        if bounds_ok:
            header = data[start:start + header_length]
            checksum_ok = sum(x[0] for x in struct.iter_unpack("<H", header)) % 65536 == 0
        volumes.append({"offset": hex(start), "length": length,
                        "header_bounds_ok": bounds_ok,
                        "header_checksum_ok": checksum_ok})
    maps = []
    for start in positions(data, b"HFDM"):
        if start + 0x24 > len(data):
            continue
        total, header, entry = struct.unpack_from("<III", data, start + 4)
        geometry_ok = (header >= 0x24 and entry >= 0x30 and total >= header
                       and total <= len(data) - start and (total-header) % entry == 0)
        maps.append({"offset": hex(start), "declared_length": total,
                     "geometry_ok": geometry_ok,
                     "observed_header_checksum_ok": sum(data[start:start + 28]) % 256 == 0})
    valid_fv = sum(v["header_bounds_ok"] and v["header_checksum_ok"] for v in volumes)
    valid_map = any(m["geometry_ok"] and m["observed_header_checksum_ok"] for m in maps)
    uniform = not data or data.count(0) == len(data) or data.count(255) == len(data)
    warnings = []
    if len(data) != EXPECTED_SIZE:
        warnings.append("Unexpected size for the tested 16 MiB profile.")
    if uniform:
        warnings.append("Empty or uniformly filled input.")
    if not valid_fv:
        warnings.append("No valid firmware-volume header found.")
    if not valid_map:
        warnings.append("No structurally valid HFDM header candidate found.")
    return {
        "size_bytes": len(data), "expected_size_bytes": EXPECTED_SIZE,
        "sha256": hashlib.sha256(data).hexdigest(),
        "valid_fv_header_count": valid_fv, "firmware_volume_candidates": volumes,
        "hfdm_candidates": maps,
        "hfdm_at_profile_offset": data[0xEA8000:0xEA8004] == b"HFDM",
        "lspe_marker_count": sum(1 for _ in positions(data, b"LSPE")),
        "preliminary_checks_passed": not warnings, "warnings": warnings,
        "limitations": "Structural checks only; no proof of authenticity, full coverage or recoverable credentials. Keep this report private."
    }


def inspect_file(path):
    if not path.is_file():
        raise ValueError("Input must be an ordinary file.")
    with path.open("rb") as handle:
        data = handle.read(MAX_SIZE + 1)
    if len(data) > MAX_SIZE:
        raise ValueError("Input exceeds the 64 MiB analysis limit.")
    return inspect_bytes(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="local image; never uploaded")
    args = parser.parse_args(argv)
    try:
        result = inspect_file(args.image)
    except (OSError, ValueError):
        parser.exit(2, "Cannot inspect input: check file type, readability and size.\n")
    print(json.dumps(result, indent=2))
    return 0 if result["preliminary_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
