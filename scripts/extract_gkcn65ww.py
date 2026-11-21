#!/usr/bin/env python3
"""Reconstruct the exact official GKCN65WW nested archive without executing it.

Narrow original project helper; not a general Inno Setup parser. The EXE filter
interpretation was cross-checked against innoextract format behavior; no upstream
source code is incorporated. Subsequent 7-Zip testing must verify file CRCs.
"""
import argparse
import hashlib
import lzma
from pathlib import Path
import struct
import zlib

PACKAGE_SHA256 = "4176f794a811f882ea312c0d8f3ebc711db4c5a8b1bc92dc7301898d3220c1a0"
PACKAGE_SIZE = 7468088
RAW_SIZE = 6902411


def reconstruct(package):
    if len(package) != PACKAGE_SIZE or hashlib.sha256(package).hexdigest() != PACKAGE_SHA256:
        raise ValueError("This is not the exact investigated official package.")
    start = package.index(b"zlb\x1a") + 4
    prop = package[start]
    if prop > 40:
        raise ValueError("Unsupported LZMA2 property.")
    dictionary = (2 | (prop & 1)) << ((prop >> 1) + 11)
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                  filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dictionary}])
    raw = decoder.decompress(package[start+1:], max_length=RAW_SIZE+1)
    if not decoder.eof or len(raw) != RAW_SIZE or not raw[:0xEB].startswith(b"@echo off"):
        raise ValueError("Unexpected package payload.")
    decoded = bytearray(raw[0xEB:])
    index = 0
    while index < len(decoded):
        if (decoded[index] in (0xE8, 0xE9) and 0x10000-index % 0x10000 >= 5
                and index+4 < len(decoded)):
            if decoded[index+4] in (0, 255):
                relative = (int.from_bytes(decoded[index+1:index+4], "little")
                            - ((index+5) & 0xFFFFFF)) & 0xFFFFFF
                decoded[index+1:index+4] = relative.to_bytes(3, "little")
                if relative & 0x800000:
                    decoded[index+4] ^= 255
            index += 5
        else:
            index += 1
    archive = bytes(decoded[decoded.index(bytes.fromhex("377abcaf271c")):])
    if len(archive) < 32 or zlib.crc32(archive[12:32]) != struct.unpack_from("<I", archive, 8)[0]:
        raise ValueError("Archive start-header CRC mismatch.")
    offset, size, checksum = struct.unpack_from("<QQI", archive, 12)
    if offset > len(archive)-32 or size > len(archive)-32-offset:
        raise ValueError("Archive header is outside the file.")
    if zlib.crc32(archive[32+offset:32+offset+size]) != checksum:
        raise ValueError("Archive next-header CRC mismatch.")
    return archive


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("output_archive", type=Path)
    args = parser.parse_args(argv)
    try:
        if not args.package.is_file():
            raise ValueError("Input must be an ordinary file.")
        with args.package.open("rb") as handle:
            package = handle.read(PACKAGE_SIZE+1)
        archive = reconstruct(package)
        args.output_archive.parent.mkdir(parents=True, exist_ok=True)
        with args.output_archive.open("xb") as handle:
            handle.write(archive)
    except (OSError, ValueError, lzma.LZMAError, struct.error):
        parser.exit(2, "Extraction stopped: check exact input hash, output permissions and absence of an existing output file.\n")
    print("Nested archive reconstructed as data. Nothing was executed. Test it with 7-Zip before extraction.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
