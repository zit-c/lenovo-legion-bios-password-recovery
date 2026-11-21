#!/usr/bin/env python3
"""Recover GKCN65WW password records from a local file, without hardware access.

Original project implementation adapted from the successful private analysis.
No original dump hash, device identifiers or real credential examples included.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import uuid

PROFILE = "GKCN65WW"
IMAGE_SIZE = 0x1000000
FDM_OFFSET = 0xEA8000
FDM_GEOMETRY = (0xC48, 0x24, 0x54)
REGIONS = (
    ("f392b582-1f08-4e95-b51d-598b19f6993f", 0x5AF000, 0x800),
    ("fa01652a-4942-417a-ae1c-b8fa2bd31a84", 0x5AF800, 0x800),
)
MAX_LENGTH = 16  # Conservative investigated profile limit, not a universal maximum.


class RecoveryError(ValueError):
    """An unsupported or invalid input; messages contain no credential data."""


class NoPasswordError(RecoveryError):
    """No nonempty valid record in the returned password regions."""


def keymap_us():
    """Standard PC set-1 printable key positions; not a copied decoder table."""
    result = {}
    for start, row in [(0x02, "1 2 3 4 5 6 7 8 9 0 - ="),
                       (0x10, "q w e r t y u i o p [ ]"),
                       (0x1E, "a s d f g h j k l ; ' `"),
                       (0x2B, "\\ z x c v b n m , . /")]:
        result.update({start+i: char for i, char in enumerate(row.split())})
    result[0x39] = " "
    return result


def recover_bytes(data, profile):
    """Return SECRET data to the caller. Never log this function's result."""
    if profile != PROFILE:
        raise RecoveryError("Unsupported profile. Only GKCN65WW is implemented.")
    if len(data) != IMAGE_SIZE:
        raise RecoveryError("Unsupported image size: expected a raw 16 MiB image, not an update container.")
    fdm = FDM_OFFSET
    if data[fdm:fdm+4] != b"HFDM":
        raise RecoveryError("Unsupported layout: HFDM is absent at the profile offset.")
    total, header, step = struct.unpack_from("<III", data, fdm+4)
    if (total, header, step) != FDM_GEOMETRY or fdm+total > len(data):
        raise RecoveryError("Unsupported HFDM geometry; refusing to guess region offsets.")
    if sum(data[fdm:fdm+28]) % 256:
        raise RecoveryError("HFDM header checksum failed. Input may be damaged or incomplete.")
    if struct.unpack_from("<Q", data, fdm+20)[0] != 0xFF000000:
        raise RecoveryError("Unsupported HFDM flash descriptor base.")
    wanted = {guid: (offset, size) for guid, offset, size in REGIONS}
    found = {}
    for pos in range(fdm+header, fdm+total-step+1, step):
        guid = str(uuid.UUID(bytes_le=bytes(data[pos:pos+16])))
        if guid in wanted:
            if guid in found:
                raise RecoveryError("Ambiguous HFDM: duplicate password-region GUID.")
            found[guid] = struct.unpack_from("<QQ", data, pos+32)
    if found != wanted:
        raise RecoveryError("Unsupported or incomplete password-region map; no fallback offsets are used.")
    trailer_offset = REGIONS[1][1] + REGIONS[1][2] - 7
    trailer = data[trailer_offset:trailer_offset+7]
    if trailer[:4] != b"LSPE":
        raise RecoveryError("LSPE service record missing at its expected location.")
    if sum(trailer[:5]) != struct.unpack_from("<H", trailer, 5)[0]:
        raise RecoveryError("LSPE checksum failed; the XOR context is not trustworthy.")
    key = trailer[4]
    keymap = keymap_us()
    records = []
    region_status = []
    for index, (_, offset, size) in enumerate(REGIONS):
        region = data[offset:offset+size]
        usable = region if index == 0 else region[:-7]
        if all(byte == 0xFF for byte in usable):
            region_status.append({"index": index, "status": "erased_or_not_returned"})
            continue
        length = usable[0] ^ key
        if length > MAX_LENGTH or length+2 > len(usable):
            raise RecoveryError("Record length exceeds the investigated profile; refusing to decode further.")
        decoded = bytes(byte ^ key for byte in usable[:length+2])
        if sum(decoded) % 256:
            raise RecoveryError("Password record checksum failed; no candidates will be written.")
        if length == 0:
            region_status.append({"index": index, "status": "empty_valid_record"})
            continue
        payload = decoded[1:-1]
        rebuilt = bytes([length]) + payload + bytes([(-sum(bytes([length])+payload)) & 255])
        if bytes(byte ^ key for byte in rebuilt) != bytes(usable[:length+2]):
            raise RecoveryError("Password record re-encoding check failed.")
        mapped = all(code in keymap for code in payload)
        candidate = "".join(keymap[code] for code in payload) if mapped else None
        records.append({"region_index": index, "record_length": length,
                        "record_checksum_valid": True, "reencoding_matches": True,
                        "decoded_record_hex": decoded.hex(" "),
                        "payload_hex": payload.hex(" "),
                        "us_unshifted_candidate": candidate,
                        "uppercase_letters_candidate": candidate.upper() if mapped else None,
                        "keyboard_interpretation": "US set-1 key-position candidate" if mapped else "Unmapped bytes; no text candidate guessed"})
        region_status.append({"index": index, "status": "validated_record"})
    if not records:
        raise NoPasswordError("No nonempty password record in the returned regions. This does not prove the laptop has no password.")
    return {"profile": PROFILE, "source_sha256": hashlib.sha256(data).hexdigest(),
            "hfdm_checksum_valid": True, "lspe_checksum_valid": True,
            "region_status": region_status, "records": records,
            "warning": "SECRET, unencrypted local result. Record bytes are validated, but model/version is not authenticated. Keyboard layout, Shift/Caps state and region roles are not universally established. Do not upload this file."}


def recover_file(path, profile):
    if not path.is_file():
        raise RecoveryError("Input must be an ordinary local file.")
    with path.open("rb") as handle:
        data = handle.read(IMAGE_SIZE+1)
    return recover_bytes(data, profile)


def write_secret(path, result):
    """Exclusive local output; 0600 on POSIX, inherited directory ACL on Windows."""
    if str(path) == "-":
        raise RecoveryError("Standard-output export is disabled. Choose a private local file.")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=True)
        handle.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="local raw image; never uploaded")
    parser.add_argument("--profile", required=True, help="explicitly select GKCN65WW; no automatic firmware identification")
    parser.add_argument("--output", required=True, type=Path, help="new private local JSON file; never overwritten")
    args = parser.parse_args(argv)
    print("Warning: only the Legion 5 17ACH6H (82JY), GKCN65WW case is confirmed. Layout checks do not authenticate firmware identity.", file=sys.stderr)
    try:
        result = recover_file(args.image, args.profile)
        write_secret(args.output, result)
    except NoPasswordError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except RecoveryError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except FileExistsError:
        print("Output already exists. Nothing was overwritten; choose a new private filename.", file=sys.stderr)
        return 2
    except OSError:
        print("Local file operation failed. Check input readability and output permissions; no hardware operation was attempted.", file=sys.stderr)
        return 2
    if any(record["us_unshifted_candidate"] is None for record in result["records"]):
        print("Warning: some validated record bytes have no supported text mapping; inspect the private result.", file=sys.stderr)
    print("Recovery result written to the requested local file. It contains secrets; do not upload it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
