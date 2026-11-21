"""Invented structures and credentials only; no private investigation fixtures."""
import contextlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import recover_bios as recovery


def fix_header(data):
    start = recovery.FDM_OFFSET
    data[start+16] = 0
    data[start+16] = (-sum(data[start:start+28])) & 255


def synthetic_image(first=bytes((0x2F, 0x0A, 0x0C)), second=None, key=0x5A):
    """Synthetic v9- key positions, unrelated to the owner's credential."""
    data = bytearray(b"\xff" * recovery.IMAGE_SIZE)
    start = recovery.FDM_OFFSET
    total, header, step = recovery.FDM_GEOMETRY
    data[start:start+total] = bytes(total)
    data[start:start+4] = b"HFDM"
    struct.pack_into("<III", data, start+4, total, header, step)
    struct.pack_into("<Q", data, start+20, 0xFF000000)
    for index, (guid, offset, size) in enumerate(recovery.REGIONS):
        entry = start + header + index*step
        data[entry:entry+16] = uuid.UUID(guid).bytes_le
        struct.pack_into("<QQ", data, entry+32, offset, size)
    fix_header(data)
    for payload, (_, offset, _) in zip((first, second), recovery.REGIONS):
        if payload is not None:
            plain = bytes([len(payload)]) + payload
            plain += bytes([(-sum(plain)) & 255])
            data[offset:offset+len(plain)] = bytes(byte ^ key for byte in plain)
    trailer = b"LSPE" + bytes([key])
    trailer += struct.pack("<H", sum(trailer))
    data[0x5AFFF9:0x5B0000] = trailer
    return data


class RecoveryTests(unittest.TestCase):
    def test_recovers_invented_key_sequence(self):
        result = recovery.recover_bytes(synthetic_image(), "GKCN65WW")
        self.assertEqual(result["records"][0]["us_unshifted_candidate"], "v9-")
        self.assertEqual(result["records"][0]["uppercase_letters_candidate"], "V9-")
        self.assertEqual(result["region_status"][1]["status"], "erased_or_not_returned")

    def test_both_regions(self):
        result = recovery.recover_bytes(synthetic_image(second=bytes((0x39,))), "GKCN65WW")
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual(result["records"][1]["us_unshifted_candidate"], " ")

    def test_unknown_mapping_is_not_guessed(self):
        result = recovery.recover_bytes(synthetic_image(first=bytes((0x7F,))), "GKCN65WW")
        self.assertIsNone(result["records"][0]["us_unshifted_candidate"])
        self.assertTrue(result["records"][0]["record_checksum_valid"])

    def test_all_erased(self):
        with self.assertRaises(recovery.NoPasswordError):
            recovery.recover_bytes(synthetic_image(first=None), "GKCN65WW")

    def test_empty_valid_record(self):
        with self.assertRaises(recovery.NoPasswordError):
            recovery.recover_bytes(synthetic_image(first=b""), "GKCN65WW")

    def test_zero_and_ff_keys(self):
        for key in (0, 255):
            with self.subTest(key=key):
                result = recovery.recover_bytes(synthetic_image(key=key), "GKCN65WW")
                self.assertEqual(result["records"][0]["us_unshifted_candidate"], "v9-")

    def test_rejects_profile_and_container_size(self):
        with self.assertRaisesRegex(recovery.RecoveryError, "Unsupported profile"):
            recovery.recover_bytes(b"", "OTHER")
        for data in (b"", b"synthetic container", bytes(recovery.IMAGE_SIZE+1)):
            with self.assertRaisesRegex(recovery.RecoveryError, "image size"):
                recovery.recover_bytes(data, "GKCN65WW")

    def test_bad_fdm_signature_geometry_checksum_base(self):
        for relative in (0, 4, 16, 20):
            with self.subTest(relative=relative):
                data = synthetic_image()
                data[recovery.FDM_OFFSET+relative] ^= 1
                if relative == 20:
                    fix_header(data)
                with self.assertRaises(recovery.RecoveryError):
                    recovery.recover_bytes(data, "GKCN65WW")

    def test_missing_duplicate_or_out_of_profile_regions(self):
        first_entry = recovery.FDM_OFFSET+0x24
        for case in ("missing", "duplicate", "offset", "size"):
            with self.subTest(case=case):
                data = synthetic_image()
                if case == "missing":
                    data[first_entry:first_entry+16] = bytes(16)
                elif case == "duplicate":
                    data[first_entry+2*0x54:first_entry+3*0x54] = data[first_entry:first_entry+0x54]
                elif case == "offset":
                    struct.pack_into("<Q", data, first_entry+32, 0xFFFFFFFFFFFFFFFF)
                else:
                    struct.pack_into("<Q", data, first_entry+40, 0x801)
                with self.assertRaises(recovery.RecoveryError):
                    recovery.recover_bytes(data, "GKCN65WW")

    def test_missing_and_bad_lspe(self):
        for offset in (0x5AFFF9, 0x5AFFFF):
            with self.subTest(offset=offset):
                data = synthetic_image()
                data[offset] ^= 1
                with self.assertRaises(recovery.RecoveryError):
                    recovery.recover_bytes(data, "GKCN65WW")

    def test_overlong_record(self):
        with self.assertRaisesRegex(recovery.RecoveryError, "length"):
            recovery.recover_bytes(synthetic_image(first=bytes((0x2F,))*17), "GKCN65WW")

    def test_record_checksum_failure(self):
        data = synthetic_image()
        data[0x5AF002] ^= 1
        with self.assertRaisesRegex(recovery.RecoveryError, "record checksum"):
            recovery.recover_bytes(data, "GKCN65WW")

    def test_cli_exclusive_secret_output_and_immutable_input(self):
        with tempfile.TemporaryDirectory() as folder:
            image = Path(folder) / "synthetic.bin"
            output = Path(folder) / "private" / "result.json"
            original = synthetic_image()
            image.write_bytes(original)
            args = [str(image), "--profile", "GKCN65WW", "--output", str(output)]
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(recovery.main(args), 0)
            self.assertEqual(json.loads(output.read_text())["records"][0]["us_unshifted_candidate"], "v9-")
            for stream in (stdout, stderr):
                self.assertNotIn("v9-", stream.getvalue())
                self.assertNotIn(str(image), stream.getvalue())
            before = output.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(recovery.main(args), 2)
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual(image.read_bytes(), original)

    def test_cli_invalid_input_creates_no_output(self):
        with tempfile.TemporaryDirectory() as folder:
            image = Path(folder) / "synthetic.bin"
            output = Path(folder) / "result.json"
            data = synthetic_image()
            data[0x5AF002] ^= 1
            image.write_bytes(data)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = recovery.main([str(image), "--profile", "GKCN65WW", "--output", str(output)])
            self.assertEqual(status, 2)
            self.assertFalse(output.exists())

    def test_stdout_export_is_rejected(self):
        with self.assertRaises(recovery.RecoveryError):
            recovery.write_secret(Path("-"), {})


if __name__ == "__main__":
    unittest.main()
