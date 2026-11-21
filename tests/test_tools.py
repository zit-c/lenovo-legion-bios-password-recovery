"""Synthetic tests only. No real firmware, credentials or identifiers."""
import contextlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_publication
import extract_gkcn65ww
import verify_dump


def synthetic_image():
    data = bytearray(b"\xff" * verify_dump.EXPECTED_SIZE)
    start = 0x1000
    header = bytearray(0x48)
    struct.pack_into("<Q", header, 0x20, 0x1000)
    header[0x28:0x2C] = b"_FVH"
    struct.pack_into("<H", header, 0x30, len(header))
    checksum = (-sum(x[0] for x in struct.iter_unpack("<H", header))) & 0xFFFF
    struct.pack_into("<H", header, 0x32, checksum)
    data[start:start+len(header)] = header
    start = 0xEA8000
    flash_map = bytearray(0x24 + 0x54)
    flash_map[:4] = b"HFDM"
    struct.pack_into("<III", flash_map, 4, len(flash_map), 0x24, 0x54)
    flash_map[16] = (-sum(flash_map[:28])) & 255
    data[start:start+len(flash_map)] = flash_map
    # Marker count test only; intentionally not a credential/service payload.
    data[0x9000:0x9004] = b"LSPE"
    return data


class VerificationTests(unittest.TestCase):
    def test_valid_synthetic_structure(self):
        result = verify_dump.inspect_bytes(synthetic_image())
        self.assertTrue(result["preliminary_checks_passed"])
        self.assertEqual(result["valid_fv_header_count"], 1)
        self.assertTrue(result["hfdm_at_profile_offset"])
        self.assertEqual(result["lspe_marker_count"], 1)
        self.assertNotIn("file", result)

    def test_broken_fv_checksum(self):
        data = synthetic_image()
        data[0x1000] ^= 1
        self.assertEqual(verify_dump.inspect_bytes(data)["valid_fv_header_count"], 0)

    def test_out_of_bounds_volume(self):
        data = synthetic_image()
        struct.pack_into("<Q", data, 0x1020, len(data) * 2)
        result = verify_dump.inspect_bytes(data)
        self.assertFalse(result["firmware_volume_candidates"][0]["header_bounds_ok"])

    def test_invalid_hfdm_geometry(self):
        data = synthetic_image()
        struct.pack_into("<I", data, 0xEA800C, 0)
        self.assertFalse(verify_dump.inspect_bytes(data)["hfdm_candidates"][0]["geometry_ok"])

    def test_truncated_and_uniform_inputs(self):
        for data in (b"", b"\xff" * 32, b"\0" * 100, b"_FVHHFDMLSPE"):
            with self.subTest(length=len(data)):
                self.assertFalse(verify_dump.inspect_bytes(data)["preliminary_checks_passed"])

    def test_cli_error_does_not_print_input_path(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as raised:
            verify_dump.main(["not-a-real-private-file.bin"])
        self.assertEqual(raised.exception.code, 2)
        self.assertNotIn("not-a-real-private-file", error.getvalue())

    def test_file_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic.bin"
            path.write_bytes(b"not firmware")
            verify_dump.inspect_file(path)
            self.assertEqual(path.read_bytes(), b"not firmware")


class ExtractorTests(unittest.TestCase):
    def test_rejects_unrecognized_package_before_decompression(self):
        with self.assertRaises(ValueError):
            extract_gkcn65ww.reconstruct(b"synthetic input, not a vendor image")


class AuditTests(unittest.TestCase):
    def make_project(self, root, text="Synthetic documentation.\n"):
        (root / "PUBLISH_FILES").write_text("PUBLISH_FILES\nREADME.md\n", encoding="utf-8")
        (root / "README.md").write_text(text, encoding="utf-8")

    def test_accepts_text_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_project(root)
            self.assertEqual(audit_publication.inspect_publication(root), [])

    def test_accepts_https_source_link(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_project(root, "Source: https://example.org/reference\n")
            self.assertEqual(audit_publication.inspect_publication(root), [])

    def test_rejects_synthetic_token(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_project(root, "ghp_" + "X" * 30)
            self.assertTrue(audit_publication.inspect_publication(root))

    def test_rejects_unknown_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_project(root)
            (root / "unexpected.bin").write_bytes(b"synthetic")
            self.assertTrue(audit_publication.inspect_publication(root))

    def test_does_not_read_private_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_project(root)
            (root / "private").mkdir()
            (root / "private" / "not-for-publication.bin").write_bytes(b"synthetic")
            self.assertEqual(audit_publication.inspect_publication(root), [])

    def test_rejects_absolute_path_text(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_project(root, "Z" + chr(58) + chr(92) + "People" + chr(92) + "Example")
            self.assertTrue(audit_publication.inspect_publication(root))

    def test_rejects_binary_disguised_as_text(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_project(root)
            (root / "README.md").write_bytes(b"MZ\0synthetic")
            self.assertTrue(audit_publication.inspect_publication(root))

    def test_rejects_inventory_traversal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_project(root)
            (root / "PUBLISH_FILES").write_text("../not-public.md\n", encoding="utf-8")
            self.assertTrue(audit_publication.inspect_publication(root))


if __name__ == "__main__":
    unittest.main()
