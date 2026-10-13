"""Archive and manifest regressions at the release trust boundary."""

import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from artifacts import MANIFEST, canonical, digest, inventory, source_digest, tar_gz, unpack, verify_inventory, verify_source, write_json, zip_archive


class ArtifactsTests(unittest.TestCase):
    def test_wheel_record_cannot_reference_files_outside_its_inventory(self):
        from apple_metadata import normalize_wheel
        for entries in ("../outside,,\n", "/outside,,\n", "module.py,,\nmodule.py,,\n", ""):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tree = root / "wheel"
                info = tree / "sdk.dist-info"
                info.mkdir(parents=True)
                (root / "outside").write_text("outside the wheel")
                (tree / "module.py").write_text("pass\n")
                (info / "RECORD").write_text(entries + "sdk.dist-info/RECORD,,\n")
                with self.assertRaises(ValueError):
                    normalize_wheel(tree, root)

    def test_source_digest_matches_the_shared_release_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "dir").mkdir()
            (root / "empty").mkdir()
            (root / "a").write_bytes(b"first")
            (root / "a").chmod(0o755)
            (root / "dir.txt").write_bytes(b"")
            (root / "dir" / "z").write_bytes(b"payload\0\xff")
            # The same value the gateway and catalog release tooling compute.
            self.assertEqual(source_digest(root), "887904a1ae03e4449f05e05fb147314cf9c8c428d3eec00179e0d7f56fc3a853")

    def test_consumer_source_cannot_drift_from_packaged_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            fixture = source / "fixture"
            fixture.write_bytes(b"expected")
            fixture.chmod(0o755)
            expected = source_digest(source)
            archive = root / "source.tar.gz"
            tar_gz(archive, source, 1700000000, "sdk")
            # NTFS copies need not preserve Unix executable bits.
            fixture.chmod(0o644)
            verify_source(source, archive, expected, "sdk")
            fixture.write_bytes(b"modified")
            with self.assertRaises(ValueError):
                verify_source(source, archive, expected, "sdk")
            fixture.write_bytes(b"expected")
            (source / "unbound-fixture").write_bytes(b"extra")
            with self.assertRaises(ValueError):
                verify_source(source, archive, expected, "sdk")
            (source / "unbound-fixture").unlink()
            with self.assertRaises(ValueError):
                verify_source(source, archive, "0" * 64, "sdk")

    def test_archives_ignore_input_time_and_permission_noise(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "z").write_bytes(b"payload\0\xff")
            (source / "a").write_text("first")
            (source / "a").chmod(0o755)
            for pack, suffix in ((tar_gz, ".tar.gz"), (zip_archive, ".zip")):
                with self.subTest(suffix=suffix):
                    first, second = root / ("first" + suffix), root / ("second" + suffix)
                    pack(first, source, 1700000000, "package")
                    os.utime(source / "z", (1800000000, 1800000000))
                    (source / "z").chmod(0o600)
                    pack(second, source, 1700000000, "package")
                    self.assertEqual(first.read_bytes(), second.read_bytes())
                    unpack(first, root / ("unpacked" + suffix))
                    actual = root / ("unpacked" + suffix) / "package"
                    self.assertEqual((actual / "z").read_bytes(), b"payload\0\xff")
                    self.assertEqual((actual / "a").stat().st_mode & 0o777, 0o755)

    def test_extraction_rejects_traversal_links_duplicates_and_total_expansion(self):
        for attack in ("../escape", "a/../escape", "/escape", "a\\escape", "C:/escape", "./escape", "a//escape", "duplicate", "link", "oversize"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "input.tar.gz"
                with tarfile.open(archive, "w:gz") as output:
                    names = ["same", "same"] if attack == "duplicate" else ["first", "second"] if attack == "oversize" else [attack]
                    for name in names:
                        member = tarfile.TarInfo(name)
                        member.size = 4
                        if attack == "link":
                            member.type = tarfile.SYMTYPE
                            member.linkname = "../escape"
                        output.addfile(member, io.BytesIO(b"data"))
                with self.assertRaises(ValueError):
                    unpack(archive, root / "output", max_bytes=7)
                self.assertFalse((root / "escape").exists())

    def test_zip_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with zipfile.ZipFile(root / "input.zip", "w") as archive:
                entry = zipfile.ZipInfo("link")
                entry.create_system = 3
                entry.external_attr = 0o120777 << 16
                archive.writestr(entry, "../escape")
            with self.assertRaises(ValueError):
                unpack(root / "input.zip", root / "output")

    def test_manifest_rejects_extra_missing_and_changed_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sdk.zip").write_bytes(b"sdk")
            manifest = {"artifacts": inventory(root, ["sdk.zip"])}
            write_json(root / MANIFEST, manifest)
            self.assertEqual(verify_inventory(root, manifest), digest(root / MANIFEST))
            (root / "extra").write_bytes(b"extra")
            with self.assertRaises(ValueError):
                verify_inventory(root, manifest)
            (root / "extra").unlink()
            (root / "sdk.zip").write_bytes(b"bad")
            with self.assertRaises(ValueError):
                verify_inventory(root, manifest)
            (root / "sdk.zip").unlink()
            with self.assertRaises(ValueError):
                verify_inventory(root, manifest)

    def test_canonical_json_matches_the_supported_rfc8785_subset(self):
        self.assertEqual(canonical({"z": [True, None, "é"], "a": 1}), b'{"a":1,"z":[true,null,"\xc3\xa9"]}')
        for value in (1.5, float("nan"), 2**53, {"é": 1}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical(value)


if __name__ == "__main__":
    unittest.main()
