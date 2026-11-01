import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import package_release as release


class PackagingTests(unittest.TestCase):
    def test_json_stream(self):
        self.assertEqual(release.json_documents('{"Path":"a"}\n{"Path":"b"}'),
                         [{"Path": "a"}, {"Path": "b"}])
        with self.assertRaises(json.JSONDecodeError):
            release.json_documents('{"Path":')

    def test_missing_license_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "No distribution license"):
                release.copy_notices(directory, directory / "out", "example")

    def test_notices_preserve_original_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "LICENSE").write_text("Original copyright and terms\n")
            (directory / "NOTICE").write_text("Original notice\n")
            output = directory / "out"
            files = release.copy_notices(directory, output, "example")
            self.assertEqual(files, ["LICENSE", "NOTICE"])
            self.assertEqual((output / "LICENSE").read_bytes(), (directory / "LICENSE").read_bytes())

    def test_archive_has_normalized_metadata_and_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            bundle = directory / "file-drop-example"
            (bundle / "bin").mkdir(parents=True)
            (bundle / "bin/filedrop").write_bytes(b"executable")
            (bundle / "LICENSE").write_text("Example license\n")
            first, second = directory / "first.tar.gz", directory / "second.tar.gz"
            release.archive(bundle, first, 123456)
            release.archive(bundle, second, 123456)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive:
                members = archive.getmembers()
                self.assertTrue(all(item.uid == item.gid == 0 and item.mtime == 123456 for item in members))
                self.assertEqual(archive.getmember("file-drop-example/bin/filedrop").mode, 0o755)
                self.assertEqual(archive.getmember("file-drop-example/LICENSE").mode, 0o644)
                self.assertEqual(archive.extractfile("file-drop-example/bin/filedrop").read(), b"executable")

    def test_archive_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            bundle = directory / "bundle"
            bundle.mkdir()
            (bundle / "link").symlink_to(directory)
            with self.assertRaisesRegex(RuntimeError, "symlinks"):
                release.archive(bundle, directory / "bad.tar.gz", 0)

    def test_dirty_tree_is_not_a_release(self):
        with patch.object(release.sys, "platform", "darwin"), patch.object(release, "run", return_value=" M README.md"):
            with self.assertRaisesRegex(RuntimeError, "clean worktree"):
                release.package("v0.1.0", Path("unused-output"))

    def test_invalid_version_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "release tag"):
            release.package("../invalid", Path("unused-output"))


if __name__ == "__main__":
    unittest.main()
