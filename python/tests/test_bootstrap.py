"""Offline unit tests for the PyPI wrapper bootstrap.

No network access: every test that would touch GitHub Releases patches
``_bootstrap.download`` to raise, so an accidental fetch fails loudly.

Run with:  python3 -m unittest discover -s python/tests
"""

import hashlib
import io
import os
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import sigil_cli  # noqa: E402
from sigil_cli import _bootstrap  # noqa: E402
from sigil_cli._bootstrap import BootstrapError  # noqa: E402


def _no_network(url, version=None):
    raise AssertionError("unexpected download attempt: %s" % url)


class AssetNameTests(unittest.TestCase):
    def test_platform_mapping(self):
        cases = {
            ("Darwin", "x86_64"): "sigil-macos-x64.tar.gz",
            ("Darwin", "arm64"): "sigil-macos-arm64.tar.gz",
            ("Linux", "x86_64"): "sigil-linux-x64.tar.gz",
            ("Linux", "aarch64"): "sigil-linux-arm64.tar.gz",
            ("Linux", "arm64"): "sigil-linux-arm64.tar.gz",
            ("Windows", "AMD64"): "sigil-windows-x64.zip",
            ("Windows", "x86_64"): "sigil-windows-x64.zip",
        }
        for (system, machine), expected in cases.items():
            with self.subTest(system=system, machine=machine):
                self.assertEqual(_bootstrap.asset_name(system, machine), expected)

    def test_unsupported_platform_fails_closed(self):
        for system, machine in [
            ("Linux", "i686"),
            ("FreeBSD", "x86_64"),
            ("Windows", "ARM64"),
            ("Linux", ""),
        ]:
            with self.subTest(system=system, machine=machine):
                with self.assertRaises(BootstrapError) as ctx:
                    _bootstrap.asset_name(system, machine)
                self.assertIn("unsupported platform", str(ctx.exception))

    def test_uses_host_platform_by_default(self):
        with (
            mock.patch.object(_bootstrap.platform, "system", return_value="Linux"),
            mock.patch.object(_bootstrap.platform, "machine", return_value="x86_64"),
        ):
            self.assertEqual(_bootstrap.asset_name(), "sigil-linux-x64.tar.gz")

    def test_asset_table_matches_release_matrix(self):
        # Every asset the release workflow publishes must be reachable.
        self.assertEqual(
            sorted(_bootstrap.ASSETS.values()),
            sorted(
                [
                    "sigil-macos-x64.tar.gz",
                    "sigil-macos-arm64.tar.gz",
                    "sigil-linux-x64.tar.gz",
                    "sigil-linux-arm64.tar.gz",
                    "sigil-windows-x64.zip",
                ]
            ),
        )


class VersionAndPathTests(unittest.TestCase):
    def test_default_version_is_package_version(self):
        self.assertEqual(_bootstrap.resolve_version({}), sigil_cli.__version__)

    def test_sigil_version_override_strips_v_prefix(self):
        self.assertEqual(
            _bootstrap.resolve_version({"SIGIL_VERSION": "v1.2.3"}), "1.2.3"
        )
        self.assertEqual(
            _bootstrap.resolve_version({"SIGIL_VERSION": "1.2.3"}), "1.2.3"
        )
        self.assertEqual(
            _bootstrap.resolve_version({"SIGIL_VERSION": "  "}), sigil_cli.__version__
        )

    def test_version_looks_like_semver(self):
        parts = sigil_cli.__version__.split(".")
        self.assertEqual(len(parts), 3)
        self.assertTrue(all(p.isdigit() for p in parts))

    def test_cached_binary_path(self):
        env = {"SIGIL_HOME": os.path.join("tmp", "sigil-home")}
        posix = _bootstrap.cached_binary_path("1.3.6", env, system="Linux")
        self.assertEqual(posix, os.path.join("tmp", "sigil-home", "bin", "sigil-1.3.6"))
        win = _bootstrap.cached_binary_path("1.3.6", env, system="Windows")
        self.assertEqual(
            win, os.path.join("tmp", "sigil-home", "bin", "sigil-1.3.6.exe")
        )

    def test_default_home_is_dot_sigil(self):
        self.assertEqual(
            _bootstrap.sigil_home({}), os.path.join(os.path.expanduser("~"), ".sigil")
        )


class ChecksumTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.payload = b"not really a binary, but stable bytes\n" * 100
        self.path = os.path.join(self.tmp.name, "sigil-linux-x64.tar.gz")
        with open(self.path, "wb") as handle:
            handle.write(self.payload)
        self.digest = hashlib.sha256(self.payload).hexdigest()

    def test_expected_hash_parses_sha256sum_output(self):
        text = (
            "0000000000000000000000000000000000000000000000000000000000000000  sigil-macos-arm64.tar.gz\n"
            "%s  sigil-linux-x64.tar.gz\n"
            "1111111111111111111111111111111111111111111111111111111111111111 *sigil-windows-x64.zip\n"
        ) % self.digest
        self.assertEqual(
            _bootstrap.expected_hash(text, "sigil-linux-x64.tar.gz"), self.digest
        )
        self.assertEqual(
            _bootstrap.expected_hash(text, "sigil-windows-x64.zip"), "1" * 64
        )

    def test_expected_hash_handles_crlf_and_blank_lines(self):
        text = "\r\n%s  sigil-linux-x64.tar.gz\r\n\r\n" % self.digest.upper()
        self.assertEqual(
            _bootstrap.expected_hash(text, "sigil-linux-x64.tar.gz"), self.digest
        )

    def test_expected_hash_missing_entry_fails_closed(self):
        with self.assertRaises(BootstrapError) as ctx:
            _bootstrap.expected_hash(
                "%s  something-else.tar.gz\n" % self.digest, "sigil-linux-x64.tar.gz"
            )
        self.assertIn("checksum missing", str(ctx.exception))

    def test_expected_hash_does_not_match_on_suffix(self):
        # "x-sigil-linux-x64.tar.gz" must not satisfy "sigil-linux-x64.tar.gz".
        with self.assertRaises(BootstrapError):
            _bootstrap.expected_hash(
                "%s  x-sigil-linux-x64.tar.gz\n" % self.digest, "sigil-linux-x64.tar.gz"
            )

    def test_verify_file_against_temp_file(self):
        self.assertTrue(_bootstrap.verify_file(self.path, self.digest))
        self.assertTrue(_bootstrap.verify_file(self.path, self.digest.upper()))

    def test_verify_file_mismatch_fails_closed(self):
        with self.assertRaises(BootstrapError) as ctx:
            _bootstrap.verify_file(self.path, "0" * 64)
        message = str(ctx.exception)
        self.assertIn("checksum mismatch", message)
        self.assertIn("Refusing to install", message)

    def test_verify_checksum_bytes(self):
        self.assertTrue(_bootstrap.verify_checksum(self.payload, self.digest))
        with self.assertRaises(BootstrapError):
            _bootstrap.verify_checksum(self.payload + b"x", self.digest)


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.binary = b"#!/bin/sh\necho sigil-fake\n"

    def _tarball(self, member="sigil"):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(member)
            info.size = len(self.binary)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(self.binary))
        return buf.getvalue()

    def _zip(self, member="sigil.exe"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as bundle:
            bundle.writestr(member, self.binary)
        return buf.getvalue()

    def test_install_from_tarball_sets_exec_bit(self):
        dest = os.path.join(self.tmp.name, "bin", "sigil-9.9.9")
        _bootstrap.install_from_archive(self._tarball(), "sigil-linux-x64.tar.gz", dest)
        with open(dest, "rb") as handle:
            self.assertEqual(handle.read(), self.binary)
        if os.name == "posix":
            self.assertTrue(os.stat(dest).st_mode & stat.S_IXUSR)
        # No temp file left behind next to the binary.
        self.assertEqual(sorted(os.listdir(os.path.dirname(dest))), ["sigil-9.9.9"])

    def test_install_from_zip(self):
        dest = os.path.join(self.tmp.name, "bin", "sigil-9.9.9.exe")
        _bootstrap.install_from_archive(self._zip(), "sigil-windows-x64.zip", dest)
        with open(dest, "rb") as handle:
            self.assertEqual(handle.read(), self.binary)

    def test_archive_without_binary_fails_closed(self):
        dest = os.path.join(self.tmp.name, "bin", "sigil-9.9.9")
        with self.assertRaises(BootstrapError) as ctx:
            _bootstrap.install_from_archive(
                self._tarball("README"), "sigil-linux-x64.tar.gz", dest
            )
        self.assertIn("does not contain sigil", str(ctx.exception))
        self.assertFalse(os.path.exists(dest))


class EnsureBinaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(_bootstrap, "download", side_effect=_no_network)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_sigil_binary_short_circuits(self):
        override = os.path.join(self.tmp.name, "sigil-local")
        with open(override, "wb") as handle:
            handle.write(b"local build")
        env = {"SIGIL_BINARY": override, "SIGIL_HOME": self.tmp.name}
        self.assertEqual(_bootstrap.ensure_binary(env), override)

    def test_sigil_binary_missing_file_is_an_error(self):
        env = {
            "SIGIL_BINARY": os.path.join(self.tmp.name, "nope"),
            "SIGIL_HOME": self.tmp.name,
        }
        with self.assertRaises(BootstrapError) as ctx:
            _bootstrap.ensure_binary(env)
        self.assertIn("SIGIL_BINARY", str(ctx.exception))

    def test_cached_binary_is_reused_without_download(self):
        env = {"SIGIL_HOME": self.tmp.name, "SIGIL_VERSION": "v0.0.1"}
        cached = _bootstrap.cached_binary_path("0.0.1", env)
        os.makedirs(os.path.dirname(cached))
        with open(cached, "wb") as handle:
            handle.write(b"cached")
        self.assertEqual(_bootstrap.ensure_binary(env), cached)

    def test_fetch_is_attempted_when_cache_is_cold(self):
        env = {"SIGIL_HOME": self.tmp.name, "SIGIL_VERSION": "0.0.2"}
        with mock.patch.object(
            _bootstrap, "fetch_binary", return_value="fetched"
        ) as fetch:
            self.assertEqual(_bootstrap.ensure_binary(env), "fetched")
        fetch.assert_called_once_with(
            "0.0.2", _bootstrap.cached_binary_path("0.0.2", env)
        )


class FetchBinaryTests(unittest.TestCase):
    """End-to-end bootstrap with the network replaced by an in-memory release."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.binary = b"#!/bin/sh\necho ok\n"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo("sigil")
            info.size = len(self.binary)
            tar.addfile(info, io.BytesIO(self.binary))
        self.archive = buf.getvalue()
        self.asset = "sigil-linux-x64.tar.gz"
        self.urls = []

    def _fake_release(self, checksum):
        def fake_download(url, version=None):
            self.urls.append(url)
            if url.endswith("/SHA256SUMS.txt"):
                return ("%s  %s\n" % (checksum, self.asset)).encode()
            if url.endswith("/" + self.asset):
                return self.archive
            raise BootstrapError("release asset not found (404): %s" % url)

        return fake_download

    def test_downloads_verifies_and_installs(self):
        dest = os.path.join(self.tmp.name, "bin", "sigil-1.3.6")
        good = hashlib.sha256(self.archive).hexdigest()
        with mock.patch.object(
            _bootstrap, "download", side_effect=self._fake_release(good)
        ):
            self.assertEqual(_bootstrap.fetch_binary("1.3.6", dest, self.asset), dest)
        with open(dest, "rb") as handle:
            self.assertEqual(handle.read(), self.binary)
        self.assertEqual(
            self.urls,
            [
                "https://github.com/NOMARJ/sigil/releases/download/v1.3.6/sigil-linux-x64.tar.gz",
                "https://github.com/NOMARJ/sigil/releases/download/v1.3.6/SHA256SUMS.txt",
            ],
        )

    def test_tampered_archive_is_rejected_and_not_installed(self):
        dest = os.path.join(self.tmp.name, "bin", "sigil-1.3.6")
        with mock.patch.object(
            _bootstrap, "download", side_effect=self._fake_release("f" * 64)
        ):
            with self.assertRaises(BootstrapError) as ctx:
                _bootstrap.fetch_binary("1.3.6", dest, self.asset)
        self.assertIn("checksum mismatch", str(ctx.exception))
        self.assertFalse(os.path.exists(dest))

    def test_missing_release_surfaces_404_message(self):
        dest = os.path.join(self.tmp.name, "bin", "sigil-0.0.0")
        with mock.patch.object(
            _bootstrap, "download", side_effect=self._fake_release("a" * 64)
        ):
            with self.assertRaises(BootstrapError) as ctx:
                _bootstrap.fetch_binary("0.0.0", dest, "sigil-macos-arm64.tar.gz")
        self.assertIn("404", str(ctx.exception))


class MainTests(unittest.TestCase):
    def test_main_reports_bootstrap_errors_with_exit_1(self):
        from sigil_cli.__main__ import main

        stderr = io.StringIO()
        with (
            mock.patch.object(
                _bootstrap, "ensure_binary", side_effect=BootstrapError("boom")
            ),
            mock.patch("sigil_cli.__main__.run", side_effect=BootstrapError("boom")),
            mock.patch("sys.stderr", stderr),
        ):
            self.assertEqual(main(["scan", "."]), 1)
        self.assertEqual(stderr.getvalue(), "sigil: boom\n")

    def test_run_hands_argv_to_binary(self):
        calls = []

        def fake_execv(path, args):
            calls.append((path, args))
            raise SystemExit(0)  # execv would never return

        with (
            mock.patch.object(_bootstrap, "ensure_binary", return_value="/opt/sigil"),
            mock.patch.object(_bootstrap, "is_windows", return_value=False),
            mock.patch.object(_bootstrap.os, "execv", side_effect=fake_execv),
        ):
            with self.assertRaises(SystemExit):
                _bootstrap.run(["scan", ".", "--no-cache"])
        self.assertEqual(
            calls, [("/opt/sigil", ["/opt/sigil", "scan", ".", "--no-cache"])]
        )

    def test_run_on_windows_returns_subprocess_exit_code(self):
        with (
            mock.patch.object(
                _bootstrap, "ensure_binary", return_value="C:\\sigil.exe"
            ),
            mock.patch.object(_bootstrap, "is_windows", return_value=True),
            mock.patch.object(_bootstrap.subprocess, "call", return_value=3) as call,
        ):
            self.assertEqual(_bootstrap.run(["--version"]), 3)
        call.assert_called_once_with(["C:\\sigil.exe", "--version"])


if __name__ == "__main__":
    unittest.main()
