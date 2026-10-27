"""Optional Linux startup check: set NEURAI_GUI_BINARY to an exported binary."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.environ.get("NEURAI_GUI_BINARY") and shutil.which("xvfb-run"),
                     "Set NEURAI_GUI_BINARY and install xvfb-run to check GUI startup")
class GuiStartupTests(unittest.TestCase):
    def test_version_starts_without_qt_or_fontconfig_warnings(self):
        binary = Path(os.environ["NEURAI_GUI_BINARY"]).resolve()
        with tempfile.TemporaryDirectory(prefix="neurai-gui-startup-") as tmp:
            root = Path(tmp)
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            data = root / "data"
            data.mkdir()
            environment = dict(
                os.environ,
                QT_QPA_PLATFORM="xcb",
                QT_FATAL_WARNINGS="1",
                XDG_RUNTIME_DIR=str(runtime),
                XDG_CONFIG_HOME=str(root / "config"),
                XDG_CACHE_HOME=str(root / "cache"),
                LC_ALL="C.UTF-8",
            )
            result = subprocess.run(
                ["xvfb-run", "-a", str(binary), "-version", "-regtest", f"-datadir={data}"],
                env=environment, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Neurai", result.stdout)
            self.assertEqual(result.stderr.strip(), "", result.stderr)
