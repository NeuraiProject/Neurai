#!/usr/bin/env python3
"""Test build.sh orchestration without compiling or requiring a Docker daemon."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class BuildScriptTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="neurai-build-test-")
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        checkout = self.root / "checkout with spaces"
        checkout.mkdir()
        self.script = checkout / "build.sh"
        shutil.copy2(Path(__file__).resolve().parents[1] / "build.sh", self.script)
        self.output = checkout / "tests/output"
        self.working_directory = self.root / "working directory"
        self.working_directory.mkdir()
        self.capture = self.root / "docker-calls.jsonl"
        tool_dir = self.root / "tools"
        tool_dir.mkdir()
        docker = tool_dir / "docker"
        docker.write_text('''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys

with open(os.environ["NEURAI_TEST_CAPTURE"], "a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
if sys.argv[1] == "build":
    mode = os.environ.get("NEURAI_TEST_MODE")
    if mode == "edit-script":
        script = Path(os.environ["NEURAI_TEST_SCRIPT"])
        script.write_text(script.read_text().replace(
            '--volume "$output_dir:/output" "$image"',
            '--volume "$output_dir:/output" "$image',
        ))
        assert subprocess.run(["bash", "-n", str(script)],
                              capture_output=True).returncode != 0
    elif mode == "fail-build":
        sys.exit(17)
''')
        docker.chmod(0o755)
        self.environment = dict(
            os.environ,
            PATH=str(tool_dir) + os.pathsep + os.environ["PATH"],
            SOURCE_COMMIT="a" * 40,
            JOBS="2",
            IMAGE="neurai-build-test:local",
            NEURAI_TEST_SCRIPT=str(self.script),
            NEURAI_TEST_CAPTURE=str(self.capture),
        )
        self.environment.pop("NEURAI_TEST_MODE", None)
        self.environment.pop("OUTPUT_DIR", None)

    def run_build(self, *arguments, mode=None, working_directory=None, extra_environment=None):
        environment = dict(self.environment)
        if mode:
            environment["NEURAI_TEST_MODE"] = mode
        if extra_environment:
            environment.update(extra_environment)
        return subprocess.run(
            ["bash", str(self.script), *arguments],
            cwd=working_directory or self.working_directory,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def docker_calls(self):
        if not self.capture.exists():
            return []
        return [json.loads(line) for line in self.capture.read_text().splitlines()]

    def test_script_edit_during_build_does_not_interrupt_extraction(self):
        result = self.run_build("linux", "DePIN-Test", "user", mode="edit-script")
        self.assertEqual(result.returncode, 0, result.stderr)
        build, run = self.docker_calls()
        self.assertEqual(build[0], "build")
        self.assertEqual(run[0], "run")
        self.assertEqual(run[run.index("--volume") + 1], str(self.output) + ":/output")
        self.assertIn("Output: " + str(self.output), result.stdout)

    def test_invalid_extraction_syntax_fails_before_building(self):
        self.script.write_text(self.script.read_text().replace(
            '--volume "$output_dir:/output" "$image"',
            '--volume "$output_dir:/output" "$image',
        ))
        result = self.run_build("linux", "DePIN-Test", "user")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.docker_calls(), [])

    def test_failed_build_does_not_extract(self):
        result = self.run_build("linux", mode="fail-build")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual([call[0] for call in self.docker_calls()], ["build"])

    def test_output_location_is_fixed_for_all_platforms(self):
        unexpected_output = self.root / "unexpected output"
        for arguments, working_directory in (
            (("linux",), self.working_directory),
            (("windows",), self.script.parent),
            (("macos", "DePIN-Test", "user", "arm64"), self.root),
        ):
            with self.subTest(arguments=arguments):
                self.capture.unlink(missing_ok=True)
                result = self.run_build(
                    *arguments,
                    working_directory=working_directory,
                    extra_environment={"OUTPUT_DIR": str(unexpected_output)},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                _, run = self.docker_calls()
                self.assertEqual(run[run.index("--volume") + 1], str(self.output) + ":/output")
                self.assertTrue(self.output.is_dir())
                self.assertFalse(unexpected_output.exists())

    def test_no_cache_is_only_forwarded_to_build(self):
        for arguments in (
            ("linux", "--no-cache"),
            ("--no-cache", "macos", "DePIN-Test", "user", "arm64"),
        ):
            with self.subTest(arguments=arguments):
                self.capture.unlink(missing_ok=True)
                result = self.run_build(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                build, run = self.docker_calls()
                self.assertIn("--no-cache", build)
                self.assertNotIn("--no-cache", run)


if __name__ == "__main__":
    unittest.main()
