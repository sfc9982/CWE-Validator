"""Bootstrap behavior without package-manager or Docker daemon side effects."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("bash"), "Bash required")
class SetupTests(unittest.TestCase):
    def bash(self, command, *args, env=None):
        return subprocess.run(
            ["bash", "-c", command, "test", *map(str, args)],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    def test_distribution_package_plans(self):
        distributions = [
            ("ubuntu", "debian", "24.04", "apt", "python3-venv", "libclang-rt-dev", "curl"),
            ("debian", "", "12", "apt", "python3-venv", "libclang-rt-dev", "curl"),
            ("linuxmint", "ubuntu debian", "22", "apt", "python3-venv", "libclang-rt-dev", "curl"),
            ("fedora", "", "43", "dnf", "python3", "compiler-rt", "curl"),
            ("rocky", "rhel centos fedora", "9.6", "dnf", "python3.11", "compiler-rt", "curl-minimal"),
            ("almalinux", "rhel centos fedora", "9.6", "dnf", "python3.11", "compiler-rt", "curl-minimal"),
            ("rhel", "fedora", "9.6", "dnf", "python3.11", "compiler-rt", "curl-minimal"),
            ("arch", "", "rolling", "pacman", "python", "compiler-rt", "curl"),
            ("manjaro", "arch", "rolling", "pacman", "python", "compiler-rt", "curl"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            release = Path(tmp) / "os-release"
            for distro, like, version, manager, python_package, runtime, curl_package in distributions:
                with self.subTest(distro=distro):
                    release.write_text(f'ID={distro}\nID_LIKE="{like}"\nVERSION_ID={version}\n')
                    result = self.bash(
                        'source "$1"; SKIP_SYSTEM=0; DRY_RUN=1; '
                        'command() { if [[ $* == "-v dnf" ]]; then return 0; '
                        'else builtin command "$@"; fi; }; '
                        'detect_distribution "$2"; select_system_packages; '
                        'printf "%s\\n" "$PM" "${SYSTEM_PACKAGES[@]}"',
                        ROOT / "scripts/setup-packages.sh",
                        release,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    packages = result.stdout.splitlines()
                    self.assertEqual(packages[0], manager)
                    self.assertIn(python_package, packages)
                    self.assertIn(runtime, packages)
                    self.assertIn(curl_package, packages)
                    if curl_package == "curl-minimal":
                        self.assertNotIn("curl", packages)

    def test_help_and_dry_run_leave_no_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            env = dict(os.environ, STATE_DIR=str(state))
            for entry in ("setup.sh", "setup-ubuntu.sh"):
                for option in ("--help", "--dry-run"):
                    result = subprocess.run(
                        ["bash", str(ROOT / "scripts" / entry), option],
                        capture_output=True,
                        text=True,
                        env=env,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(state.exists())

    def test_missing_argument_is_readable(self):
        result = self.bash('bash "$1" --python-bin', ROOT / "scripts/setup.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing value for --python-bin", result.stderr)
        self.assertNotIn("unbound variable", result.stderr)

    def test_skip_system_does_not_create_package_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.bash(
                'script=$1; test_directory=$2; set --; source "$script"; SKIP_SYSTEM=1; '
                "CONFIG_KEY=test; STEPS=(system-packages); CHECKPOINT_DIR=$test_directory; "
                'run_step system-packages; [[ ! -e "$CHECKPOINT_DIR/system-packages-test" ]]',
                ROOT / "scripts/setup.sh",
                tmp,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_nonempty_venv_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "keep.txt"
            marker.write_text("preserve this file")
            result = self.bash(
                'script=$1; test_directory=$2; set --; source "$script"; '
                "VENV_DIR=$test_directory; step_venv",
                ROOT / "scripts/setup.sh",
                tmp,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to overwrite", result.stderr)
            self.assertEqual(marker.read_text(), "preserve this file")

    def test_repeated_runs_do_not_skip_dynamic_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.bash(
                'script=$1; test_directory=$2; set --; source "$script"; '
                "CHECKPOINT_DIR=$test_directory; CONFIG_KEY=test; "
                'touch "$CHECKPOINT_DIR/python-test" "$CHECKPOINT_DIR/preflight-test"; '
                "! step_done python && ! step_done preflight",
                ROOT / "scripts/setup.sh",
                tmp,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_docker_mounts_and_privilege_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            docker = directory / "docker"
            docker.write_text(
                f"#!{shutil.which('python3')}\n"
                "import json, os, sys\n"
                "with open(os.environ['DOCKER_CAPTURE'], 'w') as f: json.dump(sys.argv[1:], f)\n"
            )
            docker.chmod(0o755)
            capture = directory / "argv.json"
            inputs = directory / "input bundle"
            inputs.mkdir()
            env = dict(
                os.environ,
                PATH=f"{directory}{os.pathsep}{os.environ['PATH']}",
                DOCKER_CAPTURE=str(capture),
                CWE_DOCKER_OUTPUT=str(directory / "evidence output"),
            )
            for full in (False, True):
                with self.subTest(full=full):
                    args = ["--full-isolation"] if full else []
                    result = subprocess.run(
                        [
                            "bash",
                            str(ROOT / "scripts/docker.sh"),
                            "run",
                            *args,
                            "--input-dir",
                            str(inputs),
                            "validate",
                            "/inputs/case.yaml",
                        ],
                        env=env,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    argv = json.loads(capture.read_text())
                    self.assertIn("none", argv)
                    self.assertIn(f"type=bind,source={inputs},target=/inputs,readonly", argv)
                    self.assertEqual("SYS_ADMIN" in argv, full)
                    self.assertEqual("seccomp=unconfined" in argv, full)
                    self.assertNotIn("--privileged", argv)
                    self.assertEqual(argv[-2:], ["validate", "/inputs/case.yaml"])
                    self.assertFalse(any("docker.sock" in arg for arg in argv))


if __name__ == "__main__":
    unittest.main()
