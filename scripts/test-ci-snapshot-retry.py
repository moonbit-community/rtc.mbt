#!/usr/bin/env python3
"""Exercise the actual pre-checkout APT step with mocked commands, without network."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"


def install_step():
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index(
        "      - name: Install dependencies from the pinned Ubuntu snapshot"
    )
    assert lines[start + 1] == "        run: |"
    body = []
    for line in lines[start + 2 :]:
        if line and not line.startswith("          "):
            break
        body.append(line[10:])
    return "\n".join(body)


MOCK_APT = '''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

log = Path(os.environ["APT_LOG"])
calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
command = "update" if "update" in sys.argv else "install"
attempt = sum(call["command"] == command for call in calls)
statuses = json.loads(os.environ[command.upper() + "_STATUSES"])
status = statuses[min(attempt, len(statuses) - 1)]
with log.open("a") as output:
    output.write(json.dumps({"command": command, "args": sys.argv[1:],
                             "frontend": os.environ.get("DEBIAN_FRONTEND"),
                             "status": status}) + "\\n")
sys.exit(status)
'''


class SnapshotRetryTest(unittest.TestCase):
    def run_case(self, update, install, expected_status, expected_waits):
        with tempfile.TemporaryDirectory(prefix="rtc-snapshot-retry-") as tmp:
            root = Path(tmp)
            apt = root / "apt-get"
            apt.write_text(MOCK_APT)
            apt.chmod(0o755)
            sleep = root / "sleep"
            sleep.write_text('#!/bin/bash\nprintf "%s\\n" "$1" >> "$SLEEP_LOG"\n')
            sleep.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{root}:{os.environ['PATH']}",
                "APT_LOG": str(root / "calls.jsonl"),
                "SLEEP_LOG": str(root / "waits.txt"),
                "UPDATE_STATUSES": json.dumps(update),
                "INSTALL_STATUSES": json.dumps(install),
                "UBUNTU_SNAPSHOT": "20260702T000000Z",
                "OPENSSL_PACKAGE_VERSION": "3.0.2-0ubuntu1.25",
            }
            script = install_step().replace(
                "/etc/apt/rtc-snapshot.list", str(root / "sources.list")
            )
            result = subprocess.run(
                ["bash", "-e", "-u", "-o", "pipefail", "-c", script],
                env=environment,
                capture_output=True,
                text=True,
            )
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, expected_status, output)
            waits = root / "waits.txt"
            self.assertEqual(
                waits.read_text().splitlines() if waits.exists() else [],
                [str(delay) for delay in expected_waits],
            )
            calls = [
                json.loads(line)
                for line in (root / "calls.jsonl").read_text().splitlines()
            ]
            for command, statuses in (("update", update), ("install", install)):
                actual = [call for call in calls if call["command"] == command]
                self.assertEqual([call["status"] for call in actual], statuses, output)
                for attempt, call in enumerate(actual, 1):
                    self.assertIn(f"APT attempt {attempt}/4", output)
                    self.assertIn(f"exit {call['status']}", output)
                    self.assertIn("Acquire::https::Timeout=30", call["args"])
                    self.assertIn("Acquire::Retries=0", call["args"])
                    self.assertIn(
                        "Acquire::https::CAInfo=/opt/bootstrap-ca.pem", call["args"]
                    )
                    if command == "update":
                        self.assertIn("APT::Update::Error-Mode=any", call["args"])
                    else:
                        self.assertEqual(call["frontend"], "noninteractive")
                        for package in ("openssl", "libssl3", "libssl-dev"):
                            self.assertIn(
                                f"{package}=3.0.2-0ubuntu1.25", call["args"]
                            )
            sources = (root / "sources.list").read_text()
            self.assertEqual(
                sources.count("https://snapshot.ubuntu.com/ubuntu/20260702T000000Z"),
                3,
            )

    def test_first_attempt_success(self):
        self.run_case([0], [0], 0, [])

    def test_transient_failures_in_both_commands(self):
        self.run_case([71, 72, 73, 0], [81, 0], 0, [5, 10, 20, 5])

    def test_update_exhausted_skips_install(self):
        self.run_case([71, 72, 73, 74], [], 74, [5, 10, 20])

    def test_install_exhausted(self):
        self.run_case([0], [81, 82, 83, 84], 84, [5, 10, 20])


if __name__ == "__main__":
    unittest.main()
