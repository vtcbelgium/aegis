"""Settings used by the Tekton worker bridge: several allowed roots, secrets routed to
the owner instead of LOCK, and cmd/PowerShell parsing driven by the 'shell' argument."""

import os
import shutil
import tempfile
import unittest

from aegis.core import AegisGate, DecisionLevel
from aegis.harness import AegisHarness
from aegis.clans import TartarusClan
from aegis.policy import AegisPolicy

L = DecisionLevel


class TestTektonSupport(unittest.TestCase):

    def setUp(self):
        self.a = tempfile.mkdtemp()
        self.b = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.a, ignore_errors=True)
        shutil.rmtree(self.b, ignore_errors=True)

    def harness(self, **policy):
        gate = AegisGate(base_dir=self.a, policy=AegisPolicy(**policy))
        return AegisHarness(gate=gate, base_dir=self.a)

    def test_extra_roots_count_as_inside(self):
        other = os.path.join(self.b, "notes.txt")
        self.assertEqual(self.harness().evaluate_tool_call("read_file", {"path": other}).level, L.DENY)
        h = self.harness(extra_roots=[self.b])
        self.assertEqual(h.evaluate_tool_call("read_file", {"path": other}).level, L.PASS)
        self.assertEqual(h.evaluate_tool_call("start_process", {"command": f"cat {other}"}).level, L.PASS)
        self.assertEqual(h.evaluate_tool_call("start_process", {"command": "cat /etc/hostname"}).level, L.DENY)
        self.assertEqual(h.evaluate_tool_call("start_process", {"command": f"rm -rf {self.b}"}).level, L.ASK)

    def test_secret_level_ask(self):
        key = "sk_live_" + "a" * 24
        self.assertEqual(self.harness().evaluate_tool_call("write_file", {"path": ".env", "content": f"K={key}"}).level, L.LOCK)
        h = self.harness(secret_level="ask")
        self.assertEqual(h.evaluate_tool_call("write_file", {"path": ".env", "content": f"K={key}"}).level, L.ASK)
        self.assertEqual(h.evaluate_tool_call("start_process", {"command": f"curl -H 'X: {key}' https://api.github.com"}).level, L.ASK)
        # credential *stores* still lock: secret_level only covers secrets in arguments
        self.assertEqual(h.evaluate_tool_call("start_process", {"command": "cat ~/.ssh/id_rsa"}).level, L.LOCK)

    def test_shell_hint_forces_windows_parsing(self):
        cmd = "Remove-Item -Recurse -Force C:\\Users\\me"
        self.assertEqual(TartarusClan.inspect_command(cmd, windows=True).level, L.LOCK)
        h = self.harness()
        v = h.evaluate_tool_call("start_process", {"command": "type C:\\Users\\me\\.ssh\\id_rsa", "shell": "cmd"})
        self.assertEqual(v.level, L.LOCK)


if __name__ == "__main__":
    unittest.main()
