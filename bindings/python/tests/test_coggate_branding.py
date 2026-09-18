import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PYTHON_ROOT = ROOT / "bindings" / "python"
SRC = PYTHON_ROOT / "src"
sys.path.insert(0, str(SRC))


class CogGateBrandingTests(unittest.TestCase):
    def test_distribution_package_and_minimal_sdk_use_coggate(self):
        metadata = (PYTHON_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('name = "coggate"', metadata)

        import coggate

        request = coggate.IssueRequest.v1(b"binding")
        self.assertEqual(request.version, "1.0")
        self.assertEqual(request.binding, b"binding")

    def test_legacy_package_directory_is_absent(self):
        legacy = "agent" + "gate"
        self.assertFalse((SRC / legacy).exists())


if __name__ == "__main__":
    unittest.main()
