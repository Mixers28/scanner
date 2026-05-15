import importlib
import inspect
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class ScannerFoundationTests(unittest.TestCase):
    def test_module_imports(self) -> None:
        modules = [
            "scanner",
            "scanner.common",
            "scanner.common.types",
            "scanner.common.config",
            "scanner.common.identity",
            "scanner.storage",
            "scanner.collector",
            "scanner.baseline",
            "scanner.whitelist",
            "scanner.anomaly",
            "scanner.verify",
            "scanner.reporting",
            "scanner.service",
        ]
        for module in modules:
            with self.subTest(module=module):
                importlib.import_module(module)

    def test_config_validation_success(self) -> None:
        from scanner.common.config import DEFAULT_CONFIG, validate_config

        validated = validate_config(DEFAULT_CONFIG)
        self.assertEqual(30, validated["verify"]["total_timeout_seconds"])

    def test_config_validation_fails_missing_section(self) -> None:
        from scanner.common.config import validate_config

        with self.assertRaises(ValueError) as exc:
            validate_config({"collector": {}, "verify": {}, "reporting": {}})
        self.assertIn("missing required section: retention", str(exc.exception))

    def test_identity_key_signature(self) -> None:
        from scanner.common.identity import build_identity_key

        signature = inspect.signature(build_identity_key)
        self.assertNotIn("product_name", signature.parameters)

    def test_identity_key_is_stable(self) -> None:
        from scanner.common.identity import build_identity_key

        key_a = build_identity_key(
            r"C:\Program Files\Example\app.exe",
            "Microsoft Corporation",
            "ABCDEF",
        )
        key_b = build_identity_key(
            r"c:/program files/example/app.exe",
            "microsoft corporation",
            "abcdef",
        )
        self.assertEqual(key_a, key_b)

    def test_user_writable_path_detection(self) -> None:
        from scanner.common.identity import is_user_writable_dir

        self.assertTrue(
            is_user_writable_dir(r"C:\Users\alice\Downloads\weird.exe")
        )
        self.assertFalse(
            is_user_writable_dir(r"C:\Program Files\Trusted\agent.exe")
        )


if __name__ == "__main__":
    unittest.main()
