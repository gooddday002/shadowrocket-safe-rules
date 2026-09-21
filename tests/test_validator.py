import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import validator


class ValidatorTests(unittest.TestCase):
    def test_active_lines(self):
        text = "# c\n\nDOMAIN-SUFFIX,example.com\n // x\nDOMAIN,api.example.com\n"
        self.assertEqual(
            validator.active_lines(text),
            ["DOMAIN-SUFFIX,example.com", "DOMAIN,api.example.com"],
        )

    def test_domain_set_validation(self):
        self.assertEqual(
            validator.validate_domain_set(["example.com", "+.foo.example"], 100),
            [],
        )
        self.assertTrue(
            validator.validate_domain_set(["DOMAIN-SUFFIX,example.com"], 100)
        )

    def test_ruleset_rejects_embedded_policy(self):
        errors = validator.validate_rule_set(
            ["DOMAIN-SUFFIX,example.com,DIRECT"], 200, True
        )
        self.assertTrue(any("embedded routing policy" in e for e in errors))

    def test_ip_requires_no_resolve(self):
        errors = validator.validate_rule_set(
            ["IP-CIDR,1.1.1.0/24"], 200, True
        )
        self.assertTrue(any("missing no-resolve" in e for e in errors))
        self.assertEqual(
            validator.validate_rule_set(
                ["IP-CIDR,1.1.1.0/24,no-resolve"], 200, True
            ),
            [],
        )

    def test_count_change_guard(self):
        guard = {
            "min_previous_rules": 25,
            "max_drop_pct": 35,
            "max_growth_pct": 80,
        }
        self.assertIsNotNone(
            validator.count_change_guard("x", 50, 100, guard)
        )
        self.assertIsNotNone(
            validator.count_change_guard("x", 200, 100, guard)
        )
        self.assertIsNone(
            validator.count_change_guard("x", 90, 100, guard)
        )
        self.assertIsNone(
            validator.count_change_guard("small", 1, 10, guard)
        )

    def test_pattern_matching(self):
        self.assertTrue(
            validator.pattern_matches_domain(
                ("suffix", "example.com"), "api.example.com"
            )
        )
        self.assertTrue(
            validator.pattern_matches_domain(
                ("exact", "example.com"), "example.com"
            )
        )
        self.assertFalse(
            validator.pattern_matches_domain(
                ("exact", "example.com"), "www.example.com"
            )
        )

    def test_conflict_keys(self):
        policies = {
            "DIRECT": [
                ("suffix", "example.com"),
                ("suffix", "cn.example"),
            ],
            "PROXY": [
                ("suffix", "example.com"),
                ("suffix", "proxy.example"),
            ],
        }
        self.assertEqual(
            validator.conflict_keys(policies),
            {"suffix:example.com"},
        )

    def test_safe_relpath(self):
        self.assertEqual(
            validator.safe_relpath("rules/example.list"),
            "rules/example.list",
        )
        with self.assertRaises(validator.ValidationError):
            validator.safe_relpath("../secret")

    def test_fail_closed_keeps_previous_rules(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "rules").mkdir()
            old = root / "rules" / "proxy.list"
            old.write_text(
                "DOMAIN-SUFFIX,old.example\n",
                encoding="utf-8",
            )

            cfg = {
                "version": 1,
                "global": {
                    "timeout_seconds": 1,
                    "max_bytes_per_source": 10000,
                    "max_line_length": 1024,
                    "max_duplicate_pct": 1.0,
                    "change_guard": {
                        "min_previous_rules": 25,
                        "max_drop_pct": 35.0,
                        "max_growth_pct": 80.0,
                    },
                    "allowed_hosts": ["raw.githubusercontent.com"],
                    "allowed_path_prefixes": [
                        "/blackmatrix7/ios_rule_script/"
                    ],
                    "require_no_resolve_for_ip": True,
                },
                "protected_proxy_domains": [],
                "sources": [{
                    "name": "Proxy",
                    "output": "rules/proxy.list",
                    "url": (
                        "https://raw.githubusercontent.com/"
                        "blackmatrix7/ios_rule_script/master/x.list"
                    ),
                    "policy": "PROXY",
                    "format": "rule_set",
                    "min_rules": 2,
                }],
            }

            cfg_path = root / "sources.json"
            cfg_path.write_text(
                json.dumps(cfg),
                encoding="utf-8",
            )
            report = root / "report.md"

            with mock.patch(
                "validator.download",
                return_value=b"DOMAIN-SUFFIX,new.example\n",
            ):
                rc = validator.run(
                    cfg_path,
                    root,
                    report,
                )

            self.assertEqual(rc, 1)
            self.assertEqual(
                old.read_text(encoding="utf-8"),
                "DOMAIN-SUFFIX,old.example\n",
            )

    def test_success_publishes_after_validation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = {
                "version": 1,
                "global": {
                    "timeout_seconds": 1,
                    "max_bytes_per_source": 10000,
                    "max_line_length": 1024,
                    "max_duplicate_pct": 1.0,
                    "change_guard": {
                        "min_previous_rules": 25,
                        "max_drop_pct": 35.0,
                        "max_growth_pct": 80.0,
                    },
                    "allowed_hosts": ["raw.githubusercontent.com"],
                    "allowed_path_prefixes": [
                        "/blackmatrix7/ios_rule_script/"
                    ],
                    "require_no_resolve_for_ip": True,
                },
                "protected_proxy_domains": [],
                "sources": [{
                    "name": "Proxy",
                    "output": "rules/proxy.list",
                    "url": (
                        "https://raw.githubusercontent.com/"
                        "blackmatrix7/ios_rule_script/master/x.list"
                    ),
                    "policy": "PROXY",
                    "format": "rule_set",
                    "min_rules": 1,
                }],
            }

            cfg_path = root / "sources.json"
            cfg_path.write_text(
                json.dumps(cfg),
                encoding="utf-8",
            )
            report = root / "report.md"

            with mock.patch(
                "validator.download",
                return_value=b"DOMAIN-SUFFIX,new.example\n",
            ):
                rc = validator.run(
                    cfg_path,
                    root,
                    report,
                )

            self.assertEqual(rc, 0)
            self.assertTrue(
                (root / "rules" / "proxy.list").exists()
            )
            self.assertTrue(
                (root / "state" / "manifest.json").exists()
            )


if __name__ == "__main__":
    unittest.main()
