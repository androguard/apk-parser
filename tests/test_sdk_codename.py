# -*- coding: utf-8 -*-
import unittest

from apkparser.permissions.ressources import (
    load_permissions,
    load_permission_mappings,
    load_api_specific_resource_module,
    _resolve_api_level,
    CODENAME_API_MAP,
)


class SdkCodenameResolutionTest(unittest.TestCase):
    def test_integer_api_level(self):
        """Existing integer API levels must behave exactly as before."""
        self.assertEqual(_resolve_api_level(29), 29)
        self.assertEqual(_resolve_api_level(33), 33)
        self.assertEqual(_resolve_api_level(35), 35)

        perms_29 = load_permissions(29)
        self.assertIsInstance(perms_29, dict)
        self.assertIn('android.permission.INTERNET', perms_29)

    def test_numeric_string_api_level(self):
        """Numeric strings representing API levels must continue working."""
        self.assertEqual(_resolve_api_level("29"), 29)
        self.assertEqual(_resolve_api_level("33"), 33)
        self.assertEqual(_resolve_api_level("35"), 35)

        self.assertEqual(load_permissions("29"), load_permissions(29))
        self.assertEqual(
            load_api_specific_resource_module("aosp_permissions", "29"),
            load_api_specific_resource_module("aosp_permissions", 29),
        )

    def test_known_sdk_codenames(self):
        """Known Android SDK codenames must resolve to their correct integer API levels."""
        # Single-letter preview codenames
        self.assertEqual(_resolve_api_level("N"), 24)
        self.assertEqual(_resolve_api_level("P"), 28)
        self.assertEqual(_resolve_api_level("Q"), 29)
        self.assertEqual(_resolve_api_level("q"), 29)
        self.assertEqual(_resolve_api_level("T"), 33)
        self.assertEqual(_resolve_api_level("U"), 34)
        self.assertEqual(_resolve_api_level("V"), 35)
        self.assertEqual(_resolve_api_level("B"), 36)

        # Full codenames with case and format variations
        self.assertEqual(_resolve_api_level("Tiramisu"), 33)
        self.assertEqual(_resolve_api_level("TIRAMISU"), 33)
        self.assertEqual(_resolve_api_level("UpsideDownCake"), 34)
        self.assertEqual(_resolve_api_level("VanillaIceCream"), 35)
        self.assertEqual(_resolve_api_level("Baklava"), 36)
        self.assertEqual(_resolve_api_level("BAKLAVA"), 36)

        # Issue #3 core assertion: 'Q' loads API 29 permissions without ValueError
        perms_q = load_permissions("Q")
        self.assertIsInstance(perms_q, dict)
        self.assertEqual(perms_q, load_permissions(29))
        self.assertIn('android.permission.INTERNET', perms_q)

        # load_api_specific_resource_module with codename
        perms_module_q = load_api_specific_resource_module("aosp_permissions", "Q")
        self.assertEqual(perms_module_q, load_api_specific_resource_module("aosp_permissions", 29))

    def test_unknown_or_malformed_sdk_string(self):
        """Unknown or malformed SDK strings must fall back safely and not raise ValueError."""
        # Must fall back to default_api (default: 16)
        resolved = _resolve_api_level("UNKNOWN_FUTURE_CODENAME", default_api=16)
        self.assertEqual(resolved, 16)

        # load_permissions should safely load fallback rather than raise ValueError
        perms_unknown = load_permissions("UNKNOWN_FUTURE_CODENAME")
        self.assertIsInstance(perms_unknown, dict)
        self.assertEqual(perms_unknown, load_permissions(16))

    def test_none_api_level(self):
        """None value falls back to default_api."""
        self.assertEqual(_resolve_api_level(None, default_api=16), 16)
        self.assertEqual(_resolve_api_level(None, default_api=21), 21)


if __name__ == '__main__':
    unittest.main()
