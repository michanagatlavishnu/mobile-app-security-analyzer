import unittest
import os
import struct
from utils.axml_parser import AxmlParser, format_typed_value, StringPool
from analyzers.permission_analyzer import analyze_permissions
from analyzers.component_analyzer import analyze_components
from analyzers.manifest_analyzer import analyze_manifest
from analyzers.risk_engine import calculate_security_score

class TestAnalyzerComponents(unittest.TestCase):

    def test_permission_analyzer(self):
        perms = [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.INTERNET",
            "com.custom.MY_PERMISSION"
        ]
        results = analyze_permissions(perms)
        self.assertEqual(len(results), 4)

        camera = next(p for p in results if p["permission"] == "android.permission.CAMERA")
        self.assertEqual(camera["protection"], "dangerous")
        self.assertEqual(camera["risk"], "HIGH")

        audio = next(p for p in results if p["permission"] == "android.permission.RECORD_AUDIO")
        self.assertEqual(audio["risk"], "CRITICAL")

        internet = next(p for p in results if p["permission"] == "android.permission.INTERNET")
        self.assertEqual(audio["protection"], "dangerous")
        self.assertEqual(internet["risk"], "SAFE")

        custom = next(p for p in results if p["permission"] == "com.custom.MY_PERMISSION")
        self.assertEqual(custom["protection"], "custom")

    def test_component_analyzer(self):
        manifest_data = {
            "activities": [
                {
                    "name": "com.example.MainActivity",
                    "exported": True,
                    "permission": None,
                    "intent_filters": [{"actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"]}]
                },
                {
                    "name": "com.example.SecretActivity",
                    "exported": True,
                    "permission": None,
                    "intent_filters": []
                }
            ],
            "services": [
                {
                    "name": "com.example.BackendService",
                    "exported": True,
                    "permission": None,
                    "intent_filters": []
                }
            ],
            "receivers": [],
            "providers": []
        }
        comps, findings = analyze_components(manifest_data)
        self.assertEqual(len(comps), 3)
        # MainActivity is launcher so it shouldn't be flagged as vulnerable exported activity; SecretActivity and BackendService should be flagged
        flagged_names = [f["evidence"] for f in findings]
        self.assertTrue(any("SecretActivity" in e for e in flagged_names))
        self.assertTrue(any("BackendService" in e for e in flagged_names))
        self.assertFalse(any("MainActivity" in e for e in flagged_names))

    def test_manifest_analyzer_findings(self):
        manifest_data = {
            "application": {
                "debuggable": True,
                "allowBackup": True,
                "usesCleartextTraffic": True
            },
            "targetSdkVersion": 26
        }
        findings = analyze_manifest(manifest_data)
        titles = [f["title"] for f in findings]
        self.assertIn("Debuggable Application", titles)
        self.assertIn("Cleartext Network Traffic Enabled", titles)
        self.assertIn("Application Data Backup Enabled", titles)
        self.assertIn("Severely Outdated Target SDK Version", titles)

    def test_risk_engine_scoring(self):
        findings = [
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"}
        ]
        score_data = calculate_security_score(findings)
        # 100 - 15 - 8 - 3 = 74
        self.assertEqual(score_data["score"], 74)
        self.assertEqual(score_data["risk_level"], "MEDIUM")

    def test_malformed_input_safety(self):
        # AXML parser with empty / truncated bytes
        parser = AxmlParser(b"")
        res = parser.parse()
        self.assertIn("error", res)

        parser2 = AxmlParser(b"\x00" * 20)
        res2 = parser2.parse()
        self.assertIn("error", res2)

        # Corrupt AXML chunks with invalid sizes
        corrupt_axml = b"\x03\x00\x08\x00\x64\x00\x00\x00" + (b"\xFF" * 100)
        parser3 = AxmlParser(corrupt_axml)
        res3 = parser3.parse()
        self.assertTrue("error" in res3 or res3.get("application") is not None)

        # Malformed DEX binary inspection
        from utils.dex_parser import inspect_dex_bytes, extract_strings_from_dex
        dex_res = inspect_dex_bytes(b"NOT_A_DEX_FILE_BYTES")
        self.assertFalse(dex_res["valid"])
        self.assertIn("error", dex_res)

        corrupt_dex_magic = b"dex\n035\0" + (b"\xFF" * 16)
        dex_res2 = inspect_dex_bytes(corrupt_dex_magic)
        self.assertFalse(dex_res2["valid"])

        # Truncated DEX strings extraction
        dex_strings = extract_strings_from_dex(b"dex\n035\0\x00\x00\x00")
        self.assertIsInstance(dex_strings, list)

        # Malformed certificate bytes extraction
        from analyzers.certificate_analyzer import parse_certificate_from_der_or_pkcs7
        garbage_certs = parse_certificate_from_der_or_pkcs7(b"\x30\x82\x99\x99GARBAGE_BYTES_THAT_ARE_NOT_ASN1")
        self.assertEqual(garbage_certs, [])

        # Corrupt ZIP archive verification
        from utils.apk_utils import verify_zip_integrity
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(b"CORRUPT_NOT_A_ZIP_ARCHIVE_DATA")
            tmp_path = tmp.name
        try:
            self.assertFalse(verify_zip_integrity(tmp_path))
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_secret_masking(self):
        from analyzers.secret_analyzer import mask_secret
        # Google API key
        masked = mask_secret("AIzaSyD-8_f9j4k1LmN2pQrStUvWxYz1234567")
        self.assertTrue(masked.startswith("AIza"))
        self.assertTrue(masked.endswith("4567"))
        self.assertIn("************", masked)
        self.assertNotIn("LmN2pQr", masked)

        # Short secret
        masked_short = mask_secret("secret12")
        self.assertEqual(len(masked_short), 8)
        self.assertIn("****", masked_short)

    def test_secret_patterns(self):
        from analyzers.secret_analyzer import SECRET_RULES
        google_rule = next(r for r in SECRET_RULES if "Google" in r["type"])
        self.assertTrue(google_rule["pattern"].search("AIzaSyD-8_f9j4k1LmN2pQrStUvWxYz1234567"))

        aws_rule = next(r for r in SECRET_RULES if r["type"] == "AWS Access Key")
        self.assertTrue(aws_rule["pattern"].search("AKIAIOSFODNN7EXAMPLE"))

        jwt_rule = next(r for r in SECRET_RULES if "JWT" in r["type"])
        self.assertTrue(jwt_rule["pattern"].search("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"))

        stripe_rule = next(r for r in SECRET_RULES if "Stripe" in r["type"])
        self.assertTrue(stripe_rule["pattern"].search("pk_test_51MockFakeStripeKeyForTestingOnly0000000000000"))

    def test_dex_string_extraction(self):
        from utils.dex_parser import extract_strings_from_dex, read_uleb128
        # Test ULEB128
        val, off = read_uleb128(b"\x05\x00", 0)
        self.assertEqual(val, 5)
        self.assertEqual(off, 1)

        val_multi, off_multi = read_uleb128(b"\x80\x01\x00", 0)
        self.assertEqual(val_multi, 128)
        self.assertEqual(off_multi, 2)

        # Raw string extraction fallback
        raw_dex = b"dex\n035\0" + (b"\x00" * 0x68) + b"https://api.example.com/v1\x00AIzaSyD1234567890abcdefghijklmnopqrs\x00"
        strings = extract_strings_from_dex(raw_dex)
        self.assertTrue(any("https://api.example.com" in s for s in strings))
        self.assertTrue(any("AIzaSy" in s for s in strings))

    def test_network_url_filtering(self):
        from analyzers.network_analyzer import URL_REGEX, IGNORED_URL_PREFIXES
        test_text = "Endpoints: http://insecure.example.com/api and https://secure.example.com and http://schemas.android.com/apk/res/android"
        urls = URL_REGEX.findall(test_text)
        filtered = [u for u in urls if not u.startswith(IGNORED_URL_PREFIXES)]
        self.assertIn("http://insecure.example.com/api", filtered)
        self.assertIn("https://secure.example.com", filtered)
        self.assertNotIn("http://schemas.android.com/apk/res/android", filtered)

    def test_certificate_analyzer_debug_detection(self):
        from analyzers.certificate_analyzer import analyze_apk_certificates
        # Test against vulnerable_test_app.apk
        if os.path.exists("vulnerable_test_app.apk"):
            metadata, findings = analyze_apk_certificates("vulnerable_test_app.apk")
            self.assertTrue(metadata["is_debug_signed"])
            titles = [f["title"] for f in findings]
            self.assertIn("Application Signed with Debug Keystore Certificate", titles)
            self.assertIn("Missing APK Signature Scheme v2/v3 (JAR Signing Only)", titles)
            self.assertTrue(len(metadata["certificates"]) > 0)
            self.assertIn("CN=Android Debug", metadata["certificates"][0]["subject_dn"])

    def test_content_provider_security(self):
        manifest_data = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [
                {
                    "name": "com.example.InsecureProvider",
                    "exported": True,
                    "permission": None,
                    "readPermission": None,
                    "writePermission": None,
                    "grantUriPermissions": True,
                    "authorities": "com.example.provider"
                }
            ]
        }
        comps, findings = analyze_components(manifest_data)
        titles = [f["title"] for f in findings]
        self.assertIn("Exported ContentProvider Without Access Controls", titles)
        self.assertIn("Dynamic URI Permission Granting on Exported ContentProvider", titles)

    def test_advanced_manifest_attributes(self):
        manifest_data = {
            "application": {
                "allowTaskReparenting": True,
                "requestLegacyExternalStorage": True
            },
            "activities": [
                {
                    "name": "com.example.SingleTaskActivity",
                    "exported": True,
                    "permission": None,
                    "launchMode": "singleTask"
                }
            ]
        }
        findings = analyze_manifest(manifest_data)
        titles = [f["title"] for f in findings]
        self.assertIn("Application Task Reparenting Enabled", titles)
        self.assertIn("Legacy External Storage Requested", titles)
        self.assertIn("Exported Activity Configured with singleTask Launch Mode", titles)

    def test_advanced_code_heuristics(self):
        from analyzers.code_analyzer import CODE_SECURITY_RULES
        rule_ids = [r["id"] for r in CODE_SECURITY_RULES]
        self.assertIn("WEBVIEW_UNIVERSAL_ACCESS", rule_ids)
        self.assertIn("WEBVIEW_FILE_ACCESS_FROM_FILES", rule_ids)
        self.assertIn("WEBVIEW_DEBUGGING_ENABLED", rule_ids)
        self.assertIn("PERMISSIVE_TLS_VALIDATION", rule_ids)
        self.assertIn("HARDCODED_CRYPTO_IV", rule_ids)
        self.assertIn("HARDCODED_KEY_SPEC", rule_ids)
        self.assertIn("INSECURE_PRNG", rule_ids)
        self.assertIn("SENSITIVE_API_SMS", rule_ids)
        self.assertIn("SENSITIVE_API_TELEPHONY_ID", rule_ids)

    def test_multidex_summary(self):
        from utils.dex_parser import get_multidex_summary
        sample_summaries = [
            {"valid": True, "class_count": 120, "method_count": 1500, "field_count": 800, "string_count": 3000},
            {"valid": True, "class_count": 80, "method_count": 900, "field_count": 400, "string_count": 1800},
        ]
        summary = get_multidex_summary(sample_summaries)
        self.assertTrue(summary["is_multidex"])
        self.assertEqual(summary["dex_count"], 2)
        self.assertEqual(summary["total_classes"], 200)
        self.assertEqual(summary["total_methods"], 2400)
        self.assertFalse(summary["approaching_limit"])

    def test_shannon_entropy(self):
        from utils.entropy_analyzer import calculate_shannon_entropy, scan_strings_for_entropy
        # Repeated low-entropy string
        low_ent = calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertAlmostEqual(low_ent, 0.0, places=2)

        # High-entropy random key string
        high_ent_str = "wK9#m$L2p@vR8*xT1&zQ5^bN4!jH7~cY"
        high_ent = calculate_shannon_entropy(high_ent_str)
        self.assertGreater(high_ent, 4.5)

        records, findings = scan_strings_for_entropy([
            "short",
            "http://example.com/api/v1/auth",
            "dGhpcy1pcy1hLXJlYWxseS1sb25nLWhpZ2gtZW50cm9weS1zdHJpbmctZXhhbXBsZS0xMjM0NQ=="
        ])
        self.assertTrue(len(records) > 0)
        self.assertIn("****", records[0]["masked_value"])

    def test_api_correlation(self):
        from analyzers.correlation_analyzer import analyze_api_correlation
        if os.path.exists("vulnerable_test_app.apk"):
            meta, findings = analyze_api_correlation("vulnerable_test_app.apk")
            titles = [f["title"] for f in findings]
            self.assertIn("Potential Device Identifier Transmission via Network (Source-to-Sink)", titles)
            self.assertTrue(meta["source_sink_flows_flagged"] > 0)

if __name__ == "__main__":
    unittest.main()

