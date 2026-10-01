"""
Mobile App Security Analyzer - Code & Bytecode Heuristics Engine
Inspects compiled Dalvik DEX strings and symbol tables for dangerous APIs,
dynamic code loading, insecure WebView settings, obsolete cryptography,
permissive TLS managers, and sensitive privacy-violating APIs.
"""

from typing import Dict, Any, List
from utils.dex_parser import extract_all_dex_strings

CODE_SECURITY_RULES = [
    {
        "id": "DANGEROUS_CMD_EXEC",
        "title": "Command Execution API Usage Detected",
        "keywords": ["Runtime;->exec", "ProcessBuilder", "Ljava/lang/ProcessBuilder;"],
        "severity": "CRITICAL",
        "category": "Code Security",
        "description": "Usage of Runtime.exec() or ProcessBuilder discovered in application bytecode.",
        "impact": "If unsanitized input reaches system execution commands, adversaries can achieve local shell execution or command injection.",
        "recommendation": "Avoid invoking shell commands or OS binaries directly. Use high-level Android SDK APIs whenever possible.",
        "cwe": "CWE-78",
        "owasp": "M7: Client Code Quality",
    },
    {
        "id": "DYNAMIC_CODE_LOADING",
        "title": "Dynamic Code Loading (DCL) Detected",
        "keywords": ["DexClassLoader", "InMemoryDexClassLoader", "PathClassLoader", "Ldalvik/system/DexClassLoader;"],
        "severity": "HIGH",
        "category": "Code Security",
        "description": "The application dynamically loads classes using Dalvik ClassLoaders at runtime.",
        "impact": "Dynamic code loading can be abused to evade static analysis, execute unauthorized payloads, or be hijacked via unsafe local storage paths.",
        "recommendation": "Package all necessary application logic inside the primary APK. If dynamic loading is required, cryptographically verify code signatures prior to loading.",
        "cwe": "CWE-470",
        "owasp": "M7: Client Code Quality",
    },
    {
        "id": "WEBVIEW_JS_INTERFACE",
        "title": "WebView JavaScript Interface Bridge Detected",
        "keywords": ["addJavascriptInterface"],
        "severity": "HIGH",
        "category": "WebView Security",
        "description": "Application exposes native Java objects to JavaScript inside a WebView using addJavascriptInterface.",
        "impact": "Malicious or untrusted web content loaded in the WebView can invoke exported native Java methods and bridge to native Android capabilities.",
        "recommendation": "Ensure all exposed methods are annotated with @JavascriptInterface and only load trusted, verified HTTPS URLs.",
        "cwe": "CWE-749",
        "owasp": "M1: Improper Platform Usage",
    },
    {
        "id": "WEBVIEW_SETTINGS_RISK",
        "title": "Potentially Insecure WebView Settings Enabled",
        "keywords": ["setJavaScriptEnabled"],
        "severity": "MEDIUM",
        "category": "WebView Security",
        "description": "WebView configuration enables JavaScript execution.",
        "impact": "Permits Cross-Site Scripting (XSS) within WebViews if untrusted HTML content is rendered.",
        "recommendation": "Disable JavaScript if not strictly needed (setJavaScriptEnabled(false)) and validate all loaded URLs.",
        "cwe": "CWE-79",
        "owasp": "M1: Improper Platform Usage",
    },
    {
        "id": "WEBVIEW_FILE_ACCESS_FROM_FILES",
        "title": "WebView File Access From File URLs Allowed",
        "keywords": ["setAllowFileAccessFromFileURLs"],
        "severity": "HIGH",
        "category": "WebView Security",
        "description": "WebView explicitly enables setAllowFileAccessFromFileURLs. JavaScript running in file:// URLs can access local files stored in the application private directory.",
        "impact": "Local file exfiltration and cross-zone scripting vulnerabilities.",
        "recommendation": "Ensure setAllowFileAccessFromFileURLs(false) is configured for all WebViews.",
        "cwe": "CWE-79",
        "owasp": "M1: Improper Platform Usage",
    },
    {
        "id": "WEBVIEW_UNIVERSAL_ACCESS",
        "title": "WebView Universal Cross-Origin Access Permitted",
        "keywords": ["setAllowUniversalAccessFromFileURLs"],
        "severity": "CRITICAL",
        "category": "WebView Security",
        "description": "WebView enables setAllowUniversalAccessFromFileURLs. JavaScript running in file:// URLs can access content from any arbitrary web or local origin, completely disabling the Same-Origin Policy.",
        "impact": "Total same-origin policy bypass allowing attackers to steal session cookies, tokens, and arbitrary application sandbox files.",
        "recommendation": "Disable universal access immediately by setting setAllowUniversalAccessFromFileURLs(false).",
        "cwe": "CWE-346",
        "owasp": "M1: Improper Platform Usage",
    },
    {
        "id": "WEBVIEW_DEBUGGING_ENABLED",
        "title": "WebView Remote Debugging Enabled in Production",
        "keywords": ["setWebContentsDebuggingEnabled"],
        "severity": "HIGH",
        "category": "WebView Security",
        "description": "Application calls WebView.setWebContentsDebuggingEnabled(true). Enables Chrome DevTools inspection for all embedded WebViews over USB/ADB.",
        "impact": "Physical attackers or malware with ADB debugging permissions can execute arbitrary JavaScript, view active DOM elements, and extract cookies.",
        "recommendation": "Disable WebView debugging in release builds: WebView.setWebContentsDebuggingEnabled(false).",
        "cwe": "CWE-215",
        "owasp": "M7: Insufficient Binary Protections",
    },
    {
        "id": "WEBVIEW_MIXED_CONTENT",
        "title": "WebView Insecure Mixed Content Allowed",
        "keywords": ["MIXED_CONTENT_ALWAYS_ALLOW", "setMixedContentMode"],
        "severity": "HIGH",
        "category": "WebView Security",
        "description": "WebView configured to allow mixed content (loading unencrypted HTTP resources within an HTTPS page context).",
        "impact": "Allows network-level Man-in-the-Middle (MITM) adversaries to inject malicious script into secure web sessions.",
        "recommendation": "Set mixed content mode to MIXED_CONTENT_NEVER_ALLOW.",
        "cwe": "CWE-319",
        "owasp": "M5: Insecure Communication",
    },
    {
        "id": "PERMISSIVE_TLS_VALIDATION",
        "title": "Permissive TLS / Blind TrustManager Implementation",
        "keywords": [
            "ALLOW_ALL_HOSTNAME_VERIFIER",
            "AllowAllHostnameVerifier",
            "NullHostnameVerifier",
            "TrustAllCerts",
            "TrustAllTrustManager",
            "checkServerTrusted"
        ],
        "severity": "CRITICAL",
        "category": "Network Security",
        "description": "The application contains custom X509TrustManager or HostnameVerifier implementations that bypass standard TLS certificate chain validation.",
        "impact": "Completely negates transport layer encryption, exposing credentials and network traffic to transparent Man-in-the-Middle (MITM) interception.",
        "recommendation": "Use default platform TrustManager and use Android Network Security Configuration for custom certificate authorities or pinning.",
        "cwe": "CWE-295",
        "owasp": "M5: Insecure Communication",
    },
    {
        "id": "HARDCODED_CRYPTO_IV",
        "title": "Hardcoded or Static Cryptographic IV Indicator",
        "keywords": ["IvParameterSpec", "Ljavax/crypto/spec/IvParameterSpec;"],
        "severity": "HIGH",
        "category": "Cryptography",
        "description": "Usage of IvParameterSpec detected in application bytecode. If initialized with static, zeroed, or predictable byte arrays, cipher confidentiality in CBC or GCM mode is critically undermined.",
        "impact": "Ciphertext predictability, replay vulnerabilities, and potential key recovery in block cipher modes.",
        "recommendation": "Generate a unique, cryptographically secure random IV for every encryption operation using SecureRandom.",
        "cwe": "CWE-329",
        "owasp": "M5: Insufficient Cryptography",
    },
    {
        "id": "HARDCODED_KEY_SPEC",
        "title": "Static Key Spec Initialization Indicator",
        "keywords": ["SecretKeySpec", "Ljavax/crypto/spec/SecretKeySpec;"],
        "severity": "HIGH",
        "category": "Cryptography",
        "description": "Usage of SecretKeySpec detected in application bytecode. Hardcoded byte arrays or static strings used to instantiate SecretKeySpec compromise symmetric encryption.",
        "impact": "Reverse engineers can extract the hardcoded key from decompiled code and decrypt all protected data.",
        "recommendation": "Store keys securely in the hardware-backed Android Keystore and never embed static key arrays in source code.",
        "cwe": "CWE-321",
        "owasp": "M5: Insufficient Cryptography",
    },
    {
        "id": "INSECURE_PRNG",
        "title": "Insecure Pseudo-Random Number Generator (java.util.Random)",
        "keywords": ["Ljava/util/Random;", "java/util/Random;->nextInt", "java/util/Random;->nextBytes"],
        "severity": "MEDIUM",
        "category": "Cryptography",
        "description": "Usage of java.util.Random detected. java.util.Random uses a linear congruential formula that is predictable and unsuitable for security-sensitive operations.",
        "impact": "Predictable session tokens, initialization vectors, or temporary password generation.",
        "recommendation": "Use java.security.SecureRandom for all cryptographically sensitive random generation.",
        "cwe": "CWE-330",
        "owasp": "M5: Insufficient Cryptography",
    },
    {
        "id": "WEAK_CRYPTO_CIPHER",
        "title": "Insecure or Obsolete Cryptographic Cipher",
        "keywords": ["DES/ECB", "DESede", "Blowfish", "RC4", "ARCFOUR", "DES"],
        "severity": "HIGH",
        "category": "Cryptography",
        "description": "References to deprecated or broken cryptographic algorithms (DES, 3DES, RC4, Blowfish) were detected.",
        "impact": "Weak ciphers have known vulnerabilities and small key sizes susceptible to brute force and cryptanalysis.",
        "recommendation": "Use modern standard algorithms such as AES-GCM (256-bit) or ChaCha20-Poly1305 with Android Keystore backed keys.",
        "cwe": "CWE-327",
        "owasp": "M5: Insufficient Cryptography",
    },
    {
        "id": "INSECURE_CIPHER_MODE",
        "title": "Insecure Electronic Codebook (ECB) Cipher Mode",
        "keywords": ["AES/ECB/PKCS5Padding", "AES/ECB/NoPadding", "AES/ECB"],
        "severity": "HIGH",
        "category": "Cryptography",
        "description": "AES configured with Electronic Codebook (ECB) mode detected in application strings.",
        "impact": "ECB mode encrypts identical plaintext blocks into identical ciphertext blocks, leaking data patterns and structure without semantic security.",
        "recommendation": "Use authenticated encryption modes such as AES-GCM or AES-CBC with an HMAC integrity verification.",
        "cwe": "CWE-327",
        "owasp": "M5: Insufficient Cryptography",
    },
    {
        "id": "WEAK_HASH_ALGORITHM",
        "title": "Cryptographically Broken Hash Function (MD5 / SHA-1)",
        "keywords": ["MD5", "SHA-1", "MessageDigest.getInstance(\"MD5\")", "MessageDigest.getInstance(\"SHA-1\")"],
        "severity": "MEDIUM",
        "category": "Cryptography",
        "description": "References to MD5 or SHA-1 hashing algorithms found in application bytecode.",
        "impact": "MD5 and SHA-1 suffer from practical collision attacks and should never be used for digital signatures or integrity verification of sensitive data.",
        "recommendation": "Upgrade cryptographic hashing to SHA-256, SHA-384, or SHA-512.",
        "cwe": "CWE-328",
        "owasp": "M5: Insufficient Cryptography",
    },
    {
        "id": "INSECURE_FILE_MODE",
        "title": "World-Readable or World-Writable File Mode",
        "keywords": ["MODE_WORLD_READABLE", "MODE_WORLD_WRITEABLE"],
        "severity": "HIGH",
        "category": "Storage Security",
        "description": "Application references deprecated MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE file access modes.",
        "impact": "Enables any other application installed on the device to read or overwrite the application's private files and preferences.",
        "recommendation": "Use MODE_PRIVATE (default) for local files or use FileProvider with granular temporary URI permissions.",
        "cwe": "CWE-276",
        "owasp": "M2: Insecure Data Storage",
    },
    {
        "id": "SENSITIVE_API_SMS",
        "title": "Telephony SMS Transmission API Invocations",
        "keywords": ["SmsManager;->sendTextMessage", "SmsManager;->sendMultipartTextMessage", "Landroid/telephony/SmsManager;"],
        "severity": "HIGH",
        "category": "Privacy & Sensitive APIs",
        "description": "Application bytecode contains direct calls to telephony SMS messaging APIs.",
        "impact": "Potential unauthorized premium SMS billing, covert tracking, or SMS redirection.",
        "recommendation": "Delegate SMS operations to the default system SMS application via standard Intent action (ACTION_SENDTO) instead of directly sending SMS.",
        "cwe": "CWE-284",
        "owasp": "M1: Improper Platform Usage",
    },
    {
        "id": "SENSITIVE_API_TELEPHONY_ID",
        "title": "Hardware Device Identifier Queries (IMEI / Serial)",
        "keywords": ["getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber"],
        "severity": "MEDIUM",
        "category": "Privacy & Sensitive APIs",
        "description": "Application queries non-resettable persistent hardware identifiers (IMEI, SIM serial number) via TelephonyManager.",
        "impact": "Persistent user tracking and violation of Google Play privacy developer policies.",
        "recommendation": "Use resettable identifiers such as Advertising ID (AAID) or app-specific UUIDs instead of hardware serial numbers.",
        "cwe": "CWE-200",
        "owasp": "M6: Insecure Authorization",
    },
    {
        "id": "SENSITIVE_API_LOCATION",
        "title": "Fine Geolocation Tracking APIs Detected",
        "keywords": ["LocationManager;->getLastKnownLocation", "LocationManager;->requestLocationUpdates", "FusedLocationProviderClient"],
        "severity": "MEDIUM",
        "category": "Privacy & Sensitive APIs",
        "description": "Application directly interfaces with hardware GPS or fused network location providers.",
        "impact": "Collection of precise real-time physical location data.",
        "recommendation": "Request location only when strictly necessary, favor coarse location if high accuracy is not required, and disclose collection in the privacy policy.",
        "cwe": "CWE-359",
        "owasp": "M6: Insecure Authorization",
    },
    {
        "id": "SENSITIVE_API_CLIPBOARD",
        "title": "System Clipboard Inspection API Usage",
        "keywords": ["ClipboardManager;->getPrimaryClip", "ClipboardManager;->getText", "Landroid/content/ClipboardManager;"],
        "severity": "LOW",
        "category": "Privacy & Sensitive APIs",
        "description": "Application queries system clipboard content via ClipboardManager.",
        "impact": "Passive monitoring of user clipboard data which often contains copied passwords, two-factor codes, or personal messages.",
        "recommendation": "Only access clipboard data in response to an explicit user paste action.",
        "cwe": "CWE-200",
        "owasp": "M6: Insecure Authorization",
    },
]

def analyze_code(apk_path: str) -> List[Dict[str, Any]]:
    """
    Performs static code heuristics across all Dalvik DEX files inside the APK.
    Returns unified vulnerability findings for risk calculation and database persistence.
    """
    findings: List[Dict[str, Any]] = []
    dex_strings = extract_all_dex_strings(apk_path)
    triggered_rules = set()

    for dex_name, strings in dex_strings.items():
        string_set = set(strings)
        string_blob = "\n".join(strings)

        for rule in CODE_SECURITY_RULES:
            rule_id = rule["id"]
            if rule_id in triggered_rules:
                continue

            matched_keywords = []
            for kw in rule["keywords"]:
                if kw in string_set or kw in string_blob:
                    matched_keywords.append(kw)

            if matched_keywords:
                triggered_rules.add(rule_id)
                findings.append({
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "description": rule["description"],
                    "evidence": f"Found signature(s) [{', '.join(matched_keywords)}] in {dex_name}",
                    "location": dex_name,
                    "impact": rule["impact"],
                    "recommendation": rule["recommendation"],
                    "cwe": rule["cwe"],
                    "owasp_category": rule["owasp"],
                    "confidence": "HIGH",
                    "analyzer": "code_analyzer",
                    "source": dex_name
                })

    return findings
