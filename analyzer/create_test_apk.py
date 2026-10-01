"""
Generates a realistic, standard Android APK with binary AndroidManifest.xml,
classes.dex, classes2.dex, network_security_config.xml, resources, and PKCS#7 signed X.509 certificate.
Constructed byte-by-byte per Android Binary XML and Dalvik DEX specifications.
"""

import struct
import zipfile
import zlib
import hashlib
import datetime

def generate_pkcs7_debug_certificate() -> bytes:
    """Generates standard PKCS#7 DER signature block containing an Android Debug X.509 certificate."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Android Debug"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365 * 30))
            .sign(private_key, hashes.SHA256())
        )

        builder = pkcs7.PKCS7SignatureBuilder().set_data(b"Android Signed Manifest")
        builder = builder.add_signer(cert, private_key, hashes.SHA256())
        return builder.sign(Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    except Exception:
        # Fallback binary sequence containing "Android Debug"
        return b"\x30\x82\x02\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02CN=Android Debug, O=Android, C=US"

def build_string_pool(strings):
    utf8_flag = 1 << 8
    encoded_strings = []
    offsets = []
    current_offset = 0

    for s in strings:
        raw = s.encode("utf-8")
        offsets.append(current_offset)
        u16len = len(s)
        u8len = len(raw)
        entry = bytes([u16len, u8len]) + raw + b"\x00"
        encoded_strings.append(entry)
        current_offset += len(entry)

    strings_data = b"".join(encoded_strings)
    pad = (4 - (len(strings_data) % 4)) % 4
    strings_data += b"\x00" * pad

    header_size = 28
    string_count = len(strings)
    style_count = 0
    strings_start = header_size + (string_count * 4)
    styles_start = 0
    chunk_size = strings_start + len(strings_data)

    header = struct.pack(
        "<HHIIIIII",
        0x0001,  # chunk type
        header_size,
        chunk_size,
        string_count,
        style_count,
        utf8_flag,
        strings_start,
        styles_start
    )

    offset_table = struct.pack(f"<{string_count}I", *offsets)
    return header + offset_table + strings_data

def build_binary_axml():
    strings = [
        "manifest",
        "package",
        "versionCode",
        "versionName",
        "uses-sdk",
        "minSdkVersion",
        "targetSdkVersion",
        "uses-permission",
        "name",
        "application",
        "debuggable",
        "allowBackup",
        "usesCleartextTraffic",
        "networkSecurityConfig",
        "requestLegacyExternalStorage",
        "allowTaskReparenting",
        "activity",
        "exported",
        "service",
        "provider",
        "authorities",
        "grantUriPermissions",
        "intent-filter",
        "action",
        "category",
        "org.owasp.goatdroid",
        "2.1-debug",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
        "org.owasp.goatdroid.MainActivity",
        "org.owasp.goatdroid.DebugConsoleActivity",
        "org.owasp.goatdroid.SyncService",
        "org.owasp.goatdroid.UserDataProvider",
        "org.owasp.goatdroid.provider",
        "android.intent.action.MAIN",
        "android.intent.category.LAUNCHER",
        "@xml/network_security_config"
    ]

    string_pool = build_string_pool(strings)

    def start_elem(name_idx, attr_count=0):
        chunk_size = 16 + 20 + (attr_count * 20)
        header = struct.pack("<HHI II", 0x0102, 16, chunk_size, 1, 0xFFFFFFFF)
        attr_ext = struct.pack("<II HHH HHH", 0xFFFFFFFF, name_idx, 20, 20, attr_count, 0, 0, 0)
        return header + attr_ext

    def end_elem(name_idx):
        return struct.pack("<HHI II II", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, name_idx)

    def attr_entry(name_idx, val_str_idx, val_type, data):
        type_full = (val_type << 24) | 0x0008
        return struct.pack("<III I I", 0xFFFFFFFF, name_idx, val_str_idx, type_full, data)

    # 1. <manifest package="org.owasp.goatdroid" versionCode=2 versionName="2.1-debug">
    body = bytearray()
    body.extend(start_elem(0, 3))
    body.extend(attr_entry(1, 25, 0x03, 25))
    body.extend(attr_entry(2, 0xFFFFFFFF, 0x10, 2))
    body.extend(attr_entry(3, 26, 0x03, 26))

    # 2. <uses-sdk minSdkVersion=21 targetSdkVersion=26>
    body.extend(start_elem(4, 2))
    body.extend(attr_entry(5, 0xFFFFFFFF, 0x10, 21))
    body.extend(attr_entry(6, 0xFFFFFFFF, 0x10, 26))
    body.extend(end_elem(4))

    # 3. Permissions: CAMERA, RECORD_AUDIO, ACCESS_FINE_LOCATION, READ_SMS, INTERNET
    perm_indices = [27, 28, 29, 30, 31]
    for p_idx in perm_indices:
        body.extend(start_elem(7, 1))
        body.extend(attr_entry(8, p_idx, 0x03, p_idx))
        body.extend(end_elem(7))

    # 4. <application debuggable=true allowBackup=true usesCleartextTraffic=true networkSecurityConfig="@xml/network_security_config" requestLegacyExternalStorage=true allowTaskReparenting=true>
    body.extend(start_elem(9, 6))
    body.extend(attr_entry(10, 0xFFFFFFFF, 0x12, 1))
    body.extend(attr_entry(11, 0xFFFFFFFF, 0x12, 1))
    body.extend(attr_entry(12, 0xFFFFFFFF, 0x12, 1))
    body.extend(attr_entry(13, 39, 0x03, 39))
    body.extend(attr_entry(14, 0xFFFFFFFF, 0x12, 1))
    body.extend(attr_entry(15, 0xFFFFFFFF, 0x12, 1))

    # 4a. <activity name="org.owasp.goatdroid.MainActivity" exported=true>
    body.extend(start_elem(16, 2))
    body.extend(attr_entry(8, 32, 0x03, 32))
    body.extend(attr_entry(17, 0xFFFFFFFF, 0x12, 1))
    # <intent-filter>
    body.extend(start_elem(22, 0))
    body.extend(start_elem(23, 1))
    body.extend(attr_entry(8, 37, 0x03, 37))
    body.extend(end_elem(23))
    body.extend(start_elem(24, 1))
    body.extend(attr_entry(8, 38, 0x03, 38))
    body.extend(end_elem(24))
    body.extend(end_elem(22))
    body.extend(end_elem(16))

    # 4b. <activity name="org.owasp.goatdroid.DebugConsoleActivity" exported=true>
    body.extend(start_elem(16, 2))
    body.extend(attr_entry(8, 33, 0x03, 33))
    body.extend(attr_entry(17, 0xFFFFFFFF, 0x12, 1))
    body.extend(end_elem(16))

    # 4c. <service name="org.owasp.goatdroid.SyncService" exported=true>
    body.extend(start_elem(18, 2))
    body.extend(attr_entry(8, 34, 0x03, 34))
    body.extend(attr_entry(17, 0xFFFFFFFF, 0x12, 1))
    body.extend(end_elem(18))

    # 4d. <provider name="org.owasp.goatdroid.UserDataProvider" authorities="org.owasp.goatdroid.provider" exported=true grantUriPermissions=true>
    body.extend(start_elem(19, 4))
    body.extend(attr_entry(8, 35, 0x03, 35))
    body.extend(attr_entry(20, 36, 0x03, 36))
    body.extend(attr_entry(17, 0xFFFFFFFF, 0x12, 1))
    body.extend(attr_entry(21, 0xFFFFFFFF, 0x12, 1))
    body.extend(end_elem(19))

    # End application & manifest
    body.extend(end_elem(9))
    body.extend(end_elem(0))

    header_size = 8
    total_size = header_size + len(string_pool) + len(body)
    xml_header = struct.pack("<HHI", 0x0003, header_size, total_size)

    return xml_header + string_pool + bytes(body)

def build_dalvik_dex_with_strings(string_list):
    """Generates standard Dalvik Executable (DEX 035) with populated string_ids and string_data."""
    header_size = 0x70
    str_count = len(string_list)
    string_ids_off = header_size

    str_data_items = []
    for s in string_list:
        raw = s.encode("utf-8")
        entry = bytes([len(raw)]) + raw + b"\x00"
        str_data_items.append(entry)

    data_start_off = string_ids_off + (str_count * 4)
    offsets = []
    cur = data_start_off
    for item in str_data_items:
        offsets.append(cur)
        cur += len(item)

    string_ids_table = struct.pack(f"<{str_count}I", *offsets)
    all_string_data = b"".join(str_data_items)

    total_size = header_size + len(string_ids_table) + len(all_string_data)

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\0"
    struct.pack_into("<I", header, 0x20, total_size)
    struct.pack_into("<I", header, 0x24, header_size)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<II", header, 0x38, str_count, string_ids_off)
    struct.pack_into("<I", header, 0x40, 1)  # type_ids_size
    struct.pack_into("<I", header, 0x58, 1)  # method_ids_size
    struct.pack_into("<I", header, 0x60, 1)  # class_defs_size

    body = string_ids_table + all_string_data
    header[12:32] = hashlib.sha1(header[32:] + body).digest()
    struct.pack_into("<I", header, 0x08, zlib.adler32(header[12:] + body))

    return bytes(header) + body

def create_real_apk(output_apk_path):
    axml_data = build_binary_axml()

    # Primary DEX strings: secrets, dangerous APIs, crypto, webview, endpoints, sensitive APIs
    dex1_strings = [
        "AIzaSyD-8_f9j4k1LmN2pQrStUvWxYz12345678",
        "AKIAIOSFODNN7EXAMPLE",
        "pk_test_51MockFakeStripeKeyForTestingOnly0000000000000",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "http://api.insecure-backend.com/v1/auth",
        "https://api.secure-backend.com/v1",
        "http://192.168.1.100:8080/debug",
        "https://staging-auth.company.local",
        "Runtime;->exec",
        "Ljava/lang/ProcessBuilder;",
        "Ldalvik/system/DexClassLoader;",
        "setJavaScriptEnabled",
        "setAllowFileAccessFromFileURLs",
        "setAllowUniversalAccessFromFileURLs",
        "setWebContentsDebuggingEnabled",
        "MIXED_CONTENT_ALWAYS_ALLOW",
        "addJavascriptInterface",
        "DES/ECB",
        "AES/ECB/PKCS5Padding",
        "MD5",
        "MODE_WORLD_READABLE",
        "IvParameterSpec",
        "SecretKeySpec",
        "Ljava/util/Random;->nextInt",
        "ALLOW_ALL_HOSTNAME_VERIFIER",
        "checkServerTrusted",
        "SmsManager;->sendTextMessage",
        "LocationManager;->getLastKnownLocation",
        "getDeviceId",
        "ClipboardManager;->getPrimaryClip"
    ]
    dex1_data = build_dalvik_dex_with_strings(dex1_strings)

    # Secondary DEX (classes2.dex) strings: multi-dex verification
    dex2_strings = [
        "api_key=\"9f8e7d6c5b4a3f2e1d0c\"",
        "https://cdn.partner-service.com/assets/sdk.js",
        "DESede",
        "Blowfish"
    ]
    dex2_data = build_dalvik_dex_with_strings(dex2_strings)

    network_config_xml = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""

    cert_rsa_bytes = generate_pkcs7_debug_certificate()

    with zipfile.ZipFile(output_apk_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", axml_data)
        zf.writestr("classes.dex", dex1_data)
        zf.writestr("classes2.dex", dex2_data)
        zf.writestr("res/xml/network_security_config.xml", network_config_xml.encode("utf-8"))
        zf.writestr("res/values/strings.xml", b"<resources><string name='app_name'>GoatDroid</string></resources>")
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nCreated-By: Android Gradle 8.2\r\n")
        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n")
        zf.writestr("META-INF/CERT.RSA", cert_rsa_bytes)

    return output_apk_path

if __name__ == "__main__":
    apk_path = "vulnerable_test_app.apk"
    create_real_apk(apk_path)
    print(f"Created real Android test APK with Multi-DEX & Network Config at: {apk_path}")
