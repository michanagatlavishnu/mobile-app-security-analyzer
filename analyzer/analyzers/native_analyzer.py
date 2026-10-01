"""
Mobile App Security Analyzer - Native Library (.so) Analyzer
Audits compiled native shared object binaries in APK lib/ directory.
Inspects ABI coverage (64-bit compliance), binary presence, and security libraries.
"""

import os
import zipfile
import hashlib
from typing import Dict, Any, List, Tuple

def analyze_native_libraries(apk_path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Inspects native libraries (.so files) embedded in lib/<abi>/ inside the APK.
    Returns:
    - native library metadata summary
    - security findings regarding native libraries
    """
    findings: List[Dict[str, Any]] = []
    libraries: List[Dict[str, Any]] = []
    abi_map: Dict[str, List[str]] = {}

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for item in zf.infolist():
                if item.filename.startswith("lib/") and item.filename.endswith(".so"):
                    parts = item.filename.split("/")
                    if len(parts) >= 3:
                        abi = parts[1]
                        lib_name = parts[-1]
                        file_bytes = zf.read(item.filename)
                        sha256 = hashlib.sha256(file_bytes).hexdigest()

                        abi_map.setdefault(abi, []).append(lib_name)
                        libraries.append({
                            "name": lib_name,
                            "abi": abi,
                            "path": item.filename,
                            "size": item.file_size,
                            "sha256": sha256
                        })
    except Exception:
        pass

    supported_abis = sorted(list(abi_map.keys()))
    has_native_code = len(libraries) > 0

    # 1. 64-bit Architecture Compliance Check
    if has_native_code:
        has_32bit = any(abi in ("armeabi-v7a", "x86", "armeabi") for abi in supported_abis)
        has_64bit = any(abi in ("arm64-v8a", "x86_64") for abi in supported_abis)

        if has_32bit and not has_64bit:
            findings.append({
                "title": "Missing 64-Bit Native Architecture Support",
                "severity": "LOW",
                "category": "Native Binary Security",
                "description": f"The application includes 32-bit native binaries ({', '.join(supported_abis)}) but lacks 64-bit counterparts (arm64-v8a / x86_64). Google Play mandates 64-bit support. Furthermore, 64-bit architectures offer significantly enhanced memory space layout randomization (ASLR) and pointer authentication against memory corruption.",
                "evidence": f"Supported ABIs: {supported_abis}",
                "location": "lib/",
                "impact": "Ineligibility for modern platform optimizations and reduced ASLR entropy compared to 64-bit architectures.",
                "recommendation": "Compile and package arm64-v8a native library variants using the Android NDK.",
                "cwe": "CWE-1104",
                "owasp_category": "M7: Insufficient Binary Protections",
                "confidence": "HIGH",
                "analyzer": "native_analyzer",
                "source": "lib/"
            })

    metadata = {
        "has_native_code": has_native_code,
        "total_libraries": len(libraries),
        "supported_abis": supported_abis,
        "abi_breakdown": {abi: len(libs) for abi, libs in abi_map.items()},
        "libraries": libraries
    }

    return metadata, findings
