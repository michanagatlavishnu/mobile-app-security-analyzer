"""
Mobile App Security Analyzer - API Correlation & Source-to-Sink Engine
Correlates sensitive Android privacy/telephony/location sources with outbound network sinks.
Identifies potential covert data exfiltration and privacy violation data flows.
"""

import os
import json
from typing import Dict, Any, List, Tuple
from utils.dex_parser import extract_all_dex_strings

def load_security_api_mapping() -> Dict[str, Any]:
    mapping_path = os.path.join(os.path.dirname(__file__), "..", "utils", "security_api_mapping.json")
    if os.path.exists(mapping_path):
        try:
            with open(mapping_path, "r", encoding="utf-8") as f:
                return json.load(f).get("api_categories", {})
        except Exception:
            pass
    return {}

def analyze_api_correlation(apk_path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Evaluates Dalvik strings and symbol tables across all DEX files.
    Maps sensitive source APIs to outbound network sinks.
    Returns:
    - structured correlation summary
    - security findings regarding source-to-sink data transmission
    """
    findings: List[Dict[str, Any]] = []
    api_categories = load_security_api_mapping()
    dex_strings = extract_all_dex_strings(apk_path)

    dex_detections: Dict[str, Dict[str, List[str]]] = {}
    aggregated_sources: Dict[str, List[str]] = {}
    aggregated_sinks: List[str] = []

    for dex_name, strings in dex_strings.items():
        dex_detections[dex_name] = {}
        str_blob = "\n".join(strings)
        str_set = set(strings)

        for cat_id, cat_info in api_categories.items():
            matched = []
            for sig in cat_info.get("signatures", []):
                if sig in str_set or sig in str_blob:
                    matched.append(sig)

            if matched:
                dex_detections[dex_name][cat_id] = matched
                if cat_id == "network_sinks":
                    aggregated_sinks.extend(matched)
                else:
                    aggregated_sources.setdefault(cat_id, []).extend(matched)

    has_network_sinks = len(aggregated_sinks) > 0 or any("http" in s.lower() for s_list in dex_strings.values() for s in s_list)

    # 1. Device Telephony Exfiltration Correlation
    if "device_telephony" in aggregated_sources and has_network_sinks:
        srcs = list(set(aggregated_sources["device_telephony"]))
        findings.append({
            "title": "Potential Device Identifier Transmission via Network (Source-to-Sink)",
            "severity": "HIGH",
            "category": "Privacy & Sensitive APIs",
            "description": "Static code correlation discovered hardware identifier extraction APIs (e.g. TelephonyManager.getDeviceId/getImei) co-located with active network transmission libraries (HttpURLConnection/OkHttpClient). Indicates potential transmission of non-resettable device fingerprints to remote servers.",
            "evidence": f"Sensitive Source(s): {srcs} correlated with outbound network sinks",
            "location": "Dalvik DEX bytecode",
            "impact": "Persistent user tracking, violation of platform privacy baselines, and potential exfiltration of sensitive telemetry.",
            "recommendation": "Avoid querying hardware serial numbers. If telemetry is required, use privacy-preserving randomized app-instance IDs.",
            "cwe": "CWE-200",
            "owasp_category": "M6: Insecure Authorization",
            "confidence": "HIGH",
            "analyzer": "correlation_analyzer",
            "source": "classes.dex"
        })

    # 2. Location Tracking Exfiltration Correlation
    if "location_tracking" in aggregated_sources and has_network_sinks:
        srcs = list(set(aggregated_sources["location_tracking"]))
        findings.append({
            "title": "Potential Geolocation Data Transmission via Network (Source-to-Sink)",
            "severity": "MEDIUM",
            "category": "Privacy & Sensitive APIs",
            "description": "Static code correlation discovered GPS/FusedLocation APIs co-located with outbound HTTP/network client libraries.",
            "evidence": f"Location Source(s): {srcs} correlated with outbound network sinks",
            "location": "Dalvik DEX bytecode",
            "impact": "Real-time physical location data transmitted across the network.",
            "recommendation": "Enforce strict transport layer encryption (TLS 1.3) and ensure user consent is obtained prior to transmitting location.",
            "cwe": "CWE-359",
            "owasp_category": "M6: Insecure Authorization",
            "confidence": "HIGH",
            "analyzer": "correlation_analyzer",
            "source": "classes.dex"
        })

    # 3. Dynamic Code Loading Correlation
    if "dynamic_code_loading" in aggregated_sources and has_network_sinks:
        srcs = list(set(aggregated_sources["dynamic_code_loading"]))
        findings.append({
            "title": "Dynamic Bytecode Loading with Network Connectivity",
            "severity": "HIGH",
            "category": "Code Security",
            "description": "The application contains Dalvik dynamic class loaders (DexClassLoader/PathClassLoader) alongside network capabilities, creating the potential to download and execute remote, unverified executable bytecode.",
            "evidence": f"DCL API: {srcs} with network client presence",
            "location": "Dalvik DEX bytecode",
            "impact": "Remote code execution (RCE) and evasion of static application security testing.",
            "recommendation": "Package all classes directly within the APK and remove dynamic code loaders.",
            "cwe": "CWE-470",
            "owasp_category": "M7: Client Code Quality",
            "confidence": "HIGH",
            "analyzer": "correlation_analyzer",
            "source": "classes.dex"
        })

    metadata = {
        "sensitive_sources_detected": {k: len(v) for k, v in aggregated_sources.items()},
        "network_sinks_detected": len(aggregated_sinks),
        "source_sink_flows_flagged": len(findings),
        "per_dex_detections": {
            dex: {cat: len(sigs) for cat, sigs in cats.items()}
            for dex, cats in dex_detections.items()
        }
    }

    return metadata, findings
