#!/usr/bin/env python3
"""
Mobile App Security Analyzer - Main Analysis Pipeline
Executes binary AXML manifest parsing, permission audits, component analysis, metadata extraction, and risk scoring.
"""

import sys
import os
import json
import argparse
from typing import Dict, Any, List

from utils.apk_utils import (
    validate_apk_file,
    calculate_sha256,
    verify_zip_integrity,
    safe_extract_apk,
    ApkValidationError,
)
from utils.axml_parser import parse_manifest_from_apk
from analyzers.manifest_analyzer import analyze_manifest
from analyzers.permission_analyzer import analyze_permissions
from analyzers.component_analyzer import analyze_components
from analyzers.metadata_analyzer import analyze_metadata
from analyzers.risk_engine import calculate_security_score
from analyzers.network_analyzer import analyze_network
from analyzers.secret_analyzer import analyze_secrets
from analyzers.code_analyzer import analyze_code
from analyzers.native_analyzer import analyze_native_libraries
from analyzers.correlation_analyzer import analyze_api_correlation
from utils.entropy_analyzer import scan_strings_for_entropy
from utils.dex_parser import get_multidex_summary, extract_all_dex_strings

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mobile App Security Analyzer - Android APK Static Analysis Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--apk",
        required=True,
        type=str,
        help="Path to the Android APK file to analyze",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional path to output the analysis result JSON file",
    )
    parser.add_argument(
        "--scan-id",
        type=int,
        default=None,
        help="Database Scan ID associated with this analysis job",
    )
    return parser

def run_apk_analysis(apk_path: str, scan_id: int = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "success": False,
        "scan_id": scan_id,
        "apk": {
            "filename": os.path.basename(apk_path) if apk_path else "",
            "sha256": "",
            "size": 0,
        },
        "metadata": {},
        "manifest": {},
        "permissions": [],
        "components": [],
        "network": [],
        "secrets": [],
        "code": [],
        "findings": [],
        "score": None,
        "risk_level": None,
        "errors": [],
    }

    try:
        # 1. Validation & Integrity
        validate_apk_file(apk_path)
        if not verify_zip_integrity(apk_path):
            result["errors"].append("ZIP archive integrity check failed. Corrupted APK.")
            return result

        result["apk"]["sha256"] = calculate_sha256(apk_path)
        result["apk"]["size"] = os.path.getsize(apk_path)

        # 2. Binary AndroidManifest.xml Parsing
        manifest_data = parse_manifest_from_apk(apk_path)
        if "error" in manifest_data:
            result["errors"].append(f"Manifest analysis error: {manifest_data['error']}")
            # Proceed with partial analysis if possible
            manifest_data = {"permissions": [], "activities": [], "services": [], "receivers": [], "providers": []}

        result["manifest"] = manifest_data

        # 3. Metadata Analysis
        metadata_res = analyze_metadata(apk_path, manifest_data)
        metadata_res["multidex_summary"] = get_multidex_summary(metadata_res.get("dex_summary", []))
        result["metadata"] = metadata_res

        # 4. Permission Auditing
        requested_perms = manifest_data.get("permissions", [])
        result["permissions"] = analyze_permissions(requested_perms)

        # 5. Component Auditing
        component_records, component_findings = analyze_components(manifest_data)
        result["components"] = component_records

        # 6. Manifest Security Findings
        manifest_findings = analyze_manifest(manifest_data)
        for f in manifest_findings:
            f.setdefault("analyzer", "manifest_analyzer")
            f.setdefault("source", "AndroidManifest.xml")

        for f in component_findings:
            f.setdefault("analyzer", "component_analyzer")
            f.setdefault("source", "AndroidManifest.xml")

        # 7. Deep Static Analysis Engines (Phase 6)
        network_findings, network_records = analyze_network(apk_path, manifest_data)
        result["network"] = network_records

        secret_findings, secret_records = analyze_secrets(apk_path)
        result["secrets"] = secret_records

        code_findings = analyze_code(apk_path)
        result["code"] = code_findings

        # 8. Advanced Code Intelligence & Native Inspection (Phase 9)
        native_metadata, native_findings = analyze_native_libraries(apk_path)
        result["native"] = native_metadata

        all_dex_strings = [s for sublist in extract_all_dex_strings(apk_path).values() for s in sublist]
        entropy_records, entropy_findings = scan_strings_for_entropy(all_dex_strings)
        result["entropy"] = entropy_records

        correlation_metadata, correlation_findings = analyze_api_correlation(apk_path)
        result["correlation"] = correlation_metadata

        # 9. Aggregate & Deduplicate Findings
        cert_findings = result["metadata"].get("certificateFindings", [])
        for f in cert_findings:
            f.setdefault("analyzer", "certificate_analyzer")
            f.setdefault("source", "META-INF")

        raw_findings = []
        raw_findings.extend(manifest_findings)
        raw_findings.extend(component_findings)
        raw_findings.extend(network_findings)
        raw_findings.extend(secret_findings)
        raw_findings.extend(code_findings)
        raw_findings.extend(cert_findings)
        raw_findings.extend(native_findings)
        raw_findings.extend(entropy_findings)
        raw_findings.extend(correlation_findings)

        # Deduplicate findings by (title, category, location)
        unique_findings = []
        seen_keys = set()
        for f in raw_findings:
            # Normalize confidence to uppercase
            conf = (f.get("confidence") or "HIGH").upper()
            if conf not in ("HIGH", "MEDIUM", "LOW"):
                conf = "HIGH"
            f["confidence"] = conf
            f.setdefault("analyzer", "static_analyzer")
            f.setdefault("source", f.get("location") or "APK")

            dedup_key = (f.get("title"), f.get("category"), f.get("location"))
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                unique_findings.append(f)

        result["findings"] = unique_findings

        # 9. Risk Engine Scoring
        score_data = calculate_security_score(unique_findings)
        result["score"] = score_data["score"]
        result["risk_level"] = score_data["risk_level"]
        result["score_breakdown"] = score_data["breakdown"]

        result["success"] = True

    except ApkValidationError as e:
        result["errors"].append(str(e))
    except Exception as e:
        result["errors"].append(f"Analysis engine exception: {str(e)}")

    return result

def main():
    parser = build_parser()
    args = parser.parse_args()

    result = run_apk_analysis(args.apk, args.scan_id)
    output_json = json.dumps(result, indent=2)

    if args.output:
        try:
            output_dir = os.path.dirname(os.path.abspath(args.output))
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_json)
        except Exception as e:
            sys.stderr.write(f"Failed writing output file '{args.output}': {str(e)}\n")
            sys.exit(1)
    else:
        print(output_json)

    if not result["success"]:
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
