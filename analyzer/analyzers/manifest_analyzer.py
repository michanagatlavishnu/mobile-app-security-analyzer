"""
Manifest Analyzer
Audits AndroidManifest configuration for security weaknesses (debuggable, allowBackup, cleartext traffic, legacy storage).
"""

import os
import json
from typing import Dict, Any, List

def load_policy() -> Dict[str, Any]:
    policy_path = os.path.join(os.path.dirname(__file__), "..", "utils", "security_policy.json")
    if os.path.exists(policy_path):
        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"minimum_recommended_target_sdk": 34, "deprecated_target_sdk": 28}

def analyze_manifest(manifest_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    policy = load_policy()

    app = manifest_data.get("application", {})

    # 1. Debuggable Application
    if app.get("debuggable") is True:
        findings.append({
            "title": "Debuggable Application",
            "severity": "HIGH",
            "category": "Configuration Security",
            "description": "The application has android:debuggable enabled. Debuggable applications expose Java Debug Wire Protocol (JDWP) ports and allow attackers to attach debuggers, extract process memory, inject arbitrary code, and bypass runtime security controls.",
            "evidence": "android:debuggable=true in <application>",
            "location": "AndroidManifest.xml <application>",
            "impact": "Attackers with physical access or ADB enabled can execute arbitrary code within the app's UID and access all sandbox data.",
            "recommendation": "Ensure android:debuggable is set to false in release builds, typically handled automatically by Android Gradle plugin build types.",
            "cwe": "CWE-215",
            "owasp_category": "M7: Insufficient Binary Protections",
            "confidence": "high"
        })

    # 2. Backup Enabled
    if app.get("allowBackup") is True:
        findings.append({
            "title": "Application Data Backup Enabled",
            "severity": "LOW",
            "category": "Data Storage Security",
            "description": "The application has android:allowBackup enabled without explicit exclusions. Users or attackers with ADB access can backup application data including SharedPreferences, databases, and private files using adb backup.",
            "evidence": "android:allowBackup=true in <application>",
            "location": "AndroidManifest.xml <application>",
            "impact": "Potential data extraction from private application sandbox via ADB backup utilities.",
            "recommendation": "Set android:allowBackup=\"false\" if the application stores sensitive user tokens or authentication state, or specify custom backup rules using android:fullBackupContent.",
            "cwe": "CWE-538",
            "owasp_category": "M8: Security Misconfiguration",
            "confidence": "medium"
        })

    # 3. Cleartext Traffic Allowed
    if app.get("usesCleartextTraffic") is True:
        findings.append({
            "title": "Cleartext Network Traffic Enabled",
            "severity": "HIGH",
            "category": "Network Security",
            "description": "The application explicitly permits unencrypted HTTP traffic by specifying android:usesCleartextTraffic=\"true\". On Android 9 (API 28) and higher, cleartext traffic is disabled by default.",
            "evidence": "android:usesCleartextTraffic=true in <application>",
            "location": "AndroidManifest.xml <application>",
            "impact": "Network adversaries positioned on the local network (e.g. public Wi-Fi) can passively sniff or tamper with transmitted data via Man-in-the-Middle (MITM) attacks.",
            "recommendation": "Enforce HTTPS transport encryption for all communications and configure a restrictive Network Security Configuration XML resource.",
            "cwe": "CWE-319",
            "owasp_category": "M5: Insecure Communication",
            "confidence": "high"
        })

    # 4. Target SDK Level Analysis
    target_sdk = manifest_data.get("targetSdkVersion")
    if target_sdk is not None:
        try:
            target_sdk_int = int(target_sdk)
            min_recommended = policy.get("minimum_recommended_target_sdk", 34)
            deprecated_sdk = policy.get("deprecated_target_sdk", 28)

            if target_sdk_int < deprecated_sdk:
                findings.append({
                    "title": "Severely Outdated Target SDK Version",
                    "severity": "MEDIUM",
                    "category": "Platform Configuration",
                    "description": f"The application targets API level {target_sdk_int}, which is below the deprecated SDK threshold ({deprecated_sdk}). Older API levels lack critical platform-level security mitigations such as scoped storage, background execution limits, and mandatory TLS.",
                    "evidence": f"android:targetSdkVersion={target_sdk_int}",
                    "location": "AndroidManifest.xml <uses-sdk>",
                    "impact": "The application opts out of modern platform security enhancements and vulnerability mitigations introduced in newer Android versions.",
                    "recommendation": f"Update targetSdkVersion to the current Android release level (recommended API {min_recommended}+).",
                    "cwe": "CWE-1104",
                    "owasp_category": "M8: Security Misconfiguration",
                    "confidence": "high"
                })
            elif target_sdk_int < min_recommended:
                findings.append({
                    "title": "Target SDK Version Below Recommended Level",
                    "severity": "LOW",
                    "category": "Platform Configuration",
                    "description": f"The application targets API level {target_sdk_int}. Google Play and security policies recommend targeting at least API {min_recommended}.",
                    "evidence": f"android:targetSdkVersion={target_sdk_int} (Recommended: {min_recommended})",
                    "location": "AndroidManifest.xml <uses-sdk>",
                    "impact": "May not benefit from the latest platform runtime privacy protections.",
                    "recommendation": f"Upgrade targetSdkVersion in build.gradle to API {min_recommended}.",
                    "cwe": "CWE-1104",
                    "owasp_category": "M8: Security Misconfiguration",
                    "confidence": "medium"
                })
        except (ValueError, TypeError):
            pass

    # 5. Legacy External Storage Request
    if app.get("requestLegacyExternalStorage") is True:
        findings.append({
            "title": "Legacy External Storage Requested",
            "severity": "LOW",
            "category": "Data Storage Security",
            "description": "The application opts out of Android Scoped Storage by setting android:requestLegacyExternalStorage=\"true\".",
            "evidence": "android:requestLegacyExternalStorage=true in <application>",
            "location": "AndroidManifest.xml <application>",
            "impact": "Permits broader read/write access to shared external storage directories, increasing exposure of cached files.",
            "recommendation": "Adopt Android Scoped Storage APIs (MediaStore / Storage Access Framework) and remove requestLegacyExternalStorage.",
            "cwe": "CWE-276",
            "owasp_category": "M9: Insecure Data Storage",
            "confidence": "high"
        })

    # 6. Task Reparenting Analysis (StrandHogg / Task Hijacking)
    if app.get("allowTaskReparenting") is True:
        findings.append({
            "title": "Application Task Reparenting Enabled",
            "severity": "MEDIUM",
            "category": "Component Security",
            "description": "The application enables android:allowTaskReparenting=\"true\" at the application level. An activity can be reparented from the task that started it to the task for which it has affinity when that task is brought to the foreground, which can be abused for Task Hijacking (StrandHogg).",
            "evidence": "android:allowTaskReparenting=true in <application>",
            "location": "AndroidManifest.xml <application>",
            "impact": "Malicious background apps can hijack task stacks to disguise malicious activities as legitimate app interfaces.",
            "recommendation": "Set android:allowTaskReparenting=\"false\" unless cross-task reparenting is explicitly required by application architecture.",
            "cwe": "CWE-1021",
            "owasp_category": "M1: Improper Platform Usage",
            "confidence": "high"
        })

    # 7. Activity-Specific Task Affinity and Launch Mode Audits
    for act in manifest_data.get("activities", []):
        act_name = act.get("name", "UnnamedActivity")
        is_exported = act.get("exported", False)
        perm = act.get("permission")
        launch_mode = act.get("launchMode")
        affinity = act.get("taskAffinity")
        reparenting = act.get("allowTaskReparenting")

        if reparenting is True and not app.get("allowTaskReparenting"):
            findings.append({
                "title": "Activity Task Reparenting Enabled",
                "severity": "MEDIUM",
                "category": "Component Security",
                "description": f"Activity '{act_name}' specifies android:allowTaskReparenting=\"true\", enabling task reparenting when a task with matching affinity moves to foreground.",
                "evidence": f"Activity: {act_name}, allowTaskReparenting=true",
                "location": f"AndroidManifest.xml <activity android:name=\"{act_name}\">",
                "impact": "Potential UI spoofing or task hijacking by co-located third-party apps.",
                "recommendation": "Disable allowTaskReparenting for sensitive activities.",
                "cwe": "CWE-1021",
                "owasp_category": "M1: Improper Platform Usage",
                "confidence": "high"
            })

        if is_exported and not perm and launch_mode in ("singleTask", "singleInstance"):
            findings.append({
                "title": f"Exported Activity Configured with {launch_mode} Launch Mode",
                "severity": "MEDIUM",
                "category": "Component Security",
                "description": f"Activity '{act_name}' is exported without permission controls and uses launchMode='{launch_mode}'. An attacker can manipulate task state, deliver unexpected intents to onNewIntent(), or perform Intent spoofing.",
                "evidence": f"Activity: {act_name}, exported=true, launchMode={launch_mode}",
                "location": f"AndroidManifest.xml <activity android:name=\"{act_name}\">",
                "impact": "Intent spoofing and task state corruption by unauthorized external callers.",
                "recommendation": "Protect the exported activity with a signature permission or change launchMode to standard if not required.",
                "cwe": "CWE-926",
                "owasp_category": "M1: Improper Platform Usage",
                "confidence": "high"
            })

    return findings
