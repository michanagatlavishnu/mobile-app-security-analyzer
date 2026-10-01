"""
Component Analyzer
Analyzes exported Activities, Services, Broadcast Receivers, and Content Providers.
Extracts intent filters and flags unprotected externally accessible components and ContentProviders.
"""

from typing import Dict, Any, List, Tuple

def analyze_components(manifest_data: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Returns:
    - structured component list for the database
    - security findings regarding unprotected exported components
    """
    component_records: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    component_categories = [
        ("activity", manifest_data.get("activities", [])),
        ("service", manifest_data.get("services", [])),
        ("receiver", manifest_data.get("receivers", [])),
        ("provider", manifest_data.get("providers", []))
    ]

    for c_type, items in component_categories:
        for item in items:
            name = item.get("name") or "UnnamedComponent"
            is_exported = bool(item.get("exported", False))
            permission = item.get("permission")
            intent_filters = item.get("intent_filters", [])

            component_records.append({
                "type": c_type,
                "name": name,
                "exported": is_exported,
                "permission": permission,
                "intent_filters": intent_filters
            })

            # 1. Dedicated ContentProvider Deep Dive Audit
            if c_type == "provider":
                read_perm = item.get("readPermission")
                write_perm = item.get("writePermission")
                grant_uri = bool(item.get("grantUriPermissions", False))
                auth = item.get("authorities")

                if is_exported:
                    has_read_perm = bool(permission or read_perm)
                    has_write_perm = bool(permission or write_perm)

                    if not has_read_perm and not has_write_perm:
                        findings.append({
                            "title": "Exported ContentProvider Without Access Controls",
                            "severity": "HIGH",
                            "category": "Component Security",
                            "description": f"The ContentProvider '{name}' (authority: '{auth}') is exported to all external applications without permission, readPermission, or writePermission restrictions. Any third-party app installed on the device can query, insert, update, or delete sensitive application data.",
                            "evidence": f"Provider: {name}, exported=true, readPermission=null, writePermission=null, authorities={auth}",
                            "location": f"AndroidManifest.xml <provider android:name=\"{name}\">",
                            "impact": "Arbitrary data exposure, data tampering, or unauthorized SQL injection through exported ContentProvider query boundaries.",
                            "recommendation": "Set android:exported=\"false\" if the provider is intended for internal app use, or declare robust android:readPermission and android:writePermission.",
                            "cwe": "CWE-280",
                            "owasp_category": "M1: Improper Platform Usage",
                            "confidence": "HIGH",
                            "analyzer": "component_analyzer",
                            "source": "AndroidManifest.xml"
                        })
                    elif not has_write_perm:
                        findings.append({
                            "title": "Exported ContentProvider Lacks Write Permission",
                            "severity": "HIGH",
                            "category": "Component Security",
                            "description": f"The ContentProvider '{name}' protects read access but permits unrestricted write access to any other installed application.",
                            "evidence": f"Provider: {name}, exported=true, writePermission=null",
                            "location": f"AndroidManifest.xml <provider android:name=\"{name}\">",
                            "impact": "Data tampering or unauthorized modification of database tables and files.",
                            "recommendation": "Define android:writePermission requiring a signature-level protection.",
                            "cwe": "CWE-280",
                            "owasp_category": "M1: Improper Platform Usage",
                            "confidence": "HIGH",
                            "analyzer": "component_analyzer",
                            "source": "AndroidManifest.xml"
                        })
                    elif not has_read_perm:
                        findings.append({
                            "title": "Exported ContentProvider Lacks Read Permission",
                            "severity": "MEDIUM",
                            "category": "Component Security",
                            "description": f"The ContentProvider '{name}' protects write access but allows unrestricted query access to any other installed application.",
                            "evidence": f"Provider: {name}, exported=true, readPermission=null",
                            "location": f"AndroidManifest.xml <provider android:name=\"{name}\">",
                            "impact": "Data leakage of private database content to untrusted applications.",
                            "recommendation": "Define android:readPermission requiring a signature-level protection.",
                            "cwe": "CWE-280",
                            "owasp_category": "M1: Improper Platform Usage",
                            "confidence": "HIGH",
                            "analyzer": "component_analyzer",
                            "source": "AndroidManifest.xml"
                        })

                    if grant_uri:
                        findings.append({
                            "title": "Dynamic URI Permission Granting on Exported ContentProvider",
                            "severity": "MEDIUM",
                            "category": "Component Security",
                            "description": f"ContentProvider '{name}' specifies android:grantUriPermissions=\"true\" while being exported. If sub-paths are not strictly constrained via <grant-uri-permission>, external applications can obtain temporary unauthorized read/write access to sensitive files.",
                            "evidence": f"Provider: {name}, exported=true, grantUriPermissions=true",
                            "location": f"AndroidManifest.xml <provider android:name=\"{name}\">",
                            "impact": "Improper access control allowing sandbox isolation bypass via URI permission grants.",
                            "recommendation": "Use granular <grant-uri-permission> path-prefix rules and set android:grantUriPermissions=\"false\" at the provider root.",
                            "cwe": "CWE-732",
                            "owasp_category": "M1: Improper Platform Usage",
                            "confidence": "HIGH",
                            "analyzer": "component_analyzer",
                            "source": "AndroidManifest.xml"
                        })
                continue

            # 2. Check for other unprotected exported components (Activities, Services, Receivers)
            if is_exported and not permission:
                # Is it the main launch activity? Main launch activity MUST be exported by design
                is_main_launcher = False
                for flt in intent_filters:
                    if "android.intent.action.MAIN" in flt.get("actions", []) and "android.intent.category.LAUNCHER" in flt.get("categories", []):
                        is_main_launcher = True
                        break

                if not is_main_launcher:
                    severity = "HIGH" if c_type in ("provider", "service") else "MEDIUM"
                    findings.append({
                        "title": f"Exported {c_type.capitalize()} Without Permission Protection",
                        "severity": severity,
                        "category": "Component Security",
                        "description": f"The {c_type} '{name}' is exported to other applications (android:exported=\"true\") but is not protected by an explicit permission constraint. Any other application installed on the device can invoke this component.",
                        "evidence": f"Component: {name}, exported=true, permission=null",
                        "location": f"AndroidManifest.xml <{c_type} android:name=\"{name}\">",
                        "impact": f"Unauthorized third-party applications can interact with, launch, or manipulate this {c_type}, potentially triggering unintended background tasks or leaking state.",
                        "recommendation": f"Set android:exported=\"false\" if the {c_type} is intended only for internal application use, or declare a signature-level android:permission.",
                        "cwe": "CWE-926",
                        "owasp_category": "M3: Insecure Authentication/Authorization",
                        "confidence": "HIGH",
                        "analyzer": "component_analyzer",
                        "source": "AndroidManifest.xml"
                    })

    return component_records, findings
