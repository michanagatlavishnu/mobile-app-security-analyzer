"""
Mobile App Security Analyzer - Network Intelligence Engine
Extracts endpoints, detects unencrypted cleartext HTTP communications,
identifies staging/internal IPs, and audits Android Network Security Configurations.
"""

import re
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Tuple, Set
from utils.dex_parser import extract_all_dex_strings

# Standard XML namespaces and common schemas to ignore
IGNORED_URL_PREFIXES = (
    "http://schemas.android.com/",
    "http://www.w3.org/",
    "http://apache.org/",
    "http://xml.org/",
    "http://www.w3.org/2000/xmlns/",
    "https://schemas.android.com/",
)

URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://)[a-z0-9\-\._~%!$&'()*+,;=:@]+(?::\d+)?(?:/[^\s<>"'{}|\\^`\[\]]*)?)""",
    re.IGNORECASE
)

IP_ENDPOINT_REGEX = re.compile(
    r"""(?i)\b(?:https?://)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?(?:\S*)\b"""
)

INTERNAL_DEV_REGEX = re.compile(
    r"""(?i)\b(?:https?://)?[a-z0-9\-]+(?:\.local|\.dev|\.internal|\.test|localhost)(?::\d+)?(?:\S*)\b"""
)

def analyze_network(apk_path: str, manifest_data: Dict[str, Any] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Analyzes application network posture:
    1. Extracts URLs and endpoints from DEX strings and resources
    2. Identifies unencrypted HTTP endpoints
    3. Identifies hardcoded IP addresses & internal/staging domains
    4. Audits Network Security Configuration XML files
    """
    findings: List[Dict[str, Any]] = []
    network_records: List[Dict[str, Any]] = []

    seen_urls: Set[str] = set()
    dex_strings = extract_all_dex_strings(apk_path)

    # 1. Harvest URLs from all DEX strings
    raw_endpoints: List[Tuple[str, str]] = []  # (source_location, url)
    for dex_name, strings in dex_strings.items():
        for s in strings:
            if "http://" in s or "https://" in s:
                matches = URL_REGEX.findall(s)
                for u in matches:
                    u_clean = u.rstrip(".,;:)\"'>")
                    if u_clean.startswith(IGNORED_URL_PREFIXES):
                        continue
                    raw_endpoints.append((dex_name, u_clean))

    # 2. Check XML resources for Network Security Config and additional URLs
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for item in zf.namelist():
                lower = item.lower()
                if "network_security_config" in lower and lower.endswith(".xml"):
                    try:
                        xml_bytes = zf.read(item)
                        # Check if plaintext XML or binary
                        if xml_bytes.startswith(b"<?xml") or b"<network-security-config" in xml_bytes:
                            root = ET.fromstring(xml_bytes.decode("utf-8", errors="replace"))
                            # Check cleartextTrafficPermitted
                            for elem in root.iter():
                                if elem.attrib.get("cleartextTrafficPermitted", "").lower() == "true":
                                    network_records.append({
                                        "type": "Cleartext Traffic Allowed in Config",
                                        "severity": "HIGH",
                                        "description": f"Network security config ({item}) explicitly permits cleartext traffic.",
                                        "evidence": ET.tostring(elem, encoding="unicode")[:200]
                                    })
                                    findings.append({
                                        "title": "Network Security Config Permits Cleartext HTTP",
                                        "severity": "HIGH",
                                        "category": "Network Security",
                                        "description": "The application network_security_config.xml explicitly permits cleartext HTTP network traffic.",
                                        "evidence": f"File {item}: cleartextTrafficPermitted=true",
                                        "location": item,
                                        "impact": "Network adversaries can eavesdrop on or manipulate unencrypted HTTP traffic.",
                                        "recommendation": "Set cleartextTrafficPermitted='false' to enforce TLS for all network connections.",
                                        "cwe": "CWE-319",
                                        "owasp_category": "M3: Insecure Communication",
                                        "confidence": "HIGH",
                                        "analyzer": "network_analyzer",
                                        "source": item
                                    })
                                # Check user cert trust anchors
                                if elem.tag == "certificates" and elem.attrib.get("src") == "user":
                                    network_records.append({
                                        "type": "User CA Trust Enabled",
                                        "severity": "MEDIUM",
                                        "description": f"Network security config trusts user-installed CA certificates.",
                                        "evidence": ET.tostring(elem, encoding="unicode")[:200]
                                    })
                                    findings.append({
                                        "title": "User-Installed CA Certificates Trusted in Network Config",
                                        "severity": "MEDIUM",
                                        "category": "Network Security",
                                        "description": "Application explicitly trusts user-installed CA certificates, facilitating MitM proxies.",
                                        "evidence": f"File {item}: <certificates src=\"user\" />",
                                        "location": item,
                                        "impact": "Facilitates Man-in-the-Middle traffic interception using custom CA certificates on untrusted devices.",
                                        "recommendation": "Only trust system CA certificates in production builds; limit user cert trust to debug builds.",
                                        "cwe": "CWE-295",
                                        "owasp_category": "M3: Insecure Communication",
                                        "confidence": "HIGH",
                                        "analyzer": "network_analyzer",
                                        "source": item
                                    })
                    except Exception:
                        pass

                # Scan text resources for URLs
                if lower.startswith("assets/") or lower.startswith("res/values/"):
                    try:
                        content = zf.read(item).decode("utf-8", errors="replace")
                        matches = URL_REGEX.findall(content)
                        for u in matches:
                            u_clean = u.rstrip(".,;:)\"'>")
                            if not u_clean.startswith(IGNORED_URL_PREFIXES):
                                raw_endpoints.append((item, u_clean))
                    except Exception:
                        pass
    except Exception:
        pass

    # 3. Categorize Endpoints
    http_count = 0
    ip_endpoints: List[str] = []
    dev_endpoints: List[str] = []

    for loc, url in raw_endpoints:
        if url in seen_urls:
            continue
        seen_urls.add(url)

        # Insecure Cleartext HTTP
        if url.lower().startswith("http://"):
            http_count += 1
            network_records.append({
                "type": "Cleartext HTTP URL",
                "severity": "HIGH",
                "description": f"Unencrypted HTTP URL endpoint discovered in bytecode or resources: {url}",
                "evidence": f"Location: {loc} | Endpoint: {url}"
            })

        # Hardcoded IP Endpoint
        if IP_ENDPOINT_REGEX.search(url):
            ip_endpoints.append(url)
            network_records.append({
                "type": "Hardcoded IP Address Endpoint",
                "severity": "MEDIUM",
                "description": f"Direct IP address endpoint found instead of domain name: {url}",
                "evidence": f"Location: {loc} | Endpoint: {url}"
            })

        # Internal/Staging Endpoint
        if INTERNAL_DEV_REGEX.search(url):
            dev_endpoints.append(url)
            network_records.append({
                "type": "Development / Staging Endpoint",
                "severity": "MEDIUM",
                "description": f"Internal or pre-production domain identified: {url}",
                "evidence": f"Location: {loc} | Endpoint: {url}"
            })

    # Consolidate cleartext finding if present
    if http_count > 0:
        sample_urls = [u for u in seen_urls if u.startswith("http://")][:5]
        evidence_text = f"Found {http_count} cleartext HTTP URL(s). Examples: " + ", ".join(sample_urls)
        findings.append({
            "title": "Cleartext HTTP Endpoints Discovered",
            "severity": "HIGH",
            "category": "Insecure Communication",
            "description": f"The application contains {http_count} unencrypted HTTP URLs in its compiled strings or resources.",
            "evidence": evidence_text,
            "location": "Bytecode & Resources",
            "impact": "Traffic sent to cleartext endpoints is vulnerable to eavesdropping, credential interception, and injection attacks.",
            "recommendation": "Migrate all HTTP endpoints to HTTPS and enforce TLS 1.3 or 1.2 across all network communications.",
            "cwe": "CWE-319",
            "owasp_category": "M3: Insecure Communication",
            "confidence": "HIGH",
            "analyzer": "network_analyzer",
            "source": "network_analyzer"
        })

    if ip_endpoints:
        findings.append({
            "title": "Hardcoded IP Address Endpoints Detected",
            "severity": "MEDIUM",
            "category": "Network Security",
            "description": f"The application communicates directly with raw IP addresses ({len(ip_endpoints)} found).",
            "evidence": f"Discovered IP endpoints: {', '.join(ip_endpoints[:4])}",
            "location": "Bytecode & Resources",
            "impact": "Direct IP communication bypasses DNS-based security controls and makes certificate validation difficult or impossible.",
            "recommendation": "Use valid fully qualified domain names (FQDNs) with properly signed TLS certificates.",
            "cwe": "CWE-295",
            "owasp_category": "M3: Insecure Communication",
            "confidence": "HIGH",
            "analyzer": "network_analyzer",
            "source": "network_analyzer"
        })

    return findings, network_records
