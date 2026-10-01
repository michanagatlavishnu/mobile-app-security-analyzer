"""
Mobile App Security Analyzer - Secret Detection Engine
Identifies embedded API keys, tokens, credentials, and cryptographic material using
specialized regex patterns, string table parsing, and strict secret masking.
"""

import re
import zipfile
from typing import Dict, Any, List, Tuple
from utils.dex_parser import extract_all_dex_strings

def mask_secret(val: str) -> str:
    """Masks secret to prevent sensitive disclosure in reports, logs, and database."""
    val = val.strip()
    length = len(val)
    if length <= 6:
        return "*" * length
    if length <= 12:
        return val[:2] + ("*" * (length - 4)) + val[-2:]
    return val[:4] + ("*" * (min(16, length - 8))) + val[-4:]

SECRET_RULES = [
    {
        "type": "Google / Firebase API Key",
        "pattern": re.compile(r"AIza[A-Za-z0-9_-]{33,36}"),
        "severity": "HIGH",
        "cwe": "CWE-798",
        "owasp": "M2: Insecure Data Storage",
        "title": "Hardcoded Google / Firebase API Key Detected",
        "description": "A Google or Firebase API key pattern was discovered hardcoded in application binaries or assets. If not properly restricted, unauthorized parties could consume backend cloud quotas or access sensitive cloud resources.",
        "impact": "Potential unauthorized API usage, backend cloud cost amplification, and access to associated Firebase services.",
        "recommendation": "Restrict the API key in Google Cloud Console by Android package name and SHA-1 certificate fingerprint, or move sensitive operations to a secure backend."
    },
    {
        "type": "AWS Access Key",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "owasp": "M2: Insecure Data Storage",
        "title": "Hardcoded AWS Access Key ID Detected",
        "description": "An Amazon Web Services (AWS) Access Key ID was discovered in the application. Hardcoding AWS credentials inside client APKs enables full reverse engineering and AWS infrastructure compromise.",
        "impact": "Complete compromise of AWS resources, unauthorized data exfiltration, compute resource hijacking, and administrative takeover.",
        "recommendation": "Immediately revoke and rotate the compromised AWS key. Use AWS Cognito identity pools or temporary STS tokens via backend authentication."
    },
    {
        "type": "AWS Secret Access Key",
        "pattern": re.compile(r"""(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"""),
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "owasp": "M2: Insecure Data Storage",
        "title": "Hardcoded AWS Secret Key Detected",
        "description": "An AWS Secret Key assignment was detected inside application strings or resources.",
        "impact": "Direct root or IAM role compromise within the linked AWS organization.",
        "recommendation": "Rotate credentials immediately in AWS IAM and never embed secret keys in mobile client binaries."
    },
    {
        "type": "JSON Web Token (JWT)",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "severity": "HIGH",
        "cwe": "CWE-798",
        "owasp": "M2: Insecure Data Storage",
        "title": "Hardcoded JSON Web Token (JWT) Exposed",
        "description": "A signed JSON Web Token (JWT) was found embedded in application resources or bytecode. Hardcoded bearer tokens allow persistent authenticated access under the compromised identity.",
        "impact": "Account takeover, session impersonation, and unauthorized access to backend APIs.",
        "recommendation": "Issue short-lived JWT tokens dynamically during runtime authentication; never embed static tokens."
    },
    {
        "type": "Stripe API Key",
        "pattern": re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b"),
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "owasp": "M2: Insecure Data Storage",
        "title": "Hardcoded Stripe Payment Key Detected",
        "description": "A Stripe payment gateway secret or publishable key was discovered. Live secret keys allow attackers to charge cards, refund orders, or view customer financial data.",
        "impact": "Financial loss, fraudulent transactions, and PCI-DSS compliance violations.",
        "recommendation": "Revoke the key immediately from the Stripe Dashboard. Restrict client apps to Stripe Publishable Keys with restricted permissions."
    },
    {
        "type": "GitHub Token",
        "pattern": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "owasp": "M2: Insecure Data Storage",
        "title": "Hardcoded GitHub Personal Access Token",
        "description": "A GitHub personal access or OAuth token was identified. Attackers can clone private source repositories or modify infrastructure.",
        "impact": "Unauthorized source code access, supply chain tampering, and developer credential compromise.",
        "recommendation": "Revoke the token immediately through GitHub Developer Settings and audit git commit logs."
    },
    {
        "type": "Slack Token",
        "pattern": re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b"),
        "severity": "HIGH",
        "cwe": "CWE-798",
        "owasp": "M2: Insecure Data Storage",
        "title": "Hardcoded Slack Token Detected",
        "description": "A Slack bot or webhook token was found inside the APK, risking internal workspace communication intercept.",
        "impact": "Unauthorized eavesdropping on corporate communications and internal bot spoofing.",
        "recommendation": "Revoke the token in the Slack API app console and use server-side OAuth mediation."
    },
    {
        "type": "Generic Hardcoded Secret",
        "pattern": re.compile(r"""(?i)(?:api_key|apikey|client_secret|db_password|app_secret)\s*[:=]\s*["']([^"'\s]{8,64})["']"""),
        "severity": "HIGH",
        "cwe": "CWE-798",
        "owasp": "M2: Insecure Data Storage",
        "title": "Generic Hardcoded Credential Assignment",
        "description": "Code patterns indicating an API key, database password, or client secret assignment were detected.",
        "impact": "Unauthorized authentication against third-party or internal API services.",
        "recommendation": "Store secrets securely on a backend server or retrieve them dynamically using Keystore-backed encryption."
    }
]

def analyze_secrets(apk_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Scans APK bytecode (all classes*.dex) and text/resource files for embedded secrets.
    Returns:
      (findings, secrets_records)
      - findings: Formatted for vulnerabilities table & risk engine scoring
      - secrets_records: Formatted for the dedicated secrets MySQL table
    """
    findings: List[Dict[str, Any]] = []
    secrets_records: List[Dict[str, Any]] = []
    seen_secrets = set()

    # 1. Harvest DEX strings
    dex_strings = extract_all_dex_strings(apk_path)

    # 2. Harvest strings from common text/resource files
    asset_strings: Dict[str, List[str]] = {}
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for item in zf.namelist():
                lower = item.lower()
                if (
                    lower.startswith("assets/") or
                    lower.startswith("res/raw/") or
                    lower.endswith(".json") or
                    lower.endswith(".properties") or
                    lower.endswith(".env") or
                    lower.endswith(".xml") and not lower.endswith("androidmanifest.xml")
                ):
                    try:
                        raw = zf.read(item)
                        # Extract strings from resource files
                        text = raw.decode("utf-8", errors="replace")
                        asset_strings[item] = text.splitlines()
                    except Exception:
                        pass
    except Exception:
        pass

    # Helper scanner
    def scan_target_strings(location: str, string_list: List[str]):
        for text in string_list:
            if not text or len(text) < 8:
                continue

            for rule in SECRET_RULES:
                matches = rule["pattern"].findall(text)
                for match in matches:
                    raw_val = match if isinstance(match, str) else match[0]
                    raw_val = raw_val.strip()
                    if not raw_val:
                        continue

                    masked = mask_secret(raw_val)
                    key = (rule["type"], location, masked)
                    if key in seen_secrets:
                        continue
                    seen_secrets.add(key)

                    # Record for secrets table
                    secrets_records.append({
                        "secret_type": rule["type"],
                        "location": location,
                        "masked_value": masked,
                        "severity": rule["severity"]
                    })

                    # Record for vulnerabilities table
                    findings.append({
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "category": "Hardcoded Secrets",
                        "description": rule["description"],
                        "evidence": f"Found {rule['type']} in {location}: {masked}",
                        "location": location,
                        "impact": rule["impact"],
                        "recommendation": rule["recommendation"],
                        "cwe": rule["cwe"],
                        "owasp_category": rule["owasp"],
                        "confidence": "HIGH",
                        "analyzer": "secret_analyzer",
                        "source": location
                    })

    # Execute scan over DEX files
    for dex_name, strings in dex_strings.items():
        scan_target_strings(dex_name, strings)

    # Execute scan over assets/resources
    for asset_path, lines in asset_strings.items():
        scan_target_strings(asset_path, lines)

    return findings, secrets_records
