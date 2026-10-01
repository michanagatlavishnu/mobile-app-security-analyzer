"""
Mobile App Security Analyzer - Shannon Entropy Engine
Calculates information entropy for candidate strings extracted from compiled bytecode and resources.
Detects potential high-entropy hardcoded secrets, obfuscated keys, and token payloads.
"""

import math
import re
from typing import List, Dict, Any, Tuple
from analyzers.secret_analyzer import mask_secret

IGNORED_SUBSTRINGS = (
    "http://",
    "https://",
    "schemas.android.com",
    "android.intent.",
    "com.google.android.",
    "androidx.",
    "android.support.",
    "org.apache.",
    "org.jetbrains.",
    "kotlin.",
    "Landroid/",
    "Ljava/",
    "Lkotlin/"
)

def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def scan_strings_for_entropy(
    strings: List[str],
    min_length: int = 24,
    max_length: int = 120,
    entropy_threshold: float = 4.5
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Scans a collection of strings for high-entropy tokens indicative of raw secret keys or tokens.
    Returns:
    - list of detected high-entropy token records (with masked values)
    - list of security findings
    """
    records: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    seen = set()

    for s in strings:
        s_clean = s.strip()
        if len(s_clean) < min_length or len(s_clean) > max_length:
            continue

        if any(ign in s_clean for ign in IGNORED_SUBSTRINGS):
            continue

        # Candidate must be composed of base64/hex/alphanumeric characters
        if not re.match(r"^[A-Za-z0-9+/=_\-]+$", s_clean):
            continue

        # Character diversity check (at least 14 unique characters)
        if len(set(s_clean)) < 14:
            continue

        entropy = calculate_shannon_entropy(s_clean)
        if entropy >= entropy_threshold:
            if s_clean not in seen:
                seen.add(s_clean)
                masked = mask_secret(s_clean)
                records.append({
                    "entropy": round(entropy, 2),
                    "length": len(s_clean),
                    "masked_value": masked,
                    "character_set_size": len(set(s_clean))
                })

    if records:
        # Group highest entropy finding
        highest = max(records, key=lambda x: x["entropy"])
        findings.append({
            "title": "High-Entropy Hardcoded Token or Key Detected",
            "severity": "HIGH",
            "category": "Secrets & Key Management",
            "description": f"Discovered {len(records)} high-entropy string constant(s) (entropy >= {entropy_threshold:.1f} bits) in application Dalvik bytecode. High Shannon entropy is a strong heuristic indicator of embedded cryptographic keys, authorization tokens, or encrypted blobs.",
            "evidence": f"Candidate token: {highest['masked_value']} (Shannon Entropy: {highest['entropy']:.2f}, length: {highest['length']})",
            "location": "Dalvik DEX strings",
            "impact": "Exposed credentials allow reverse engineers to authenticate against backends or decrypt sensitive local assets.",
            "recommendation": "Remove all embedded keys and tokens from the client APK. Fetch tokens dynamically after user authentication or use the Android Keystore.",
            "cwe": "CWE-798",
            "owasp_category": "M2: Insecure Data Storage",
            "confidence": "MEDIUM",
            "analyzer": "entropy_analyzer",
            "source": "classes.dex"
        })

    return records, findings
