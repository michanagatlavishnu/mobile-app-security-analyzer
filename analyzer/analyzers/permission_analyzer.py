"""
Permission Analyzer
Inspects requested Android permissions, categorizes sensitivity, and extracts risk tiers.
"""

from typing import Dict, Any, List

# Standard Android Permission Sensitivity Dictionary
PERMISSION_METADATA = {
    "android.permission.CAMERA": {
        "protection": "dangerous",
        "risk": "HIGH",
        "description": "Allows application to capture photos and videos using the device camera."
    },
    "android.permission.RECORD_AUDIO": {
        "protection": "dangerous",
        "risk": "CRITICAL",
        "description": "Allows application to access microphone and record ambient audio."
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "protection": "dangerous",
        "risk": "HIGH",
        "description": "Allows application to pinpoint precise GPS geographic coordinates."
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "protection": "dangerous",
        "risk": "MEDIUM",
        "description": "Allows application to approximate location using cell towers and Wi-Fi."
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "protection": "dangerous",
        "risk": "CRITICAL",
        "description": "Allows persistent location monitoring when the application is in the background."
    },
    "android.permission.READ_CONTACTS": {
        "protection": "dangerous",
        "risk": "HIGH",
        "description": "Allows application to read user contact list and personal address book."
    },
    "android.permission.WRITE_CONTACTS": {
        "protection": "dangerous",
        "risk": "HIGH",
        "description": "Allows application to modify, add, or delete stored contact records."
    },
    "android.permission.READ_SMS": {
        "protection": "dangerous",
        "risk": "CRITICAL",
        "description": "Allows application to read SMS messages, potentially exposing 2FA OTP tokens."
    },
    "android.permission.SEND_SMS": {
        "protection": "dangerous",
        "risk": "CRITICAL",
        "description": "Allows application to dispatch SMS messages without user confirmation (toll fraud risk)."
    },
    "android.permission.RECEIVE_SMS": {
        "protection": "dangerous",
        "risk": "CRITICAL",
        "description": "Allows application to intercept incoming SMS messages."
    },
    "android.permission.READ_PHONE_STATE": {
        "protection": "dangerous",
        "risk": "HIGH",
        "description": "Allows access to cellular state, carrier information, and unique hardware identifiers."
    },
    "android.permission.CALL_PHONE": {
        "protection": "dangerous",
        "risk": "HIGH",
        "description": "Allows placing outgoing telephone calls without going through the Dialer UI."
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "protection": "dangerous",
        "risk": "HIGH",
        "description": "Allows reading files stored across shared external storage directories."
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "protection": "dangerous",
        "risk": "HIGH",
        "description": "Allows writing and modifying files in shared external storage."
    },
    "android.permission.READ_MEDIA_IMAGES": {
        "protection": "dangerous",
        "risk": "HIGH",
        "description": "Allows granular access to user photo libraries on modern Android versions."
    },
    "android.permission.READ_MEDIA_VIDEO": {
        "protection": "dangerous",
        "risk": "HIGH",
        "description": "Allows granular access to user video recordings on modern Android versions."
    },
    "android.permission.BLUETOOTH_CONNECT": {
        "protection": "dangerous",
        "risk": "MEDIUM",
        "description": "Allows connecting to paired Bluetooth peripherals."
    },
    "android.permission.BLUETOOTH_SCAN": {
        "protection": "dangerous",
        "risk": "MEDIUM",
        "description": "Allows discovering nearby Bluetooth hardware, often used for indoor tracking."
    },
    "android.permission.INTERNET": {
        "protection": "normal",
        "risk": "SAFE",
        "description": "Allows opening network sockets to the Internet."
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "protection": "normal",
        "risk": "SAFE",
        "description": "Allows viewing information about network connectivity."
    },
    "android.permission.VIBRATE": {
        "protection": "normal",
        "risk": "SAFE",
        "description": "Allows haptic vibrator control."
    },
    "android.permission.WAKE_LOCK": {
        "protection": "normal",
        "risk": "SAFE",
        "description": "Allows keeping processor awake."
    }
}

def analyze_permissions(requested_permissions: List[str]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for perm in requested_permissions:
        meta = PERMISSION_METADATA.get(perm)
        if meta:
            results.append({
                "permission": perm,
                "protection": meta["protection"],
                "risk": meta["risk"],
                "description": meta["description"]
            })
        else:
            # Custom or unrecognized permission
            is_custom = not perm.startswith("android.permission.")
            results.append({
                "permission": perm,
                "protection": "custom" if is_custom else "unknown",
                "risk": "LOW" if is_custom else "SAFE",
                "description": "Custom or third-party application permission definition." if is_custom else "Standard system permission."
            })

    return results
