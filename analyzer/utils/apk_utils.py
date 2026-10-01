import os
import hashlib
import zipfile
import tempfile
import shutil

class ApkValidationError(Exception):
    """Raised when APK file validation fails."""
    pass

def validate_apk_file(apk_path: str) -> None:
    """
    Validates that the file exists, is readable, and has a .apk extension.
    """
    if not apk_path:
        raise ApkValidationError("APK path cannot be empty.")

    if not os.path.exists(apk_path):
        raise ApkValidationError(f"File not found: '{apk_path}'")

    if not os.path.isfile(apk_path):
        raise ApkValidationError(f"Path is not a regular file: '{apk_path}'")

    if not apk_path.lower().endswith(".apk"):
        raise ApkValidationError("File extension must be .apk")

    if os.path.getsize(apk_path) == 0:
        raise ApkValidationError("APK file is empty (0 bytes).")

def calculate_sha256(file_path: str) -> str:
    """
    Computes SHA-256 hash of a file efficiently using chunked reads.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def verify_zip_integrity(apk_path: str) -> bool:
    """
    Verifies that the APK is a valid, non-corrupted ZIP archive.
    """
    if not zipfile.is_zipfile(apk_path):
        return False
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            # testzip() returns the name of the first corrupted file, or None if all is well
            return zf.testzip() is None
    except Exception:
        return False

def list_zip_entries(apk_path: str) -> list:
    """
    Safely lists all entry filenames in the APK archive.
    """
    with zipfile.ZipFile(apk_path, "r") as zf:
        return zf.namelist()

def safe_extract_apk(apk_path: str, target_dir: str = None) -> str:
    """
    Safely extracts APK entries to an isolated directory with path traversal protection (Zip Slip).
    """
    if target_dir is None:
        target_dir = tempfile.mkdtemp(prefix="apk_sec_")

    target_dir = os.path.abspath(target_dir)

    with zipfile.ZipFile(apk_path, "r") as zf:
        for member in zf.infolist():
            # Sanitize member name
            entry_name = member.filename
            
            # Reject absolute paths or path traversal markers
            if entry_name.startswith("/") or entry_name.startswith("\\") or ".." in entry_name:
                continue

            destination_path = os.path.abspath(os.path.join(target_dir, entry_name))

            # Strictly verify destination stays inside the target directory
            if not destination_path.startswith(target_dir + os.sep) and destination_path != target_dir:
                continue

            if member.is_dir():
                os.makedirs(destination_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(destination_path), exist_ok=True)
                with zf.open(member) as source, open(destination_path, "wb") as target:
                    shutil.copyfileobj(source, target)

    return target_dir
