"""
DEX File Header & Multi-DEX Metrics Inspector
Inspects Dalvik Executable (.dex) headers across all classes*.dex files,
extracts structural metrics (method, class, field, prototype, string counts),
and calculates multi-DEX aggregates.
"""

import struct
import hashlib
import re
import zipfile
from typing import Dict, Any, List, Set, Tuple

def read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Reads unsigned LEB128 integer and returns (value, next_offset)."""
    result = 0
    shift = 0
    idx = offset
    data_len = len(data)
    while idx < data_len and shift <= 35:
        byte = data[idx]
        idx += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, idx

def extract_strings_from_dex(dex_bytes: bytes) -> List[str]:
    """
    Extracts all unique strings from Dalvik DEX binary.
    Parses string_ids table and augments with raw printable string harvesting.
    """
    strings: Set[str] = set()
    data_len = len(dex_bytes)

    if data_len >= 0x70 and dex_bytes.startswith(b"dex\n"):
        try:
            string_ids_size, string_ids_off = struct.unpack_from("<II", dex_bytes, 0x38)
            if string_ids_off < data_len and (string_ids_off + (string_ids_size * 4)) <= data_len:
                for i in range(string_ids_size):
                    str_data_off = struct.unpack_from("<I", dex_bytes, string_ids_off + (i * 4))[0]
                    if str_data_off < data_len:
                        u16len, data_start = read_uleb128(dex_bytes, str_data_off)
                        null_pos = dex_bytes.find(b"\x00", data_start)
                        if null_pos != -1:
                            raw = dex_bytes[data_start:null_pos]
                        else:
                            raw = dex_bytes[data_start:data_start + 256]
                        try:
                            val = raw.decode("utf-8", errors="replace")
                            if val:
                                strings.add(val)
                        except Exception:
                            pass
        except Exception:
            pass

    # Robust printable string scanner for Dalvik bytecode constants and annotations
    raw_matches = re.findall(b"[\x20-\x7E]{4,}", dex_bytes)
    for m in raw_matches:
        try:
            s = m.decode("utf-8", errors="replace").strip()
            if s and len(s) >= 4:
                strings.add(s)
        except Exception:
            pass

    return sorted(list(strings))

def inspect_dex_bytes(dex_bytes: bytes) -> Dict[str, Any]:
    """
    Parses DEX header according to Dalvik Executable specifications.
    Header structure:
    0x00 - magic (8 bytes: 'dex\n035\0')
    0x08 - checksum (4 bytes adler32)
    0x0C - signature (20 bytes SHA-1)
    0x20 - file_size (4 bytes uint)
    0x24 - header_size (4 bytes uint, usually 0x70)
    0x28 - endian_tag (4 bytes uint, usually 0x12345678)
    0x38 - string_ids_size (4 bytes uint)
    0x3C - string_ids_off (4 bytes uint)
    0x40 - type_ids_size (4 bytes uint)
    0x48 - proto_ids_size (4 bytes uint)
    0x50 - field_ids_size (4 bytes uint)
    0x58 - method_ids_size (4 bytes uint)
    0x60 - class_defs_size (4 bytes uint)
    """
    if len(dex_bytes) < 0x70:
        return {"valid": False, "error": "DEX file too small for standard header"}

    magic = dex_bytes[:8]
    if not (magic.startswith(b"dex\n") and magic.endswith(b"\0")):
        return {"valid": False, "error": "Invalid DEX magic signature"}

    try:
        version = magic[4:7].decode("ascii", errors="replace")
        file_size, header_size, endian_tag = struct.unpack_from("<III", dex_bytes, 0x20)
        string_ids_size = struct.unpack_from("<I", dex_bytes, 0x38)[0]
        type_ids_size = struct.unpack_from("<I", dex_bytes, 0x40)[0]
        proto_ids_size = struct.unpack_from("<I", dex_bytes, 0x48)[0]
        field_ids_size = struct.unpack_from("<I", dex_bytes, 0x50)[0]
        method_ids_size = struct.unpack_from("<I", dex_bytes, 0x58)[0]
        class_defs_size = struct.unpack_from("<I", dex_bytes, 0x60)[0]

        return {
            "valid": True,
            "version": version,
            "file_size": file_size,
            "header_size": header_size,
            "string_count": string_ids_size,
            "type_count": type_ids_size,
            "proto_count": proto_ids_size,
            "field_count": field_ids_size,
            "method_count": method_ids_size,
            "class_count": class_defs_size,
            "sha256": hashlib.sha256(dex_bytes).hexdigest()
        }
    except Exception as e:
        return {"valid": False, "error": f"Error parsing DEX header: {str(e)}"}

def inspect_dex_files_in_apk(apk_path: str) -> List[Dict[str, Any]]:
    """Inspects all classes*.dex files within an APK archive."""
    dex_summaries = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            dex_names = sorted([n for n in zf.namelist() if re.match(r"^classes\d*\.dex$", n)])
            for name in dex_names:
                data = zf.read(name)
                info = inspect_dex_bytes(data)
                info["filename"] = name
                info["actual_bytes"] = len(data)
                dex_summaries.append(info)
    except Exception as e:
        dex_summaries.append({"filename": "error", "error": str(e)})

    return dex_summaries

def get_multidex_summary(dex_summaries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates aggregated metrics across all DEX files."""
    valid_dex = [d for d in dex_summaries if d.get("valid")]
    total_classes = sum(d.get("class_count", 0) for d in valid_dex)
    total_methods = sum(d.get("method_count", 0) for d in valid_dex)
    total_fields = sum(d.get("field_count", 0) for d in valid_dex)
    total_strings = sum(d.get("string_count", 0) for d in valid_dex)

    return {
        "dex_count": len(valid_dex),
        "is_multidex": len(valid_dex) > 1,
        "total_classes": total_classes,
        "total_methods": total_methods,
        "total_fields": total_fields,
        "total_strings": total_strings,
        "dalvik_64k_limit": 65536,
        "approaching_limit": any(d.get("method_count", 0) > 60000 for d in valid_dex)
    }

def extract_all_dex_strings(apk_path: str) -> Dict[str, List[str]]:
    """
    Extracts strings from all classes*.dex files inside an APK.
    Returns mapping of filename -> list of strings.
    """
    results: Dict[str, List[str]] = {}
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            dex_names = sorted([n for n in zf.namelist() if re.match(r"^classes\d*\.dex$", n)])
            for name in dex_names:
                data = zf.read(name)
                results[name] = extract_strings_from_dex(data)
    except Exception:
        pass
    return results
