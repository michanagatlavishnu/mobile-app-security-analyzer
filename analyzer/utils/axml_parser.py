"""
Binary Android XML (AXML) Parser
Decodes AndroidManifest.xml binary format directly into a structured Python dictionary.
Fully compliant with Android AXML chunk specifications:
- RES_XML_TYPE (0x0003)
- RES_STRING_POOL_TYPE (0x0001)
- RES_XML_RESOURCE_MAP_TYPE (0x0180)
- RES_XML_START_NAMESPACE_TYPE (0x0100)
- RES_XML_END_NAMESPACE_TYPE (0x0101)
- RES_XML_START_ELEMENT_TYPE (0x0102)
- RES_XML_END_ELEMENT_TYPE (0x0103)
- Typed value resolution (Boolean, Integer, String, Hex, References)
"""

import struct
from typing import Dict, Any, List, Optional

# Chunk types
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003

RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# Typed values
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_DYNAMIC_ATTRIBUTE = 0x08
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

class StringPool:
    def __init__(self, data: bytes, offset: int):
        self.strings: List[str] = []
        chunk_type, header_size, size = struct.unpack_from("<HHI", data, offset)
        if chunk_type != RES_STRING_POOL_TYPE:
            raise ValueError(f"Invalid string pool chunk type: 0x{chunk_type:04x}")

        string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
            "<IIIII", data, offset + 8
        )
        is_utf8 = bool(flags & (1 << 8))

        string_offsets = []
        for i in range(string_count):
            str_off = struct.unpack_from("<I", data, offset + 28 + (i * 4))[0]
            string_offsets.append(str_off)

        base_offset = offset + strings_start
        for str_off in string_offsets:
            curr_pos = base_offset + str_off
            if curr_pos >= len(data):
                self.strings.append("")
                continue

            if is_utf8:
                u16len = data[curr_pos]
                curr_pos += 1
                if u16len & 0x80:
                    curr_pos += 1
                u8len = data[curr_pos]
                curr_pos += 1
                if u8len & 0x80:
                    u8len = ((u8len & 0x7F) << 8) | data[curr_pos]
                    curr_pos += 1
                try:
                    str_val = data[curr_pos : curr_pos + u8len].decode("utf-8", errors="replace")
                except Exception:
                    str_val = ""
            else:
                u16len = struct.unpack_from("<H", data, curr_pos)[0]
                curr_pos += 2
                if u16len & 0x8000:
                    u16len = ((u16len & 0x7FFF) << 16) | struct.unpack_from("<H", data, curr_pos)[0]
                    curr_pos += 2
                byte_len = u16len * 2
                try:
                    str_val = data[curr_pos : curr_pos + byte_len].decode("utf-16le", errors="replace")
                except Exception:
                    str_val = ""
            self.strings.append(str_val)

    def get(self, idx: int) -> Optional[str]:
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return None


def format_typed_value(data_type: int, data_value: int, string_pool: StringPool) -> Any:
    """Decodes typed values from Android binary XML attribute specifications."""
    if data_type == TYPE_STRING:
        return string_pool.get(data_value)
    elif data_type == TYPE_INT_BOOLEAN:
        return bool(data_value != 0)
    elif data_type == TYPE_INT_DEC:
        return int(data_value)
    elif data_type == TYPE_INT_HEX:
        return hex(data_value)
    elif data_type == TYPE_REFERENCE:
        return f"@0x{data_value:08x}"
    elif data_type == TYPE_NULL:
        return None
    return data_value


class AxmlParser:
    def __init__(self, raw_bytes: bytes):
        self.data = raw_bytes
        self.offset = 0
        self.string_pool: Optional[StringPool] = None
        self.resource_ids: List[int] = []

    def parse(self) -> Dict[str, Any]:
        """Parses AXML binary data into structured dictionary tree."""
        if not self.data or len(self.data) < 8:
            return {"error": "Binary XML too small"}
        try:
            return self._parse_internal()
        except Exception as e:
            return {"error": f"Malformed binary XML: {str(e)}"}

    def _parse_internal(self) -> Dict[str, Any]:
        chunk_type, header_size, file_size = struct.unpack_from("<HHI", self.data, 0)
        if chunk_type != RES_XML_TYPE:
            if self.data.lstrip().startswith(b"<"):
                return self._parse_plaintext_xml()
            return {"error": f"Invalid XML header type 0x{chunk_type:04x}, expected 0x0003"}

        self.offset = header_size
        elements_stack: List[Dict[str, Any]] = []
        root_element: Optional[Dict[str, Any]] = None

        while self.offset < len(self.data):
            if self.offset + 8 > len(self.data):
                break

            chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", self.data, self.offset)
            if chunk_size == 0 or self.offset + chunk_size > len(self.data) + 4:
                break

            if chunk_type == RES_STRING_POOL_TYPE:
                self.string_pool = StringPool(self.data, self.offset)

            elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
                res_count = (chunk_size - header_size) // 4
                for i in range(res_count):
                    res_id = struct.unpack_from("<I", self.data, self.offset + header_size + (i * 4))[0]
                    self.resource_ids.append(res_id)

            elif chunk_type == RES_XML_START_ELEMENT_TYPE:
                # RES_XML_START_ELEMENT_TYPE payload layout:
                # Standard chunk header: chunk_type(2), header_size(2), chunk_size(4) -> 8 bytes
                # lineNumber(4), commentIndex(4) -> 8 bytes (total 16 bytes = header_size)
                # ns_idx(4), name_idx(4), attr_start(2), attr_size(2), attr_count(2), idIndex(2), classIndex(2), styleIndex(2)
                ns_idx, name_idx, attr_start, attr_size, attr_count = struct.unpack_from(
                    "<IIHHH", self.data, self.offset + 16
                )
                tag_name = self.string_pool.get(name_idx) if self.string_pool else f"tag_{name_idx}"

                attributes: Dict[str, Any] = {}
                raw_attrs: List[Dict[str, Any]] = []
                attr_offset = self.offset + 16 + attr_start

                for i in range(attr_count):
                    curr_attr_pos = attr_offset + (i * attr_size if attr_size else i * 20)
                    if curr_attr_pos + 20 > len(self.data):
                        break

                    a_ns, a_name, a_val_str, a_type_full, a_data = struct.unpack_from(
                        "<IIIII", self.data, curr_attr_pos
                    )
                    a_type = (a_type_full >> 24) & 0xFF
                    attr_name = self.string_pool.get(a_name) if self.string_pool else f"attr_{a_name}"
                    attr_val = format_typed_value(a_type, a_data, self.string_pool)
                    if attr_val is None and a_val_str != 0xFFFFFFFF and self.string_pool:
                        attr_val = self.string_pool.get(a_val_str)

                    attributes[attr_name] = attr_val
                    raw_attrs.append({
                        "name": attr_name,
                        "value": attr_val,
                        "type": a_type,
                        "rawValue": a_data
                    })

                node = {
                    "tag": tag_name,
                    "attributes": attributes,
                    "children": []
                }

                if elements_stack:
                    elements_stack[-1]["children"].append(node)
                else:
                    root_element = node

                elements_stack.append(node)

            elif chunk_type == RES_XML_END_ELEMENT_TYPE:
                if elements_stack:
                    elements_stack.pop()

            self.offset += chunk_size

        return self._structure_manifest(root_element)

    def _parse_plaintext_xml(self) -> Dict[str, Any]:
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(self.data)
            def xml_to_dict(node):
                clean_attrs = {}
                for k, v in node.attrib.items():
                    attr_name = k.split("}")[-1] if "}" in k else k
                    clean_attrs[attr_name] = v
                return {
                    "tag": node.tag.split("}")[-1] if "}" in node.tag else node.tag,
                    "attributes": clean_attrs,
                    "children": [xml_to_dict(c) for c in node]
                }
            return self._structure_manifest(xml_to_dict(root))
        except Exception as e:
            return {"error": f"Failed parsing plaintext XML fallback: {str(e)}"}

    def _structure_manifest(self, root: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not root:
            return {"error": "Empty or corrupted manifest node tree"}

        result: Dict[str, Any] = {
            "package": root["attributes"].get("package", ""),
            "versionCode": root["attributes"].get("versionCode"),
            "versionName": root["attributes"].get("versionName"),
            "minSdkVersion": None,
            "targetSdkVersion": None,
            "application": {
                "debuggable": False,
                "allowBackup": True,
                "usesCleartextTraffic": False,
                "networkSecurityConfig": None,
                "label": None,
                "icon": None,
                "requestLegacyExternalStorage": False
            },
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": []
        }

        for child in root.get("children", []):
            tag = child.get("tag")
            attrs = child.get("attributes", {})

            if tag == "uses-sdk":
                result["minSdkVersion"] = attrs.get("minSdkVersion")
                result["targetSdkVersion"] = attrs.get("targetSdkVersion")

            elif tag in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"):
                perm_name = attrs.get("name")
                if perm_name and perm_name not in result["permissions"]:
                    result["permissions"].append(perm_name)

            elif tag == "application":
                app_attrs = attrs
                result["application"]["debuggable"] = bool(app_attrs.get("debuggable", False))
                result["application"]["allowBackup"] = bool(app_attrs.get("allowBackup", True))
                result["application"]["usesCleartextTraffic"] = bool(app_attrs.get("usesCleartextTraffic", False))
                result["application"]["networkSecurityConfig"] = app_attrs.get("networkSecurityConfig")
                result["application"]["label"] = app_attrs.get("label")
                result["application"]["icon"] = app_attrs.get("icon")
                result["application"]["allowTaskReparenting"] = bool(app_attrs.get("allowTaskReparenting", False))
                result["application"]["taskAffinity"] = app_attrs.get("taskAffinity")
                result["application"]["requestLegacyExternalStorage"] = bool(app_attrs.get("requestLegacyExternalStorage", False))

                for comp in child.get("children", []):
                    c_tag = comp.get("tag")
                    c_attrs = comp.get("attributes", {})
                    c_name = c_attrs.get("name")

                    intent_filters = []
                    for if_child in comp.get("children", []):
                        if if_child.get("tag") == "intent-filter":
                            filter_data = {"actions": [], "categories": [], "data": []}
                            for item in if_child.get("children", []):
                                if item.get("tag") == "action" and "name" in item.get("attributes", {}):
                                    filter_data["actions"].append(item["attributes"]["name"])
                                elif item.get("tag") == "category" and "name" in item.get("attributes", {}):
                                    filter_data["categories"].append(item["attributes"]["name"])
                                elif item.get("tag") == "data":
                                    filter_data["data"].append(item.get("attributes", {}))
                            intent_filters.append(filter_data)

                    exported_val = c_attrs.get("exported")
                    if exported_val is not None:
                        is_exported = bool(exported_val)
                    else:
                        is_exported = len(intent_filters) > 0

                    component_item = {
                        "name": c_name,
                        "exported": is_exported,
                        "permission": c_attrs.get("permission"),
                        "intent_filters": intent_filters
                    }

                    if c_tag == "activity" or c_tag == "activity-alias":
                        component_item["taskAffinity"] = c_attrs.get("taskAffinity")
                        component_item["allowTaskReparenting"] = c_attrs.get("allowTaskReparenting")
                        component_item["launchMode"] = c_attrs.get("launchMode")
                        result["activities"].append(component_item)
                    elif c_tag == "service":
                        result["services"].append(component_item)
                    elif c_tag == "receiver":
                        result["receivers"].append(component_item)
                    elif c_tag == "provider":
                        component_item["authorities"] = c_attrs.get("authorities")
                        component_item["readPermission"] = c_attrs.get("readPermission")
                        component_item["writePermission"] = c_attrs.get("writePermission")
                        component_item["grantUriPermissions"] = bool(c_attrs.get("grantUriPermissions", False))
                        result["providers"].append(component_item)

        return result


def parse_manifest_bytes(manifest_bytes: bytes) -> Dict[str, Any]:
    try:
        parser = AxmlParser(manifest_bytes)
        return parser.parse()
    except Exception as e:
        return {"error": f"Failed parsing manifest bytes: {str(e)}"}


def parse_manifest_from_apk(apk_path: str) -> Dict[str, Any]:
    import zipfile
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return {"error": "AndroidManifest.xml not found in APK"}
            manifest_bytes = zf.read("AndroidManifest.xml")
            return parse_manifest_bytes(manifest_bytes)
    except Exception as e:
        return {"error": f"Failed reading AndroidManifest.xml from APK: {str(e)}"}
