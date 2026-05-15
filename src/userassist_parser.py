"""
userassist_parser.py
────────────────────
Parses UserAssist registry keys.

Changes from v2.0:
  • filetime_to_str imported from forensic_utils (no duplication).
  • debug= constructor flag.
"""

import struct
from typing import Optional

from Registry       import Registry
from audit_logger   import ForensicAuditLogger
from forensic_utils import filetime_to_str, traceback_str


USERASSIST_GUIDS = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executed Applications",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcut Links",
    "{0D92F31F-97BC-4FD0-B7CF-702C6E0B1C20}": "Internet Explorer",
    "{5E6AB780-7743-11CF-A12B-00AA004AE837}": "Internet Toolbar",
}


def rot13_decode(encoded: str) -> str:
    result = []
    for char in encoded:
        if 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        elif 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)


class UserAssistParser:
    USERASSIST_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"

    def __init__(self, logger: ForensicAuditLogger, debug: bool = False):
        self.logger = logger
        self.debug  = debug

    def parse_from_hive(self, hive_path: str, username: str) -> list[dict]:
        self.logger.log_section("UserAssist Parser")
        self.logger.log(f"Parsing UserAssist from: {hive_path} (user: {username})")

        md5, sha256 = self.logger.hash_file(hive_path)
        results = []

        try:
            reg     = Registry.Registry(hive_path)
            ua_root = reg.open(self.USERASSIST_PATH)
        except Exception as exc:
            self.logger.log_error(f"Cannot open UserAssist key: {exc}")
            if self.debug:
                self.logger.log_error(traceback_str(exc))
            return results

        for guid_key in ua_root.subkeys():
            guid_name = guid_key.name()
            category  = USERASSIST_GUIDS.get(guid_name.upper(), f"Unknown ({guid_name})")

            try:
                count_key = guid_key.subkey("Count")
            except Registry.RegistryKeyNotFoundException:
                continue

            for value in count_key.values():
                encoded_name = value.name()
                if encoded_name.startswith("UEME_"):
                    continue

                decoded_name = rot13_decode(encoded_name)
                run_count, focus_count, focus_time_ms, last_run = \
                    self._parse_value_data(value.value())

                if run_count == 0 and last_run is None:
                    continue

                results.append({
                    "artifact_source"  : "UserAssist",
                    "username"         : username,
                    "guid_category"    : category,
                    "application_path" : decoded_name,
                    "run_count"        : run_count,
                    "focus_count"      : focus_count,
                    "focus_time_ms"    : focus_time_ms,
                    "last_run_time"    : last_run,
                    "md5"              : md5,
                    "sha256"           : sha256,
                })

        self.logger.log(f"UserAssist complete. {len(results)} entries")
        return results

    def _parse_value_data(self, data: bytes):
        if not data or len(data) < 64:
            return 0, 0, 0, None
        try:
            run_count   = struct.unpack_from("<I", data, 0x04)[0]
            focus_count = struct.unpack_from("<I", data, 0x08)[0]
            focus_time  = struct.unpack_from("<I", data, 0x0C)[0]
            last_run_ft = struct.unpack_from("<Q", data, 0x3C)[0]
            if run_count == 0xFFFFFFFF:
                run_count = 0
            return run_count, focus_count, focus_time, filetime_to_str(last_run_ft)
        except struct.error:
            return 0, 0, 0, None
