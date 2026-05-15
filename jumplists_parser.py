"""
jumplists_parser.py
───────────────────
Parses Windows AutomaticDestinations Jump List files.

Changes from v2.0:
  • filetime_to_str imported from forensic_utils (no duplication).
  • debug= constructor flag for full traceback logging.
  • Improved DestList entry robustness:
      - Per-entry offset tracking (path_start is correctly advanced per entry).
      - Version 3+ extra_bytes applied consistently.
      - Invalid path_len entries are skipped, not silently ignored.
  • Reads individual LNK streams (per entry) for target path as fallback
    when the DestList path field is empty or garbled.
"""

import os
import struct
from typing import Optional

import olefile

from audit_logger   import ForensicAuditLogger
from forensic_utils import filetime_to_str, traceback_str


KNOWN_APP_IDS = {
    "1b4dd67f29cb1962": "Windows Explorer",
    "9b9cdc69c1c24e2b": "Microsoft Word",
    "b8ab77100df80ab3": "Microsoft Excel",
    "69dba18a7a3b4b18": "Adobe Acrobat Reader",
    "c26cc0b882880ac5": "Notepad",
    "3de963060cf694d9": "VLC Media Player",
    "2003bd3b0d4b2b07": "Google Chrome",
    "c2e0e93f37b5cbf5": "Mozilla Firefox",
    "5c450709f7ae4396": "7-Zip",
    "7e4dca80246863e3": "Visual Studio Code",
}

# LNK magic (Shell Link header)
LNK_MAGIC = b'\x4C\x00\x00\x00'


class JumpListsParser:
    def __init__(self, logger: ForensicAuditLogger, debug: bool = False):
        self.logger = logger
        self.debug  = debug

    def parse_jump_lists(self, users_dir: str = r"C:\Users") -> list[dict]:
        self.logger.log_section("Jump Lists Parser")
        results = []
        import glob

        search_dirs = []
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            direct = os.path.join(
                appdata, "Microsoft", "Windows", "Recent", "AutomaticDestinations"
            )
            search_dirs.append((direct, os.environ.get("USERNAME", "UnknownUser")))

        if os.path.isdir(users_dir):
            for username in os.listdir(users_dir):
                jl_dir = os.path.join(
                    users_dir, username, "AppData", "Roaming",
                    "Microsoft", "Windows", "Recent", "AutomaticDestinations",
                )
                if os.path.isdir(jl_dir):
                    search_dirs.append((jl_dir, username))

        seen = set()
        unique_dirs = []
        for path, uname in search_dirs:
            if path.lower() not in seen:
                seen.add(path.lower())
                unique_dirs.append((path, uname))

        self.logger.log(f"Searching {len(unique_dirs)} Jump List directories")

        all_files = []
        for jl_dir, username in unique_dirs:
            files = glob.glob(os.path.join(jl_dir, "*.automaticDestinations-ms"))
            self.logger.log(f"  {jl_dir}: {len(files)} files")
            for f in files:
                all_files.append((f, username))

        self.logger.log(f"Total Jump List files: {len(all_files)}")

        for full_path, username in all_files:
            try:
                if not olefile.isOleFile(full_path):
                    continue
                entries = self._parse_single_jump_list(full_path, username)
                results.extend(entries)
            except Exception as exc:
                self.logger.log_error(f"Failed: {os.path.basename(full_path)} — {exc}")
                if self.debug:
                    self.logger.log_error(traceback_str(exc))

        self.logger.log(f"Jump Lists complete. Total entries: {len(results)}")
        return results

    def _parse_single_jump_list(self, jl_path: str, username: str) -> list[dict]:
        md5, sha256 = self.logger.hash_file(jl_path)

        app_id   = os.path.basename(jl_path).split(".")[0].lower()
        app_name = KNOWN_APP_IDS.get(app_id, f"Unknown App ({app_id})")

        results = []

        with olefile.OleFileIO(jl_path) as ole:
            if not ole.exists("DestList"):
                self.logger.log_error(f"No DestList stream: {jl_path}")
                return []

            dest_list_data = ole.openstream("DestList").read()
            entries = self._parse_dest_list(
                dest_list_data, jl_path, username, app_id, app_name, md5, sha256
            )

            # ── Fallback: read LNK streams for entries with no path ────────────
            for entry in entries:
                if not entry.get("accessed_file"):
                    lnk_path_val = self._read_lnk_stream(ole, entry.get("_entry_id", ""))
                    if lnk_path_val:
                        entry["accessed_file"] = lnk_path_val

            results.extend(entries)

        self.logger.log(f"  {app_name}: {len(results)} entries")
        return results

    def _parse_dest_list(self, data: bytes, jl_path, username,
                          app_id, app_name, md5, sha256) -> list[dict]:
        if len(data) < 32:
            return []

        version     = struct.unpack_from("<I", data, 0)[0]
        entry_count = struct.unpack_from("<I", data, 4)[0]

        # Windows 10/11 DestList version 3+ adds 4 extra bytes per entry header
        extra_bytes = 4 if version >= 3 else 0

        entries = []
        offset  = 32   # DestList header is 32 bytes

        for entry_idx in range(entry_count):
            if offset + 0x72 + extra_bytes > len(data):
                break

            entry_start = offset

            try:
                last_modified = struct.unpack_from("<Q", data, offset + 0x58)[0]
                pin_status    = struct.unpack_from("<i", data, offset + 0x60)[0]
                access_count  = struct.unpack_from("<I", data, offset + 0x64)[0]

                # path_len is at a fixed offset from the entry start
                # extra_bytes shifts this for version 3+
                path_len_offset = 0x70 + extra_bytes
                if offset + path_len_offset + 2 > len(data):
                    break
                path_len = struct.unpack_from("<H", data, offset + path_len_offset)[0]

                if path_len == 0 or path_len > 4096:
                    # Skip this entry — advance by minimum entry size + path length
                    # field (2 bytes). We don't know the real size so advance conservatively.
                    offset += 0x72 + extra_bytes
                    continue

                path_start = offset + path_len_offset + 2
                path_end   = path_start + path_len * 2

                if path_end > len(data):
                    break

                file_path = data[path_start:path_end].decode("utf-16-le", errors="replace")

                entries.append({
                    "artifact_source" : "JumpList",
                    "jump_list_path"  : jl_path,
                    "username"        : username,
                    "app_id"          : app_id,
                    "application"     : app_name,
                    "accessed_file"   : file_path,
                    "last_accessed"   : filetime_to_str(last_modified),
                    "access_count"    : access_count,
                    "is_pinned"       : pin_status >= 0,
                    "pin_position"    : pin_status if pin_status >= 0 else None,
                    "dest_list_ver"   : version,
                    "_entry_id"       : str(entry_idx),
                    "md5"             : md5,
                    "sha256"          : sha256,
                })

                # Advance offset: entry header + path_len field (2B) + path bytes
                offset = path_end

            except Exception as exc:
                self.logger.log_error(
                    f"Entry {entry_idx} parse error at offset {offset}: {exc}"
                )
                if self.debug:
                    self.logger.log_error(traceback_str(exc))
                # Advance conservatively to avoid infinite loop
                offset += 0x72 + extra_bytes

        return entries

    def _read_lnk_stream(self, ole, entry_id: str) -> Optional[str]:
        """
        Attempts to read the LNK stream for a given entry_id from the OLE file.
        Each entry in an AutomaticDestinations file has a corresponding LNK
        stream named by its decimal index (e.g., '1', '2', ...).

        Returns the target path from the LNK LocalBasePath if found.
        """
        if not entry_id:
            return None
        try:
            if not ole.exists(entry_id):
                return None
            lnk_data = ole.openstream(entry_id).read()
            if len(lnk_data) < 76 or lnk_data[:4] != LNK_MAGIC:
                return None
            # LinkInfo flag check
            link_flags = struct.unpack_from("<I", lnk_data, 0x14)[0]
            HAS_LINK_TARGET_ID_LIST = 0x0001
            HAS_LINK_INFO           = 0x0002
            offset = 76
            if link_flags & HAS_LINK_TARGET_ID_LIST:
                id_list_sz = struct.unpack_from("<H", lnk_data, offset)[0]
                offset += 2 + id_list_sz
            if link_flags & HAS_LINK_INFO and offset + 28 < len(lnk_data):
                li_start    = offset
                li_flags    = struct.unpack_from("<I", lnk_data, li_start + 8)[0]
                if li_flags & 0x0001:   # HAS_VOLUME_ID_AND_LOCAL_BASE_PATH
                    local_bp_off = struct.unpack_from("<I", lnk_data, li_start + 16)[0]
                    bp_start = li_start + local_bp_off
                    bp_end   = lnk_data.index(b'\x00', bp_start)
                    return lnk_data[bp_start:bp_end].decode("ascii", errors="replace")
        except Exception:
            pass
        return None
