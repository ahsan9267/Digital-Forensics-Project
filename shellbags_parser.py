import os
import struct
from typing import Optional

from Registry       import Registry
from audit_logger   import ForensicAuditLogger
from forensic_utils import filetime_to_str, dos_date_time_to_str, traceback_str


# Well-known GUID names for Root ShellItems (0x1F)
KNOWN_GUIDS = {
    "{20D04FE0-3AEA-1069-A2D8-08002B30309D}": "My Computer",
    "{450D8FBA-AD25-11D0-98A8-0800361B1103}": "My Documents",
    "{645FF040-5081-101B-9F08-00AA002F954E}": "Recycle Bin",
    "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}": "Network",
}

# Extension block signature for "beef0004" (file/folder extra data with FILETIME)
BEEF0004 = b'\x04\x00\xEF\xBE'


class ShellbagsParser:
    def __init__(self, logger: ForensicAuditLogger, debug: bool = False):
        self.logger = logger
        self.debug  = debug

    def parse_from_hive(self, hive_path: str, username: str,
                        usrclass_path: str = None) -> list[dict]:
        """
        Parse shellbags from NTUSER.DAT and/or UsrClass.dat.

        On Windows 10/11 the active shellbags are in UsrClass.dat under:
            Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU
        NTUSER.DAT only has a stub entry on modern Windows.

        Args:
            hive_path     : Path to NTUSER.DAT (or any exported .dat).
            username      : Target username for tagging results.
            usrclass_path : Optional path to UsrClass.dat. When provided,
                            this hive is searched first (Windows 10/11).
        """
        self.logger.log_section("Shellbags Parser")
        results = []

        # Build list of (hive_file, [bagmru_paths_to_try])
        # UsrClass.dat is checked first — it holds the real data on Win 10/11.
        hives_to_try = []

        if usrclass_path and os.path.isfile(usrclass_path):
            hives_to_try.append((usrclass_path, [
                "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                "Software\\Microsoft\\Windows\\Shell\\BagMRU",
            ]))

        if hive_path and os.path.isfile(hive_path):
            hives_to_try.append((hive_path, [
                "Software\\Microsoft\\Windows\\Shell\\BagMRU",
                "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
            ]))

        if not hives_to_try:
            self.logger.log_error("Shellbags: no valid hive files provided.")
            return results

        for hive_file, bagmru_paths in hives_to_try:
            self.logger.log(f"Trying hive: {hive_file} (user: {username})")
            try:
                md5, sha256 = self.logger.hash_file(hive_file)
                reg = Registry.Registry(hive_file)
            except Exception as exc:
                self.logger.log_error(f"Failed to open hive {hive_file}: {exc}")
                if self.debug:
                    self.logger.log_error(traceback_str(exc))
                continue

            found = False
            for bagmru_path in bagmru_paths:
                try:
                    root_key = reg.open(bagmru_path)
                    self.logger.log(f"  Found BagMRU at: {bagmru_path}")
                    before = len(results)
                    self._traverse_bagmru(root_key, "", username, results, md5, sha256)
                    self.logger.log(f"  Extracted {len(results) - before} entries")
                    found = True
                    break
                except Registry.RegistryKeyNotFoundException:
                    continue

            if not found:
                self.logger.log(f"  No BagMRU key found in: {hive_file}")

        self.logger.log(f"Shellbags complete. {len(results)} folder entries total")
        return results

    def _traverse_bagmru(self, key, parent_path, username, results, md5, sha256):
        # ── Step 1: Process values whose names are decimal digits ────────────
        # Each numeric value holds a ShellItem binary blob for that path node.
        for value in key.values():
            if not value.name().isdigit():
                continue
            try:
                shell_item_data = value.value()
                folder_name, folder_modified = self._decode_shellitem(shell_item_data)

                if folder_name:
                    full_path = (
                        os.path.join(parent_path, folder_name) if parent_path
                        else folder_name
                    )
                    results.append({
                        "artifact_source" : "Shellbags",
                        "username"        : username,
                        "folder_path"     : full_path,
                        "folder_modified" : folder_modified,
                        "registry_key"    : key.path(),
                        "md5"             : md5,
                        "sha256"          : sha256,
                    })
                    try:
                        child_key = key.subkey(value.name())
                        self._traverse_bagmru(child_key, full_path, username,
                                              results, md5, sha256)
                    except Registry.RegistryKeyNotFoundException:
                        pass

            except Exception as exc:
                self.logger.log_error(f"ShellItem decode error in {key.path()}: {exc}")
                if self.debug:
                    self.logger.log_error(traceback_str(exc))

        # ── Step 2: Recurse into numeric subkeys even when the parent key   ──
        # has no matching numeric *value* (e.g. BagMRU root only has a
        # (Default) value but does have numbered child keys like "0", "1").
        # Without this, the entire tree is missed when the root value list
        # is empty or contains only non-digit entries.
        value_names_seen = {v.name() for v in key.values() if v.name().isdigit()}
        for subkey in key.subkeys():
            if subkey.name().isdigit() and subkey.name() not in value_names_seen:
                try:
                    self._traverse_bagmru(subkey, parent_path, username,
                                          results, md5, sha256)
                except Exception as exc:
                    self.logger.log_error(
                        f"Subkey traversal error in {key.path()}\\{subkey.name()}: {exc}"
                    )
                    if self.debug:
                        self.logger.log_error(traceback_str(exc))

    def _decode_shellitem(self, data: bytes):
        """
        Extended ShellItem decoder.

        Type routing:
          0x1F — Root / GUID items (Desktop, My Computer, Recycle Bin, etc.)
          0x20 — Volume (drive letter)
          0x30/0x31/0x32 — File / Folder (short + long name)
          0xC3 — Network share (UNC path)

        For 0x30/0x31/0x32, also checks for the BEEF0004 extension block
        which contains a proper FILETIME for last-modified — more accurate
        than the DOS date embedded in the base item.
        """
        if len(data) < 4:
            return None, None

        item_type = data[2]

        # ── Root / GUID items (0x1F) ──────────────────────────────────────────
        if item_type == 0x1F and len(data) >= 20:
            try:
                guid_bytes = data[4:20]
                # Format as {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
                p1 = struct.unpack_from("<I", guid_bytes, 0)[0]
                p2 = struct.unpack_from("<H", guid_bytes, 4)[0]
                p3 = struct.unpack_from("<H", guid_bytes, 6)[0]
                p4 = guid_bytes[8:10].hex().upper()
                p5 = guid_bytes[10:16].hex().upper()
                guid_str = f"{{{p1:08X}-{p2:04X}-{p3:04X}-{p4}-{p5}}}"
                name = KNOWN_GUIDS.get(guid_str, f"GUID:{guid_str}")
                return name, None
            except struct.error:
                return None, None

        # ── Volume (0x2F) ─────────────────────────────────────────────────────
        if item_type == 0x2F:
            vol_bytes = data[3:5]
            vol_name  = vol_bytes.decode("ascii", errors="replace").strip("\x00")
            return vol_name or None, None

        # ── File / Folder (0x30, 0x31, 0x32) ─────────────────────────────────
        if (item_type & 0x70) == 0x30:
            if len(data) < 14:
                return None, None

            mod_date = struct.unpack_from("<H", data, 8)[0]
            mod_time = struct.unpack_from("<H", data, 10)[0]
            modified = dos_date_time_to_str(mod_date, mod_time)

            # Short name (null-terminated ASCII at offset 14)
            name_end = data.find(b'\x00', 14)
            if name_end < 0:
                return None, modified
            short_name = data[14:name_end].decode("ascii", errors="replace")

            # ── Check for BEEF0004 extension block (long name + FILETIME) ─────
            better_name, better_ts = self._parse_beef0004(data, name_end)
            final_name = better_name or short_name
            final_ts   = better_ts   or modified

            return final_name if final_name else None, final_ts

        # ── Network share (0xC3) ──────────────────────────────────────────────
        if item_type == 0xC3 and len(data) > 20:
            try:
                name_start = 20
                name_end   = data.find(b'\x00', name_start)
                if name_end > name_start:
                    share_name = data[name_start:name_end].decode("ascii", errors="replace")
                    return share_name, None
            except Exception:
                pass

        return None, None

    def _parse_beef0004(self, data: bytes, short_name_end: int):
        """
        Searches for the BEEF0004 extension block after the short name.

        BEEF0004 layout (from libyal/libfwsi research):
          0x00 : WORD   ExtensionSize
          0x02 : WORD   ExtensionVersion
          0x04 : DWORD  Signature (0xBEEF0004)
          0x08 : WORD   FileDate (DOS)
          0x0A : WORD   FileTime (DOS)
          ...
          0x14 : variable  UnicodeFilename (null-terminated UTF-16LE)

        Returns:
            (long_filename or None, filetime_str or None)
        """
        idx = data.find(BEEF0004, short_name_end)
        if idx == -1:
            return None, None
        try:
            block_start = idx - 4   # signature at +4 from block start
            if block_start < 0:
                return None, None

            # Long Unicode name starts at offset 0x14 from block start
            unicode_start = block_start + 0x14
            if unicode_start >= len(data):
                return None, None

            # Find null terminator (2-byte aligned)
            name_end = unicode_start
            while name_end + 1 < len(data):
                if data[name_end] == 0 and data[name_end + 1] == 0:
                    break
                name_end += 2

            long_name = data[unicode_start:name_end].decode("utf-16-le", errors="replace")
            return long_name if long_name else None, None
        except Exception:
            return None, None