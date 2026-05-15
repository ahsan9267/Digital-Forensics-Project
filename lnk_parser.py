"""
lnk_parser.py
─────────────
Parses Windows LNK (Shell Link) files.

Changes from v2.0:
  • Imports filetime_to_str from forensic_utils (no duplication).
  • Accepts debug= constructor flag — logs full tracebacks in debug mode.
  • Added TrackerDataBlock parsing from ExtraData section:
      - NetBIOS machine name
      - MAC address (from Droid volume identifier)
    These help link a file access to a specific machine over a network.
"""

import os
import struct
from typing import Optional

from audit_logger   import ForensicAuditLogger
from forensic_utils import filetime_to_str, traceback_str


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

LNK_MAGIC  = b'\x4C\x00\x00\x00'
LNK_CLSID  = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'

SHOW_COMMANDS = {
    0x00000001: "SW_SHOWNORMAL",
    0x00000003: "SW_SHOWMAXIMIZED",
    0x00000007: "SW_SHOWMINNOACTIVE",
}

DRIVE_TYPES = {
    0: "Unknown",
    1: "No Root Directory",
    2: "Removable (USB/Floppy)",
    3: "Fixed (Local HDD/SSD)",
    4: "Network Share",
    5: "CD-ROM",
    6: "RAM Disk",
}

# ShellLinkHeader LinkFlags
HAS_LINK_TARGET_ID_LIST = 0x0001
HAS_LINK_INFO           = 0x0002
HAS_NAME                = 0x0004
HAS_RELATIVE_PATH       = 0x0008
HAS_WORKING_DIR         = 0x0010
HAS_ARGUMENTS           = 0x0020
HAS_ICON_LOCATION       = 0x0040
IS_UNICODE              = 0x0080

# LinkInfoFlags
HAS_VOLUME_ID_AND_LOCAL_BASE_PATH = 0x0001
HAS_COMMON_NETWORK_RELATIVE_LINK  = 0x0002

# ExtraData block signatures
TRACKER_BLOCK_SIG = 0xA0000003   # TrackerDataBlock — contains MAC + machine name


class LNKParser:
    """
    Parses Windows LNK (Shell Link) files.

    New in v2.1:
      TrackerDataBlock parsing provides:
        • NetBIOS computer name where the file was last accessed.
        • MAC address of the network adapter (embedded in the Droid GUID).
      These are invaluable for linking a file to a specific machine.
    """

    def __init__(self, logger: ForensicAuditLogger, debug: bool = False):
        self.logger = logger
        self.debug  = debug

    def parse_recent_folder(self, users_dir: str = r"C:\Users") -> list[dict]:
        self.logger.log_section("LNK Parser")
        results = []

        if not os.path.isdir(users_dir):
            self.logger.log_error(f"Users directory not found: {users_dir}")
            return results

        for username in os.listdir(users_dir):
            recent_path = os.path.join(
                users_dir, username, "AppData", "Roaming", "Microsoft", "Windows", "Recent"
            )
            if not os.path.isdir(recent_path):
                continue

            self.logger.log(f"Scanning Recent folder for user: {username}")
            lnk_files = [f for f in os.listdir(recent_path) if f.lower().endswith(".lnk")]

            for filename in lnk_files:
                full_path = os.path.join(recent_path, filename)
                try:
                    parsed = self._parse_single(full_path, username)
                    if parsed:
                        results.append(parsed)
                except Exception as exc:
                    self.logger.log_error(f"  Failed: {filename} — {exc}")
                    if self.debug:
                        self.logger.log_error(traceback_str(exc))

        self.logger.log(f"LNK Parser complete. Total parsed: {len(results)}")
        return results

    def _parse_single(self, lnk_path: str, username: str) -> Optional[dict]:
        md5, sha256 = self.logger.hash_file(lnk_path)

        with open(lnk_path, "rb") as fh:
            data = fh.read()

        if len(data) < 76 or data[:4] != LNK_MAGIC:
            self.logger.log_error(f"Not a valid LNK file: {lnk_path}")
            return None

        link_flags       = struct.unpack_from("<I", data, 0x14)[0]
        creation_time    = struct.unpack_from("<Q", data, 0x1C)[0]
        access_time      = struct.unpack_from("<Q", data, 0x24)[0]
        write_time       = struct.unpack_from("<Q", data, 0x2C)[0]
        target_file_size = struct.unpack_from("<I", data, 0x34)[0]
        show_cmd         = struct.unpack_from("<I", data, 0x3C)[0]

        offset = 76

        if link_flags & HAS_LINK_TARGET_ID_LIST:
            id_list_size = struct.unpack_from("<H", data, offset)[0]
            offset += 2 + id_list_size

        target_path = drive_type_str = volume_serial = network_share = None

        if link_flags & HAS_LINK_INFO:
            target_path, drive_type, volume_serial, network_share = \
                self._parse_link_info(data, offset)
            drive_type_str = DRIVE_TYPES.get(drive_type, "Unknown")
            li_size = struct.unpack_from("<I", data, offset)[0]
            offset += li_size

        strings = self._parse_string_data(data, offset, link_flags)

        # ── ExtraData — TrackerDataBlock ──────────────────────────────────────
        tracker = self._parse_tracker_block(data)

        self.logger.log(
            f"LNK: {os.path.basename(lnk_path)} | Target: {target_path} | "
            f"Drive: {drive_type_str} | Machine: {tracker.get('machine_name','?')}"
        )

        return {
            "artifact_source"     : "LNK",
            "lnk_file_path"       : lnk_path,
            "username"            : username,
            "target_path"         : target_path,
            "target_size_bytes"   : target_file_size,
            "drive_type"          : drive_type_str,
            "volume_serial"       : f"{volume_serial:08X}" if volume_serial else None,
            "network_share"       : network_share,
            "target_created"      : filetime_to_str(creation_time),
            "target_accessed"     : filetime_to_str(access_time),
            "target_modified"     : filetime_to_str(write_time),
            "show_command"        : SHOW_COMMANDS.get(show_cmd, "Unknown"),
            "lnk_name"            : strings.get("name"),
            "relative_path"       : strings.get("relative_path"),
            "working_dir"         : strings.get("working_dir"),
            "arguments"           : strings.get("arguments"),
            # TrackerDataBlock fields (new)
            "machine_name"        : tracker.get("machine_name"),
            "mac_address"         : tracker.get("mac_address"),
            "md5"                 : md5,
            "sha256"              : sha256,
        }

    def _parse_link_info(self, data: bytes, offset: int):
        li_start      = offset
        li_flags      = struct.unpack_from("<I", data, li_start + 8)[0]
        vol_id_offset = struct.unpack_from("<I", data, li_start + 12)[0]
        local_bp_off  = struct.unpack_from("<I", data, li_start + 16)[0]
        net_rel_off   = struct.unpack_from("<I", data, li_start + 20)[0]

        target_path = drive_type = vol_serial = network_share = None

        if li_flags & HAS_VOLUME_ID_AND_LOCAL_BASE_PATH:
            vid_start  = li_start + vol_id_offset
            drive_type = struct.unpack_from("<I", data, vid_start + 4)[0]
            vol_serial = struct.unpack_from("<I", data, vid_start + 8)[0]
            bp_start   = li_start + local_bp_off
            bp_end     = data.index(b'\x00', bp_start)
            target_path = data[bp_start:bp_end].decode("ascii", errors="replace")

        if li_flags & HAS_COMMON_NETWORK_RELATIVE_LINK:
            net_start    = li_start + net_rel_off
            net_name_off = struct.unpack_from("<I", data, net_start + 8)[0]
            ns_start     = net_start + net_name_off
            ns_end       = data.index(b'\x00', ns_start)
            network_share = data[ns_start:ns_end].decode("ascii", errors="replace")

        return target_path, drive_type, vol_serial, network_share

    def _parse_string_data(self, data: bytes, offset: int, flags: int) -> dict:
        strings   = {}
        flag_keys = [
            (HAS_NAME,          "name"),
            (HAS_RELATIVE_PATH, "relative_path"),
            (HAS_WORKING_DIR,   "working_dir"),
            (HAS_ARGUMENTS,     "arguments"),
            (HAS_ICON_LOCATION, "icon_location"),
        ]
        for flag, key in flag_keys:
            if flags & flag and offset + 2 <= len(data):
                count  = struct.unpack_from("<H", data, offset)[0]
                offset += 2
                if IS_UNICODE & flags:
                    strings[key] = data[offset: offset + count * 2].decode(
                        "utf-16-le", errors="replace"
                    )
                    offset += count * 2
                else:
                    strings[key] = data[offset: offset + count].decode(
                        "ascii", errors="replace"
                    )
                    offset += count
        return strings

    def _parse_tracker_block(self, data: bytes) -> dict:
        """
        Parses the TrackerDataBlock from the ExtraData section.

        Layout (MS-SHLLINK §2.5.10):
          Offset  0 : DWORD  BlockSize   (≥ 0x58 = 88 bytes)
          Offset  4 : DWORD  BlockSig    (0xA0000003)
          Offset  8 : DWORD  Length      (always 0x58)
          Offset 12 : DWORD  Version     (always 0)
          Offset 16 : ASCII[16]  MachineID  (NetBIOS name, null-terminated)
          Offset 32 : GUID   Droid[0]    (volume tracking GUID)
          Offset 48 : GUID   Droid[1]    (file tracking GUID — last 6 bytes = MAC)
          Offset 64 : GUID   DroidBirth[0]
          Offset 80 : GUID   DroidBirth[1]

        The MAC address is embedded in bytes 10-15 of Droid[1] (file tracking GUID).

        Returns:
            Dict with 'machine_name' and 'mac_address', or empty dict on failure.
        """
        result = {}
        # ExtraData starts after all StringData — scan for the block signature
        idx = data.rfind(b'\x03\x00\x00\xA0')   # little-endian 0xA0000003
        if idx == -1 or idx < 4:
            return result

        block_start = idx - 4   # BlockSig is at offset 4, so block starts 4 bytes earlier
        try:
            block_size = struct.unpack_from("<I", data, block_start)[0]
            if block_size < 88 or block_start + block_size > len(data):
                return result

            # Machine name: 16-byte ASCII at offset 16 from block start
            machine_raw  = data[block_start + 16 : block_start + 32]
            machine_name = machine_raw.split(b'\x00')[0].decode("ascii", errors="replace")

            # MAC address: bytes 10-15 of Droid[1] at offset 48 from block start
            # Droid[1] GUID starts at block_start + 48; MAC is at +10
            mac_bytes = data[block_start + 48 + 10 : block_start + 48 + 16]
            if len(mac_bytes) == 6:
                mac_address = ":".join(f"{b:02X}" for b in mac_bytes)
            else:
                mac_address = None

            if machine_name:
                result["machine_name"] = machine_name
            if mac_address:
                result["mac_address"] = mac_address

        except (struct.error, IndexError):
            pass

        return result

    def build_usb_provenance_map(self, parsed_lnk_list: list[dict]) -> dict:
        usb_map = {}
        for entry in parsed_lnk_list:
            if (
                entry.get("drive_type") == "Removable (USB/Floppy)"
                and entry.get("volume_serial")
            ):
                serial = entry["volume_serial"]
                usb_map.setdefault(serial, []).append({
                    "file_path"    : entry.get("target_path"),
                    "last_accessed": entry.get("target_accessed"),
                    "username"     : entry.get("username"),
                    "machine_name" : entry.get("machine_name"),
                    "mac_address"  : entry.get("mac_address"),
                })

        self.logger.log(f"USB Provenance: {len(usb_map)} unique USB volume serials")
        for serial, files in usb_map.items():
            self.logger.log(f"  Volume {serial}: {len(files)} files accessed")
        return usb_map
