"""
recycle_bin_parser.py
─────────────────────
Parses $I metadata files from the Windows Recycle Bin.

Changes from v2.0:
  • filetime_to_str / filetime_to_datetime imported from forensic_utils.
  • debug= constructor flag for full traceback logging.
  • Graceful partial-parse: returns what can be decoded even if path is corrupt.
"""

import os
import struct
from typing import Optional

from audit_logger   import ForensicAuditLogger
from forensic_utils import filetime_to_str, filetime_to_datetime, traceback_str


class RecycleBinParser:
    BULK_DELETION_COUNT  = 10
    BULK_DELETION_WINDOW = 60   # seconds

    def __init__(self, logger: ForensicAuditLogger, debug: bool = False):
        self.logger = logger
        self.debug  = debug

    def parse_recycle_bin(self, recycle_bin_root: str = r"C:\$Recycle.Bin") -> list[dict]:
        self.logger.log_section("Recycle Bin Parser")
        self.logger.log(f"Scanning Recycle Bin: {recycle_bin_root}")
        results = []

        if not os.path.isdir(recycle_bin_root):
            self.logger.log_error(f"Recycle Bin directory not found: {recycle_bin_root}")
            return results

        for sid_dir in os.listdir(recycle_bin_root):
            sid_path = os.path.join(recycle_bin_root, sid_dir)
            if not os.path.isdir(sid_path):
                continue

            self.logger.log(f"Processing SID directory: {sid_dir}")
            i_files = [f for f in os.listdir(sid_path) if f.upper().startswith("$I")]
            self.logger.log(f"  Found {len(i_files)} $I metadata files")

            for filename in i_files:
                full_path = os.path.join(sid_path, filename)
                try:
                    parsed = self._parse_i_file(full_path, sid_dir)
                    if parsed:
                        results.append(parsed)
                except Exception as exc:
                    self.logger.log_error(f"  Failed: {filename} — {exc}")
                    if self.debug:
                        self.logger.log_error(traceback_str(exc))

        self.logger.log(f"Recycle Bin complete. Total deletions: {len(results)}")

        bulk_events = self._detect_bulk_deletion(results)
        if bulk_events:
            self.logger.log(
                f"[ALERT] {len(bulk_events)} bulk deletion events — possible evidence tampering"
            )

        return results

    def _parse_i_file(self, i_path: str, sid: str) -> Optional[dict]:
        md5, sha256 = self.logger.hash_file(i_path)

        with open(i_path, "rb") as fh:
            data = fh.read()

        if len(data) < 24:
            self.logger.log_error(f"$I file too small: {i_path}")
            return None

        version       = struct.unpack_from("<Q", data, 0x00)[0]
        file_size     = struct.unpack_from("<Q", data, 0x08)[0]
        deletion_time = struct.unpack_from("<Q", data, 0x10)[0]

        original_path = self._extract_path(data, version)
        deletion_dt   = filetime_to_str(deletion_time)

        self.logger.log(
            f"Deleted: {original_path or '(unknown)'} | Time: {deletion_dt} | "
            f"Size: {file_size:,} bytes"
        )

        return {
            "artifact_source"  : "RecycleBin",
            "i_file_path"      : i_path,
            "user_sid"         : sid,
            "original_path"    : original_path,
            "original_size"    : file_size,
            "deletion_time"    : deletion_dt,
            "_deletion_dt_raw" : filetime_to_datetime(deletion_time),
            "version"          : version,
            "bulk_deletion"    : False,
            "md5"              : md5,
            "sha256"           : sha256,
        }

    def _extract_path(self, data: bytes, version: int) -> Optional[str]:
        try:
            if version == 1:
                if len(data) < 0x18 + 520:
                    return None
                return data[0x18: 0x18 + 520].decode("utf-16-le", errors="replace").rstrip("\x00")
            elif version == 2:
                if len(data) < 0x1C:
                    return None
                name_len = struct.unpack_from("<I", data, 0x18)[0]
                if len(data) < 0x1C + name_len * 2:
                    return None
                return data[0x1C: 0x1C + name_len * 2].decode("utf-16-le", errors="replace")
            return None
        except (struct.error, UnicodeDecodeError):
            return None

    def _detect_bulk_deletion(self, records: list[dict]) -> list[dict]:
        from collections import defaultdict
        by_sid = defaultdict(list)
        for r in records:
            if r.get("_deletion_dt_raw"):
                by_sid[r["user_sid"]].append(r)

        bulk_events = []
        for sid, entries in by_sid.items():
            sorted_entries = sorted(entries, key=lambda x: x["_deletion_dt_raw"])
            for i, entry in enumerate(sorted_entries):
                window_start   = entry["_deletion_dt_raw"]
                window_entries = [
                    e for e in sorted_entries[i:]
                    if (e["_deletion_dt_raw"] - window_start).total_seconds()
                    <= self.BULK_DELETION_WINDOW
                ]
                if len(window_entries) >= self.BULK_DELETION_COUNT:
                    for e in window_entries:
                        e["bulk_deletion"] = True
                    bulk_events.append({
                        "sid"       : sid,
                        "count"     : len(window_entries),
                        "start_time": window_start.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "files"     : [e["original_path"] for e in window_entries],
                    })
                    break
        return bulk_events
