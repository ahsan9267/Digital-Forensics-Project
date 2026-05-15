"""
prefetch_parser.py
──────────────────
Parses Windows Prefetch (.pf) files from C:\\Windows\\Prefetch\\.

Changes from v2.0:
  • Imports filetime_to_datetime/filetime_to_str from forensic_utils (no duplication).
  • Accepts debug= flag — logs full tracebacks in debug mode.
  • Added support for Prefetch versions 17 (XP/2003), 23 (Vista/7), 26 (Win8/8.1).
  • Graceful partial-parse: if run-time or metrics extraction fails, the record
    is still returned with what was successfully decoded.
"""

import os
import struct
import ctypes
from typing import Optional

from audit_logger    import ForensicAuditLogger
from forensic_utils  import filetime_to_str, filetime_to_datetime, traceback_str


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

MAM_SIGNATURE  = b'\x4D\x41\x4D\x04'   # Windows 10/11 MAM compression header
PREFETCH_MAGIC = b'\x53\x43\x43\x41'   # "SCCA" — Prefetch file signature

# Supported Prefetch format versions
VERSION_MAP = {
    17: "Windows XP / Server 2003",
    23: "Windows Vista / 7",
    26: "Windows 8 / 8.1",
    30: "Windows 10 / 11",
    31: "Windows 11 22H2+",
}


# ─────────────────────────────────────────────────────────────────────────────
# MAM Decompression (Windows 10/11 only)
# ─────────────────────────────────────────────────────────────────────────────

def decompress_mam(raw_bytes: bytes) -> bytes:
    """
    Decompresses a MAM-compressed Windows 10/11 Prefetch file using the
    Windows RtlDecompressBufferEx API via ctypes.

    Only callable on Windows. Raises NotImplementedError on other platforms.

    Args:
        raw_bytes: Raw bytes of the .pf file (starting with MAM_SIGNATURE).

    Returns:
        Decompressed Prefetch data bytes (starts with SCCA magic after success).

    Raises:
        RuntimeError: If decompression fails (NTSTATUS != 0).
        NotImplementedError: If not running on Windows.
    """
    if os.name != "nt":
        raise NotImplementedError(
            "MAM decompression requires Windows (RtlDecompressBufferEx)."
        )

    uncompressed_size = struct.unpack_from("<I", raw_bytes, 4)[0]
    output_buffer     = ctypes.create_string_buffer(uncompressed_size)
    final_size        = ctypes.c_ulong(0)
    work_buffer       = ctypes.create_string_buffer(0x8000)

    status = ctypes.windll.ntdll.RtlDecompressBufferEx(
        0x0004,                                  # COMPRESSION_FORMAT_XPRESS_HUFF
        output_buffer,
        uncompressed_size,
        ctypes.c_char_p(raw_bytes[8:]),          # Compressed data starts at offset 8
        len(raw_bytes) - 8,
        ctypes.byref(final_size),
        work_buffer,
    )

    if status != 0:
        raise RuntimeError(
            f"RtlDecompressBufferEx failed with NTSTATUS: {hex(status)}"
        )

    return output_buffer.raw[: final_size.value]


# ─────────────────────────────────────────────────────────────────────────────
# Main Parser Class
# ─────────────────────────────────────────────────────────────────────────────

class PrefetchParser:
    """
    Parses Windows Prefetch files (.pf).

    Supported versions:
      17  — Windows XP / Server 2003
      23  — Windows Vista / 7
      26  — Windows 8 / 8.1
      30  — Windows 10 / 11  (with MAM decompression)

    Forensic significance:
      Prefetch files are created by the Windows Superfetch service after
      a program runs.  They survive even if the original executable is deleted,
      making them primary evidence for proving program execution.
    """

    def __init__(self, logger: ForensicAuditLogger, debug: bool = False):
        self.logger = logger
        self.debug  = debug

    # ─────────────────────────────────────────────────────────────────────────
    # Public: Parse all .pf files in a directory
    # ─────────────────────────────────────────────────────────────────────────

    def parse_directory(self, prefetch_dir: str) -> list[dict]:
        """
        Parses all .pf files found in prefetch_dir.

        Args:
            prefetch_dir: Path to the Prefetch directory.

        Returns:
            List of dicts, one per successfully parsed Prefetch file.
        """
        self.logger.log_section("Prefetch Parser")
        self.logger.log(f"Scanning Prefetch directory: {prefetch_dir}")

        if not os.path.isdir(prefetch_dir):
            self.logger.log_error(f"Prefetch directory not found: {prefetch_dir}")
            return []

        pf_files = [f for f in os.listdir(prefetch_dir) if f.upper().endswith(".PF")]
        self.logger.log(f"Found {len(pf_files)} .pf files")

        results = []
        for filename in pf_files:
            full_path = os.path.join(prefetch_dir, filename)
            try:
                parsed = self._parse_single(full_path)
                if parsed:
                    results.append(parsed)
            except Exception as exc:
                self.logger.log_error(f"Failed to parse {filename}: {exc}")
                if self.debug:
                    self.logger.log_error(traceback_str(exc))

        self.logger.log(f"Successfully parsed {len(results)} Prefetch files")
        return results

    # ─────────────────────────────────────────────────────────────────────────
    # Private: Parse a single .pf file (all versions)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_single(self, pf_path: str) -> Optional[dict]:
        md5, sha256 = self.logger.hash_file(pf_path)

        with open(pf_path, "rb") as fh:
            raw = fh.read()

        # Decompress MAM (Windows 10/11 only)
        if raw[:4] == MAM_SIGNATURE:
            raw = decompress_mam(raw)

        if raw[4:8] != PREFETCH_MAGIC:
            self.logger.log_error(f"Invalid SCCA signature in {pf_path}")
            return None

        version = struct.unpack_from("<I", raw, 0)[0]

        if version not in VERSION_MAP:
            self.logger.log_error(
                f"Unsupported Prefetch version {version} in {pf_path} — skipping"
            )
            return None

        exe_name_raw  = raw[16:76]
        exe_name      = exe_name_raw.decode("utf-16-le").rstrip("\x00")
        prefetch_hash = struct.unpack_from("<I", raw, 76)[0]

        # ── Version-specific run-time / run-count parsing ─────────────────────
        last_run_time, previous_runs, run_count = self._parse_run_info(raw, version)

        # ── File metrics (best-effort) ────────────────────────────────────────
        files_loaded: list[str] = []
        try:
            files_loaded = self._parse_file_metrics(raw, version)
        except Exception as exc:
            self.logger.log_error(
                f"File metrics parse failed for {exe_name}: {exc}"
            )
            if self.debug:
                self.logger.log_error(traceback_str(exc))

        self.logger.log(
            f"Parsed Prefetch [{VERSION_MAP[version]}]: {exe_name} "
            f"| Runs: {run_count} | Last: {last_run_time}"
        )

        return {
            "artifact_source" : "Prefetch",
            "executable_name" : exe_name,
            "prefetch_hash"   : f"{prefetch_hash:08X}",
            "pf_file_path"    : pf_path,
            "last_run_time"   : last_run_time,
            "previous_runs"   : previous_runs,
            "run_count"       : run_count,
            "files_loaded"    : files_loaded,
            "md5"             : md5,
            "sha256"          : sha256,
            "version"         : version,
            "version_label"   : VERSION_MAP[version],
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Version-specific run-info parsing
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_run_info(self, raw: bytes, version: int):
        """
        Extracts last_run_time, previous_runs list, and run_count.

        Layout differences by version:
          v17 (XP):
            Offset 0x78 : QWORD  last_run_time (single timestamp)
            Offset 0x90 : DWORD  run_count
          v23 (Vista/7):
            Offset 0x80 : QWORD  last_run_time
            Offset 0x98 : DWORD  run_count
          v26 (Win8):
            Offset 0x80 : QWORD × 8  run_times  (last + 7 previous)
            Offset 0xD0 : DWORD  run_count
          v30 (Win10/11):
            Offset 0x80 : QWORD × 8  run_times
            Offset 0xD0 : DWORD  run_count
        """
        last_run_time = None
        previous_runs = []
        run_count     = 0

        try:
            if version == 17:
                ft        = struct.unpack_from("<Q", raw, 0x78)[0]
                run_count = struct.unpack_from("<I", raw, 0x90)[0]
                last_run_time = filetime_to_str(ft)

            elif version == 23:
                ft        = struct.unpack_from("<Q", raw, 0x80)[0]
                run_count = struct.unpack_from("<I", raw, 0x98)[0]
                last_run_time = filetime_to_str(ft)

            elif version in (26, 30, 31):
                # 8 × QWORD run-time array at offset 0x80
                rts = struct.unpack_from("<8Q", raw, 0x80)
                last_run_time  = filetime_to_str(rts[0])
                previous_runs  = [filetime_to_str(t) for t in rts[1:] if t != 0]
                run_count      = struct.unpack_from("<I", raw, 0xD0)[0]

        except struct.error as exc:
            self.logger.log_error(f"Run-info parse error (v{version}): {exc}")

        return last_run_time, previous_runs, run_count

    # ─────────────────────────────────────────────────────────────────────────
    # File Metrics Array
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_file_metrics(self, raw: bytes, version: int) -> list[str]:
        """
        Extracts loaded file/DLL names from the File Metrics Array.

        Offsets for metrics and filename strings differ by version:
          v17  : metrics at 0x054, strings at 0x064
          v23  : metrics at 0x090, strings at 0x0A0
          v26/30: metrics at 0x064, strings at 0x078

        Each entry is 20 bytes (v17/23) or 32 bytes (v26/30).
        """
        # (metrics_offset_field, metrics_count_field,
        #  strings_offset_field, strings_size_field, entry_size)
        layout = {
            17: (0x054, 0x058, 0x064, 0x068, 20),
            23: (0x090, 0x094, 0x0A0, 0x0A4, 20),
            26: (0x064, 0x068, 0x078, 0x07C, 32),
            30: (0x064, 0x068, 0x078, 0x07C, 32),
            31: (0x064, 0x068, 0x078, 0x07C, 32),
        }

        if version not in layout:
            return []

        mo, mc, so, ss, entry_sz = layout[version]

        metrics_offset = struct.unpack_from("<I", raw, mo)[0]
        metrics_count  = struct.unpack_from("<I", raw, mc)[0]
        strings_offset = struct.unpack_from("<I", raw, so)[0]
        strings_size   = struct.unpack_from("<I", raw, ss)[0]

        strings_block = raw[strings_offset: strings_offset + strings_size]
        filenames     = []

        # Filename string offset field: byte 12 in v17/23, byte 12 in v26/30
        # Char count field           : byte 16 in v17/23, byte 16 in v26/30
        for i in range(metrics_count):
            entry_start  = metrics_offset + i * entry_sz
            str_offset   = struct.unpack_from("<I", raw, entry_start + 12)[0]
            str_num_char = struct.unpack_from("<I", raw, entry_start + 16)[0]

            name_bytes = strings_block[str_offset * 2: str_offset * 2 + str_num_char * 2]
            filename   = name_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
            filenames.append(filename)

        return filenames