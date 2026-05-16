"""
forensic_utils.py
─────────────────
Centralised utility module for the Windows Forensic Triage Tool.

Consolidates:
  • FILETIME_EPOCH_DIFF constant (was duplicated in 6 files)
  • filetime_to_str()            (was duplicated in 6 files)
  • filetime_to_datetime()       (was duplicated in 2 files)
  • dos_date_time_to_str()       (was duplicated in shellbags_parser)
  • ForensicPaths dataclass      (centralises all hardcoded paths)
  • path_normalise()             (new — for improved correlation)
  • safe_basename()              (null-safe os.path.basename)
  • traceback_str()              (full traceback for debug logging)
"""

import os
import re
import traceback
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# FILETIME Constants & Conversion Helpers
# ─────────────────────────────────────────────────────────────────────────────

# Seconds between Windows FILETIME epoch (1601-01-01) and Unix epoch (1970-01-01)
FILETIME_EPOCH_DIFF: int = 11_644_473_600

# Sanity bounds for FILETIME → Unix conversion (year 1970 – year 3000)
_UNIX_MIN: float = 0.0
_UNIX_MAX: float = 32_503_680_000.0


def filetime_to_str(ft: int) -> Optional[str]:
    """
    Converts a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    to a UTC timestamp string.

    Args:
        ft: 64-bit integer FILETIME value.

    Returns:
        'YYYY-MM-DD HH:MM:SS UTC' string, or None if ft is 0 or out of range.

    Example:
        >>> filetime_to_str(132_000_000_000_000_000)
        '2019-11-12 00:00:00 UTC'
    """
    if ft == 0:
        return None
    try:
        unix_ts = (ft / 10_000_000) - FILETIME_EPOCH_DIFF
        if not (_UNIX_MIN <= unix_ts <= _UNIX_MAX):
            return None
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (OSError, ValueError, OverflowError):
        return None


def filetime_to_datetime(ft: int) -> Optional[datetime]:
    """
    Converts a Windows FILETIME to a timezone-aware Python datetime (UTC).

    Returns:
        datetime object, or None if ft is 0 or invalid.
    """
    if ft == 0:
        return None
    try:
        unix_ts = (ft / 10_000_000) - FILETIME_EPOCH_DIFF
        if not (_UNIX_MIN <= unix_ts <= _UNIX_MAX):
            return None
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (OSError, ValueError, OverflowError):
        return None


def dos_date_time_to_str(dos_date: int, dos_time: int) -> Optional[str]:
    """
    Converts a DOS date + time pair (as found in FAT-based ShellItems) to a
    UTC timestamp string.

    DOS Date format (16-bit):
      bits 15-9 : year offset from 1980
      bits 8-5  : month (1-12)
      bits 4-0  : day (1-31)

    DOS Time format (16-bit):
      bits 15-11: hour (0-23)
      bits 10-5 : minute (0-59)
      bits 4-0  : 2-second count (0-29, multiply by 2 for actual seconds)

    Returns:
        'YYYY-MM-DD HH:MM:SS UTC' string, or None if both values are 0.
    """
    if dos_date == 0 and dos_time == 0:
        return None
    try:
        year   = ((dos_date >> 9) & 0x7F) + 1980
        month  = (dos_date >> 5) & 0x0F
        day    =  dos_date & 0x1F
        hour   = (dos_time >> 11) & 0x1F
        minute = (dos_time >> 5) & 0x3F
        second = (dos_time & 0x1F) * 2
        if not (1 <= month <= 12 and 1 <= day <= 31):
            return None
        dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Path Helpers
# ─────────────────────────────────────────────────────────────────────────────

def safe_basename(path: Optional[str]) -> str:
    """
    Null-safe wrapper around os.path.basename that also strips Windows null
    terminators (\\x00) found in some Recycle Bin $I path fields.

    Args:
        path: File path string, may be None.

    Returns:
        Basename string, or empty string if path is None/empty.
    """
    if not path:
        return ""
    return os.path.basename(path.rstrip("\x00"))


# 8.3 short-name suffix pattern  e.g. "PROGRA~1"
_SHORT_NAME_RE = re.compile(r"~\d+", re.IGNORECASE)


def path_normalise(path: Optional[str]) -> str:
    """
    Normalises a Windows file path for use as a correlation key.

    Transformations applied:
      1. Strip null terminators (common in Recycle Bin $I records).
      2. Convert to lower-case.
      3. Expand common environment-variable prefixes to canonical form.
      4. Replace forward slashes with backslashes.
      5. Strip 8.3 short-name suffixes (PROGRA~1 → programfiles, etc.).
      6. Collapse consecutive backslashes.

    This is intentionally lossy — the goal is a consistent lookup key,
    not a round-trippable path.

    Args:
        path: Raw path string from any artifact source.

    Returns:
        Normalised lower-case path string suitable as a dict key.

    Example:
        >>> path_normalise(r'C:\\PROGRA~1\\Wireshark\\wireshark.exe')
        'c:\\\\programfiles\\\\wireshark\\\\wireshark.exe'
    """
    if not path:
        return ""

    p = path.rstrip("\x00").lower().replace("/", "\\")

    # Expand common env-var prefixes that appear literally in some artifacts
    p = p.replace("%systemroot%", "c:\\windows")
    p = p.replace("%programfiles%", "c:\\program files")
    p = p.replace("%programfiles(x86)%", "c:\\program files (x86)")
    p = p.replace("%appdata%", "c:\\users\\<user>\\appdata\\roaming")
    p = p.replace("%localappdata%", "c:\\users\\<user>\\appdata\\local")
    p = p.replace("%temp%", "c:\\users\\<user>\\appdata\\local\\temp")

    # Strip 8.3 suffixes (PROGRA~1 → progra, then collapse)
    p = _SHORT_NAME_RE.sub("", p)

    # Collapse duplicate backslashes
    while "\\\\" in p:
        p = p.replace("\\\\", "\\")

    return p


# ─────────────────────────────────────────────────────────────────────────────
# Error / Traceback Helper
# ─────────────────────────────────────────────────────────────────────────────

def traceback_str(exc: Exception) -> str:
    """
    Returns the full formatted traceback for an exception as a single string.
    Useful for debug-mode logging without crashing the tool.

    Args:
        exc: The caught exception object.

    Returns:
        Multi-line traceback string.
    """
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


# ─────────────────────────────────────────────────────────────────────────────
# Centralised Path Configuration
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ForensicPaths:
    """
    Centralises every hardcoded path used by the triage tool.

    Live-system defaults reflect standard Windows 10/11 locations.
    When running in --offline mode, construct with root= set to the
    mount point of the forensic image (e.g., 'E:\\Image\\').

    Attributes:
        root          : Root drive/mount point.  Default 'C:\\'
        prefetch_dir  : Path to Prefetch directory.
        users_dir     : Path to Users directory.
        recycle_dir   : Path to $Recycle.Bin directory.
        output_dir    : Path where all output files are written.
        mode          : 'live' or 'offline' — controls warning display.

    Usage (live):
        paths = ForensicPaths()

    Usage (offline / image):
        paths = ForensicPaths(root='E:\\Mount\\', output_dir='E:\\Output')
    """

    root        : str = "C:\\"
    output_dir  : str = "output"
    mode        : str = "live"          # "live" | "offline"
    _prefetch   : str = field(default="", repr=False)
    _users      : str = field(default="", repr=False)
    _recycle    : str = field(default="", repr=False)
    _system32   : str = field(default="", repr=False)

    def __post_init__(self) -> None:
        # Normalise root: ensure trailing backslash
        if not self.root.endswith("\\"):
            self.root += "\\"

    # ── Derived paths (all relative to root) ─────────────────────────────────

    @property
    def prefetch_dir(self) -> str:
        return self._prefetch or os.path.join(self.root, "Windows", "Prefetch")

    @prefetch_dir.setter
    def prefetch_dir(self, v: str) -> None:
        self._prefetch = v

    @property
    def users_dir(self) -> str:
        return self._users or os.path.join(self.root, "Users")

    @users_dir.setter
    def users_dir(self, v: str) -> None:
        self._users = v

    @property
    def recycle_dir(self) -> str:
        return self._recycle or os.path.join(self.root, "$Recycle.Bin")

    @recycle_dir.setter
    def recycle_dir(self, v: str) -> None:
        self._recycle = v

    @property
    def system32_dir(self) -> str:
        return self._system32 or os.path.join(self.root, "Windows", "System32")

    @system32_dir.setter
    def system32_dir(self, v: str) -> None:
        self._system32 = v

    # ── Factory helpers ───────────────────────────────────────────────────────

    @classmethod
    def live(cls, output_dir: str = "output") -> "ForensicPaths":
        """Returns a ForensicPaths configured for live Windows analysis."""
        return cls(root="C:\\", output_dir=output_dir, mode="live")

    @classmethod
    def offline(cls, image_root: str, output_dir: str = "output") -> "ForensicPaths":
        """
        Returns a ForensicPaths configured for offline image analysis.

        Args:
            image_root: Mount point of the forensic image (e.g. 'E:\\').
            output_dir: Where to write all output files.
        """
        return cls(root=image_root, output_dir=output_dir, mode="offline")

    def summary(self) -> str:
        """Returns a human-readable summary of all configured paths."""
        lines = [
            f"  Mode         : {self.mode.upper()}",
            f"  Root         : {self.root}",
            f"  Prefetch     : {self.prefetch_dir}",
            f"  Users        : {self.users_dir}",
            f"  Recycle Bin  : {self.recycle_dir}",
            f"  Output       : {self.output_dir}",
        ]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Platform Info Helper
# ─────────────────────────────────────────────────────────────────────────────

def get_platform_string() -> str:
    """
    Returns a human-readable Windows version string.
    Replaces the hardcoded 'Windows 11 (live host system)' in
    forensic_summary_writer.py.

    Returns:
        e.g. 'Windows 10 (10.0.19045)' or 'Windows 11 (10.0.22631)'
    """
    try:
        rel     = platform.release()          # '10' or '11'
        version = platform.version()          # '10.0.19045'
        return f"Windows {rel} ({version})"
    except Exception:
        return "Windows (version unknown)"
