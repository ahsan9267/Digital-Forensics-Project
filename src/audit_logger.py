
import hashlib
import os
from datetime import datetime


class ForensicAuditLogger:
    """
    Central audit logger for the Windows Forensic Triage Tool.

    Usage:
        logger = ForensicAuditLogger(output_dir="output")
        logger.log("Tool started")
        md5, sha256 = logger.hash_file(r"C:\\Windows\\Prefetch\\CMD.EXE-XXXXXXXX.pf")
    """

    def __init__(self, output_dir: str = "output"):
        """
        Initialises the logger. Creates the output directory if it does not exist.
        Opens (or creates) audit_log.txt and hashes.txt inside output_dir.

        Args:
            output_dir: Path to the folder where output files will be written.
        """
        os.makedirs(output_dir, exist_ok=True)
        self.output_dir = output_dir
        self.audit_log_path = os.path.join(output_dir, "audit_log.txt")
        self.hashes_path    = os.path.join(output_dir, "hashes.txt")

        # Write audit log header only when file is first created
        if not os.path.exists(self.audit_log_path):
            self._write_raw(self.audit_log_path,
                f"{'='*70}\n"
                f"FORENSIC AUDIT LOG\n"
                f"Windows Forensic Triage Tool\n"
                f"Session Started : {self._now()}\n"
                f"{'='*70}\n\n"
            )

        # Write hashes file header only when first created
        if not os.path.exists(self.hashes_path):
            self._write_raw(self.hashes_path,
                f"{'='*70}\n"
                f"FORENSIC HASH VERIFICATION LOG\n"
                f"Session Started : {self._now()}\n"
                f"{'='*70}\n\n"
                f"{'FILE PATH':<60}  {'MD5':<32}  {'SHA-256'}\n"
                f"{'-'*160}\n"
            )

    # ─────────────────────────────────────────────────────────────────────────
    # Public Interface
    # ─────────────────────────────────────────────────────────────────────────

    def log(self, message: str) -> None:
        """
        Appends a timestamped entry to the audit log.

        Args:
            message: The event description to log.
        """
        entry = f"[{self._now()}]  {message}\n"
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(entry)

    def hash_file(self, file_path: str) -> tuple[str, str]:
        """
        Computes MD5 and SHA-256 of a file using chunked reading (read-only, "rb").
        Records the result in hashes.txt and in the audit log.

        Args:
            file_path: Absolute or relative path to the source artifact file.

        Returns:
            Tuple (md5_hex, sha256_hex).

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError:   If the file cannot be read (e.g., locked by OS).
        """
        md5_h    = hashlib.md5()
        sha256_h = hashlib.sha256()

        # ── READ-ONLY access ──────────────────────────────────────────────────
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(65536)   # 64 KB chunks — efficient for large files
                if not chunk:
                    break
                md5_h.update(chunk)
                sha256_h.update(chunk)

        md5_hex    = md5_h.hexdigest()
        sha256_hex = sha256_h.hexdigest()

        # ── Log to audit trail ────────────────────────────────────────────────
        self.log(f"HASH COMPUTED  | {file_path}")
        self.log(f"  MD5          | {md5_hex}")
        self.log(f"  SHA-256      | {sha256_hex}")

        # ── Append to hashes.txt ──────────────────────────────────────────────
        with open(self.hashes_path, "a", encoding="utf-8") as fh:
            fh.write(f"{file_path:<60}  {md5_hex:<32}  {sha256_hex}\n")

        return md5_hex, sha256_hex

    def log_section(self, section_name: str) -> None:
        """Writes a visual separator into the audit log for readability."""
        separator = f"\n{'─'*70}\n  MODULE: {section_name.upper()}\n{'─'*70}\n"
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(separator)

    def log_error(self, message: str) -> None:
        """Logs an error event (prefixed with ERROR for easy grep)."""
        self.log(f"[ERROR]  {message}")

    # ─────────────────────────────────────────────────────────────────────────
    # Private Helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _now() -> str:
        """Returns current UTC timestamp with millisecond precision."""
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"

    @staticmethod
    def _write_raw(path: str, content: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
