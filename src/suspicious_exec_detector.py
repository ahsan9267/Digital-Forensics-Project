"""
suspicious_exec_detector.py
────────────────────────────
Detects executions from forensically suspicious locations.

Changes from v2.0:
  • safe_basename() imported from forensic_utils.
  • debug= constructor flag.
  • No logic changes — all patterns and whitelist preserved.
"""

import os
import re

from audit_logger   import ForensicAuditLogger
from forensic_utils import safe_basename, traceback_str


SUSPICIOUS_PATTERNS = [
    (r'\\temp\\',             "HIGH",   "TEMP Directory",
     "Execution from TEMP — primary malware staging location"),
    (r'\\tmp\\',              "HIGH",   "TMP Directory",
     "Execution from TMP — temporary directory, files here are transient"),
    (r'\\windows\\temp',      "HIGH",   "Windows Temp",
     "Execution from Windows Temp — often used by malware droppers"),
    (r'\\\$recycle',          "HIGH",   "Recycle Bin",
     "Execution from Recycle Bin — almost never legitimate"),
    (r'\\downloads\\',        "MEDIUM", "Downloads Folder",
     "Execution from Downloads — common delivery location for malicious files"),
    (r'\\appdata\\roaming\\', "MEDIUM", "AppData Roaming",
     "Execution from AppData Roaming — user-writable, no admin required"),
    (r'\\appdata\\local\\',   "MEDIUM", "AppData Local",
     "Execution from AppData Local — user-writable, no admin required"),
    (r'\\desktop\\',          "MEDIUM", "Desktop",
     "Execution from Desktop — non-standard for legitimate software"),
    (r'^[d-z]:\\[^\\]+\.exe$',"MEDIUM", "Drive Root Execution",
     "Execution from drive root — common USB autorun pattern"),
    (r'\\onedrive\\',         "LOW",    "OneDrive Folder",
     "Execution from OneDrive — cloud-synced, possible remote delivery"),
]

WHITELIST = {
    "runtimebroker.exe", "svchost.exe", "taskhostw.exe", "sihost.exe",
    "ctfmon.exe", "dllhost.exe", "conhost.exe", "werfault.exe",
    "backgroundtaskhost.exe", "searchindexer.exe", "msiexec.exe",
    "windowsdefender.exe", "msmpeng.exe", "nissrv.exe",
}


class SuspiciousExecutionDetector:

    def __init__(self, logger: ForensicAuditLogger, debug: bool = False):
        self.logger = logger
        self.debug  = debug

    def analyse(self, prefetch_events: list[dict],
                userassist_events: list[dict]) -> list[dict]:
        self.logger.log_section("Suspicious Execution Detector")
        findings = []

        for event in prefetch_events:
            exe_name = event.get("executable_name", "")
            if not exe_name:
                continue
            try:
                result = self._check_path(
                    path=exe_name,
                    source="Prefetch",
                    timestamp=event.get("last_run_time"),
                    run_count=event.get("run_count", 0),
                    extra={"prefetch_hash": event.get("prefetch_hash", "")},
                )
                if result:
                    findings.append(result)
            except Exception as exc:
                self.logger.log_error(f"SuspExec check failed for {exe_name}: {exc}")
                if self.debug:
                    self.logger.log_error(traceback_str(exc))

        for event in userassist_events:
            app_path = event.get("application_path", "")
            if not app_path:
                continue
            try:
                result = self._check_path(
                    path=app_path,
                    source="UserAssist",
                    timestamp=event.get("last_run_time"),
                    run_count=event.get("run_count", 0),
                    extra={"guid_category": event.get("guid_category", "")},
                )
                if result:
                    findings.append(result)
            except Exception as exc:
                self.logger.log_error(f"SuspExec check failed for {app_path}: {exc}")
                if self.debug:
                    self.logger.log_error(traceback_str(exc))

        # Deduplicate by executable name
        seen   = set()
        unique = []
        for f in findings:
            key = f["executable_name"].lower()
            if key not in seen:
                seen.add(key)
                unique.append(f)

        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        unique.sort(key=lambda x: order.get(x["risk_level"], 3))

        high   = sum(1 for f in unique if f["risk_level"] == "HIGH")
        medium = sum(1 for f in unique if f["risk_level"] == "MEDIUM")
        low    = sum(1 for f in unique if f["risk_level"] == "LOW")
        self.logger.log(
            f"Suspicious Execution Detector complete. "
            f"HIGH: {high} | MEDIUM: {medium} | LOW: {low}"
        )
        return unique

    def _check_path(self, path: str, source: str, timestamp,
                     run_count: int, extra: dict) -> dict | None:
        exe_name = safe_basename(path).lower()
        if exe_name in WHITELIST:
            return None

        path_lower    = path.lower()
        matched_rules = []
        highest_risk  = None

        for pattern, risk, category, note in SUSPICIOUS_PATTERNS:
            if re.search(pattern, path_lower):
                matched_rules.append({
                    "risk_level": risk,
                    "category"  : category,
                    "note"      : note,
                })
                if highest_risk is None or risk == "HIGH":
                    highest_risk = risk
                elif highest_risk == "LOW" and risk == "MEDIUM":
                    highest_risk = risk

        depth = path.count("\\")
        if depth >= 6 and not matched_rules:
            matched_rules.append({
                "risk_level": "LOW",
                "category"  : "Deeply Nested Path",
                "note"      : f"Execution from {depth}-level deep path — possible obfuscation",
            })
            highest_risk = "LOW"

        if not matched_rules:
            return None

        if len(matched_rules) >= 2 and highest_risk == "MEDIUM":
            highest_risk = "HIGH"
            self.logger.log(f"  Risk escalated to HIGH (multiple flags): {exe_name}")

        return {
            "artifact_source" : "SuspiciousExec",
            "executable_name" : safe_basename(path),
            "full_path"       : path,
            "source_artifact" : source,
            "risk_level"      : highest_risk,
            "category"        : matched_rules[0]["category"],
            "forensic_note"   : matched_rules[0]["note"],
            "all_flags"       : matched_rules,
            "flag_count"      : len(matched_rules),
            "timestamp"       : timestamp,
            "run_count"       : run_count,
            **extra,
        }
