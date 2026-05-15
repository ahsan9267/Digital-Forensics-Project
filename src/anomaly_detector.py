"""
anomaly_detector.py
───────────────────
Forensic Anomaly Detection Engine.

Changes from v2.0:
  • safe_basename() imported from forensic_utils instead of raw os.path.basename.
  • debug= constructor flag for full traceback logging.
  • No logic changes — all 5 anomaly types preserved exactly.
"""

import os
from audit_logger   import ForensicAuditLogger
from forensic_utils import safe_basename, traceback_str


HIGH_VALUE_EXTENSIONS = {
    ".py", ".exe", ".bat", ".cmd", ".ps1", ".vbs",
    ".pcap", ".pcapng", ".cap",
    ".evtx", ".log", ".db", ".sqlite",
    ".kdbx", ".pem", ".key", ".pfx",
    ".zip", ".7z", ".rar",
}

RAPID_DELETION_WINDOW = 30  # seconds

USER_TOOL_KEYWORDS = [
    "WIRESHARK", "NMAP", "NPCAP", "BURP", "PYTHON", "POWERSHELL",
    "RAMCAPTURE", "VOLATILITY", "AUTOPSY", "REGEDIT", "PROCMON",
    "HASHCAT", "NETCAT", "MIMIKATZ", "SQLMAP",
]

BACKGROUND_KEYWORDS = [
    "UPDATE", "HELPER", "SERVICE", "SVCHOST", "RUNTIME",
    "INSTALLER", "SETUP", "UNINSTALL", "TASKHOST", "DLLHOST",
]


class AnomalyDetector:

    def __init__(self, logger: ForensicAuditLogger, debug: bool = False):
        self.logger = logger
        self.debug  = debug

    def detect(self, prefetch_events, userassist_events,
               recycle_events, lnk_events, jumplist_events) -> list[dict]:
        self.logger.log_section("Anomaly Detection Engine")
        anomalies = []

        for method in (self._type1, self._type3, self._type4, self._type5):
            try:
                if method == self._type1:
                    anomalies.extend(method(userassist_events, prefetch_events))
                elif method == self._type3:
                    anomalies.extend(method(prefetch_events, userassist_events))
                elif method in (self._type4, self._type5):
                    anomalies.extend(method(recycle_events))
            except Exception as exc:
                self.logger.log_error(f"Anomaly method {method.__name__} failed: {exc}")
                if self.debug:
                    self.logger.log_error(traceback_str(exc))

        try:
            anomalies.extend(self._type2(recycle_events, lnk_events, jumplist_events))
        except Exception as exc:
            self.logger.log_error(f"Anomaly _type2 failed: {exc}")
            if self.debug:
                self.logger.log_error(traceback_str(exc))

        priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        anomalies.sort(key=lambda x: priority.get(x["severity"], 3))

        counts = {
            "CRITICAL": sum(1 for a in anomalies if a["severity"] == "CRITICAL"),
            "HIGH":     sum(1 for a in anomalies if a["severity"] == "HIGH"),
            "MEDIUM":   sum(1 for a in anomalies if a["severity"] == "MEDIUM"),
        }
        self.logger.log(
            f"Anomaly Detection complete. "
            f"CRITICAL: {counts['CRITICAL']} | HIGH: {counts['HIGH']} | MEDIUM: {counts['MEDIUM']}"
        )
        return anomalies

    def _type1(self, userassist_events, prefetch_events):
        prefetch_names = set()
        for e in prefetch_events:
            exe = e.get("executable_name", "")
            if exe:
                prefetch_names.add(exe.upper())
                prefetch_names.add(os.path.splitext(exe.upper())[0])
        anomalies = []
        for event in userassist_events:
            if event.get("run_count", 0) == 0:
                continue
            app_path = event.get("application_path", "")
            exe_name = os.path.basename(app_path)
            if not exe_name.endswith(".exe") or "8WEKYB3D8BBWE" in exe_name.upper():
                continue
            exe_base = os.path.splitext(exe_name.upper())[0]
            if exe_name.upper() not in prefetch_names and exe_base not in prefetch_names:
                anomalies.append({
                    "anomaly_type"   : "TYPE 1 — Execution Without Prefetch Record",
                    "severity"       : "HIGH",
                    "description"    : (
                        f"'{exe_name}' executed {event.get('run_count')} time(s) "
                        f"(last: {event.get('last_run_time','unknown')}) but NO matching "
                        "Prefetch file found. Possible Prefetch disabled or selective clearing."
                    ),
                    "evidence"       : event,
                    "executable"     : exe_name,
                    "recommendation" : (
                        "Check if Prefetch is enabled. Verify if the executable ran from a "
                        "network share or USB drive which do not generate Prefetch entries."
                    ),
                })
                self.logger.log(f"[TYPE 1] No Prefetch for: {exe_name}")
        return anomalies

    def _type2(self, recycle_events, lnk_events, jumplist_events):
        accessed = set()
        for e in lnk_events:
            p = e.get("target_path", "")
            if p:
                accessed.add(safe_basename(p).lower())
        for e in jumplist_events:
            p = e.get("accessed_file", "")
            if p:
                accessed.add(safe_basename(p).lower())
        anomalies = []
        for event in recycle_events:
            orig  = event.get("original_path", "").rstrip("\x00")
            fname = safe_basename(orig).lower()
            if not fname or "." not in fname:
                continue
            if fname not in accessed:
                anomalies.append({
                    "anomaly_type"   : "TYPE 2 — Deletion Without Prior Access Record",
                    "severity"       : "MEDIUM",
                    "description"    : (
                        f"'{fname}' deleted on {event.get('deletion_time','unknown')} "
                        f"({event.get('original_size',0):,} bytes) but NO prior access "
                        "record found in LNK or Jump List artifacts."
                    ),
                    "evidence"       : event,
                    "filename"       : fname,
                    "recommendation" : (
                        "Investigate if the file was created remotely or downloaded "
                        "and immediately deleted without opening."
                    ),
                })
        self.logger.log(f"[TYPE 2] Deletions without access records: {len(anomalies)}")
        return anomalies

    def _type3(self, prefetch_events, userassist_events):
        ua_names = set()
        for e in userassist_events:
            p = e.get("application_path", "")
            if p:
                ua_names.add(os.path.basename(p).upper())
                ua_names.add(os.path.splitext(os.path.basename(p).upper())[0])
        anomalies = []
        for event in prefetch_events:
            exe      = event.get("executable_name", "").upper()
            exe_base = os.path.splitext(exe)[0]
            if not any(kw in exe_base for kw in USER_TOOL_KEYWORDS):
                continue
            if any(kw in exe_base for kw in BACKGROUND_KEYWORDS):
                continue
            if exe not in ua_names and exe_base not in ua_names:
                anomalies.append({
                    "anomaly_type"   : "TYPE 3 — Silent Execution (No UserAssist Record)",
                    "severity"       : "HIGH",
                    "description"    : (
                        f"Security tool '{exe}' confirmed executed via Prefetch "
                        f"(run count: {event.get('run_count',0)}, "
                        f"last: {event.get('last_run_time','unknown')}) but UserAssist "
                        "has NO record. Tool may have been run via CLI or script."
                    ),
                    "evidence"       : event,
                    "executable"     : exe,
                    "recommendation" : (
                        "Investigate how this tool was launched. Check command-line "
                        "execution artifacts and scheduled tasks."
                    ),
                })
                self.logger.log(f"[TYPE 3] Silent security tool: {exe}")
        return anomalies

    def _type4(self, recycle_events):
        timed = [
            (e.get("_deletion_dt_raw"), e)
            for e in recycle_events if e.get("_deletion_dt_raw")
        ]
        timed.sort(key=lambda x: x[0])
        anomalies = []
        i = 0
        while i < len(timed):
            window = [timed[i]]
            j = i + 1
            while j < len(timed) and (
                timed[j][0] - timed[i][0]
            ).total_seconds() <= RAPID_DELETION_WINDOW:
                window.append(timed[j])
                j += 1
            if len(window) >= 5:
                files = [safe_basename(e.get("original_path", "")) for _, e in window]
                anomalies.append({
                    "anomaly_type"   : "TYPE 4 — Rapid Sequential Deletions",
                    "severity"       : "CRITICAL",
                    "description"    : (
                        f"{len(window)} files deleted within {RAPID_DELETION_WINDOW}s "
                        f"starting {timed[i][0].strftime('%Y-%m-%d %H:%M:%S UTC')}. "
                        f"Files: {', '.join(files[:5])}{'...' if len(files)>5 else ''}. "
                        "Strong indicator of scripted evidence destruction."
                    ),
                    "evidence"       : timed[i][1],
                    "file_count"     : len(window),
                    "start_time"     : timed[i][0].strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "recommendation" : (
                        "Check Prefetch for .bat/.cmd/.py scripts executed just before "
                        "this timestamp. Correlate with UserAssist and Jump Lists."
                    ),
                })
                self.logger.log(f"[TYPE 4] Rapid deletion: {len(window)} files in {RAPID_DELETION_WINDOW}s")
                i = j
            else:
                i += 1
        return anomalies

    def _type5(self, recycle_events):
        anomalies = []
        for event in recycle_events:
            orig = event.get("original_path", "").rstrip("\x00")
            if not orig:
                continue
            ext = os.path.splitext(orig)[1].lower()
            if ext not in HIGH_VALUE_EXTENSIONS:
                continue
            severity = (
                "HIGH" if ext in {
                    ".exe", ".py", ".bat", ".ps1",
                    ".pcap", ".pcapng", ".evtx",
                    ".kdbx", ".pem", ".key"
                }
                else "MEDIUM"
            )
            anomalies.append({
                "anomaly_type"   : "TYPE 5 — High-Value File Deletion",
                "severity"       : severity,
                "description"    : (
                    f"High-value file deleted: '{safe_basename(orig)}' ({ext}) "
                    f"on {event.get('deletion_time','unknown')}. "
                    f"Size: {event.get('original_size',0):,} bytes."
                ),
                "evidence"       : event,
                "filename"       : safe_basename(orig),
                "extension"      : ext,
                "recommendation" : (
                    f"Investigate why this {ext} file was deleted. "
                    "Attempt file carving from unallocated space if recovery needed."
                ),
            })
        self.logger.log(f"[TYPE 5] High-value deletions: {len(anomalies)}")
        return anomalies
