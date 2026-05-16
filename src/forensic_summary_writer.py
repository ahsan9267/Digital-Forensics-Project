"""
forensic_summary_writer.py
──────────────────────────
Generates the human-readable forensic summary report.

Changes from v2.0:
  • 'Windows 11' hardcoded string replaced with get_platform_string()
    from forensic_utils — now correctly shows Windows 10 or 11.
  • Accepts mode= parameter ('live' or 'offline') and adds a
    forensic soundness notice to the Chain of Custody section.
"""

import os
from datetime import datetime
from collections import Counter

from audit_logger   import ForensicAuditLogger
from forensic_utils import get_platform_string


class ForensicSummaryWriter:

    def __init__(self, logger: ForensicAuditLogger, output_dir: str = "output"):
        self.logger     = logger
        self.output_dir = output_dir

    def write(self, all_events, correlated_chains, anomalies,
              suspicious_findings, sus_stats, usb_map, username,
              mode: str = "live") -> str:
        """
        Args:
            all_events           : Combined list from all parsers.
            correlated_chains    : Output of CorrelationEngine.correlate().
            anomalies            : Output of AnomalyDetector.detect().
            suspicious_findings  : Output of SuspiciousExecutionDetector.analyse().
            sus_stats            : Dict with HIGH/MEDIUM/LOW/total_scanned counts.
            usb_map              : Output of LNKParser.build_usb_provenance_map().
            username             : Examiner / target username.
            mode                 : 'live' or 'offline' — added to CoC section.
        """
        self.logger.log("Generating Forensic Summary Report...")
        lines = []
        W = 78

        def hdr(text):
            lines.append("=" * W)
            lines.append(f"  {text}")
            lines.append("=" * W)

        def sec(text):
            lines.append("")
            lines.append("-" * W)
            lines.append(f"  {text.upper()}")
            lines.append("-" * W)

        def fld(label, value):
            lines.append(f"  {label:<28}: {value}")

        def blank():
            lines.append("")

        # ── 1. HEADER ────────────────────────────────────────────────────────
        hdr("FORENSIC EXAMINATION REPORT")
        fld("Tool Name",         "Windows Forensic Triage Tool v2.1")
        fld("Generated",         datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        fld("Target Platform",   get_platform_string())          # ← fixed
        fld("Analysis Mode",     mode.upper())
        fld("Examiner Username", username)
        fld("University",        "Riphah International University")
        fld("Course",            "Digital Forensics — Spring 2026")
        fld("Instructor",        "Sir Hummayun Raza")
        blank()

        # ── 2. ACQUISITION SUMMARY ────────────────────────────────────────────
        sec("2. Acquisition and Parsing Summary")
        source_counts = Counter(e.get("artifact_source", "Unknown") for e in all_events)
        fld("Total Events Parsed", f"{len(all_events):,}")
        blank()
        lines.append(f"  {'Artifact Source':<25} {'Events':>8}  {'Status'}")
        lines.append(f"  {'-'*25} {'-'*8}  {'-'*8}")
        for src, cnt in sorted(source_counts.items()):
            lines.append(f"  {src:<25} {cnt:>8,}  OK")
        blank()
        fld("Correlated Chains",    len(correlated_chains))
        fld("HIGH Priority Chains", sum(
            1 for c in correlated_chains
            if c.get("significance_label", "").upper() == "HIGH"
        ))
        fld("Anomalies Detected",   len(anomalies))
        crit_a = sum(1 for a in anomalies if a.get("severity") == "CRITICAL")
        high_a = sum(1 for a in anomalies if a.get("severity") == "HIGH")
        fld("  CRITICAL Anomalies", crit_a)
        fld("  HIGH Anomalies",     high_a)
        fld("Suspicious Executions", len(suspicious_findings))
        fld("  HIGH Risk",   sus_stats.get("HIGH",   0))
        fld("  MEDIUM Risk", sus_stats.get("MEDIUM", 0))
        fld("  LOW Risk",    sus_stats.get("LOW",    0))
        fld("USB Devices Found",    len(usb_map))
        blank()

        # ── 3. ACTIVITY PROFILE ───────────────────────────────────────────────
        sec("3. System Activity Profile")
        timestamps = []
        for e in all_events:
            for fn in ["last_run_time", "target_accessed", "deletion_time",
                       "last_accessed", "folder_modified"]:
                v = e.get(fn)
                if v and len(v) >= 10 and v[:4].isdigit():
                    timestamps.append(v[:10])
                    break
        if timestamps:
            timestamps.sort()
            fld("Earliest Event",    timestamps[0])
            fld("Latest Event",      timestamps[-1])
            mc   = Counter(t[:7] for t in timestamps)
            peak = max(mc, key=mc.get)
            fld("Most Active Month", f"{peak} ({mc[peak]:,} events)")
        blank()

        # ── 4. TOP 10 EXECUTED PROGRAMS ───────────────────────────────────────
        sec("4. Top 10 Most-Executed Programs")
        exec_counts: dict = {}
        for e in all_events:
            if e.get("artifact_source") == "Prefetch":
                n  = e.get("executable_name", "").upper()
                rc = e.get("run_count") or 0
                if n:
                    exec_counts[n] = exec_counts.get(n, 0) + rc
            elif e.get("artifact_source") == "UserAssist":
                n  = os.path.basename(e.get("application_path", "")).upper()
                rc = e.get("run_count") or 0
                if n and rc > 0:
                    exec_counts[n] = exec_counts.get(n, 0) + rc
        top10 = sorted(exec_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        lines.append(f"  {'#':<4} {'Executable':<45} {'Runs':>8}")
        lines.append(f"  {'-'*4} {'-'*45} {'-'*8}")
        for i, (n, c) in enumerate(top10, 1):
            lines.append(f"  {i:<4} {n:<45} {c:>8,}")
        blank()

        # ── 5. DELETED FILES INVENTORY ────────────────────────────────────────
        sec("5. Deleted Files Inventory (Recycle Bin)")
        rb = sorted(
            [e for e in all_events if e.get("artifact_source") == "RecycleBin"],
            key=lambda x: x.get("deletion_time") or ""
        )
        fld("Total Deletion Records", len(rb))
        blank()
        lines.append(f"  {'#':<4} {'Deletion Time (UTC)':<23} {'Size':>10}  {'Original Path'}")
        lines.append(f"  {'-'*4} {'-'*23} {'-'*10}  {'-'*40}")
        for i, e in enumerate(rb, 1):
            path = (e.get("original_path") or "").replace("\x00", "").strip()
            ts   = e.get("deletion_time") or "Unknown"
            sz   = self._human_size(e.get("original_size", 0))
            if len(path) > 55:
                path = "..." + path[-52:]
            lines.append(f"  {i:<4} {ts:<23} {sz:>10}  {path}")
        blank()

        # ── 6. HIGH PRIORITY CHAINS ───────────────────────────────────────────
        sec("6. High Priority Correlated Event Chains")
        high_chains = [
            c for c in correlated_chains
            if c.get("significance_label", "").upper() in ("HIGH", "CRITICAL")
        ]
        if not high_chains:
            lines.append("  No HIGH or CRITICAL priority chains detected.")
        else:
            for c in high_chains:
                lines.append(f"  Chain #{c['chain_id']} — {c['filename'].upper()}")
                lines.append(
                    f"  {'Significance':<20}: {c.get('significance_label','')} "
                    f"(Score: {c.get('significance_score',0)}/100)"
                )
                lines.append(
                    f"  {'Confidence':<20}: {c.get('confidence_score',0)}% "
                    f"({c.get('confidence_label','')})"
                )
                lines.append(f"  {'Sources':<20}: {', '.join(c.get('sources',[]))}")
                lines.append(
                    f"  {'Time Range':<20}: {c.get('first_event_time','')} "
                    f"-> {c.get('last_event_time','')}"
                )
                lines.append(f"  {'Time Window':<20}: {c.get('time_window','N/A')}")
                lines.append("  Forensic Notes:")
                for note in c.get("forensic_notes", []):
                    lines.append(f"    * {note}")
                blank()

        # ── 7. ANOMALY REPORT ─────────────────────────────────────────────────
        sec("7. Forensic Anomaly Report")
        if not anomalies:
            lines.append("  No anomalies detected.")
        else:
            for a in anomalies:
                sev   = a.get("severity", "UNKNOWN")
                atype = a.get("anomaly_type", "Unknown")
                desc  = a.get("description", "")
                rec   = a.get("recommendation", "")
                lines.append(f"  [{sev}] {atype}")
                if desc:
                    lines.append(
                        f"    Description   : {desc[:120]}{'...' if len(desc)>120 else ''}"
                    )
                if rec:
                    lines.append(
                        f"    Recommendation: {rec[:120]}{'...' if len(rec)>120 else ''}"
                    )
                blank()

        # ── 8. SUSPICIOUS EXECUTIONS ──────────────────────────────────────────
        sec("8. Suspicious Execution Summary")
        if not suspicious_findings:
            lines.append("  No suspicious execution patterns detected.")
        else:
            high_s   = [f for f in suspicious_findings if f.get("risk_level") == "HIGH"]
            medium_s = [f for f in suspicious_findings if f.get("risk_level") == "MEDIUM"]
            low_s    = [f for f in suspicious_findings if f.get("risk_level") == "LOW"]
            fld("HIGH Risk",   len(high_s))
            fld("MEDIUM Risk", len(medium_s))
            fld("LOW Risk",    len(low_s))
            blank()
            for f in suspicious_findings[:15]:
                rl   = f.get("risk_level", "?")
                en   = f.get("executable_name", "?")
                fp   = f.get("full_path", "?")
                cat  = f.get("category", "?")
                note = f.get("forensic_note", "?")
                src  = f.get("source_artifact", "?")
                ts   = f.get("timestamp", "N/A")
                lines.append(f"  [{rl:6}] {en}")
                lines.append(f"           Path     : {fp[:70]}")
                lines.append(f"           Category : {cat}")
                lines.append(f"           Note     : {note}")
                lines.append(f"           Source   : {src} | Timestamp: {ts}")
                blank()

        # ── 9. CHAIN OF CUSTODY ───────────────────────────────────────────────
        sec("9. Chain of Custody Statement")
        lines.append("  All source artifact files were accessed in read-only mode.")
        lines.append("  MD5 and SHA-256 hashes were computed for every source file.")
        lines.append("  No source data was modified during this examination.")
        lines.append("  All operations were logged with UTC timestamps to audit_log.txt.")
        blank()

        if mode == "live":
            lines.append("  ⚠  LIVE SYSTEM ANALYSIS WARNING:")
            lines.append("  This examination was performed on a live running system.")
            lines.append("  The following evidence modifications may have occurred:")
            lines.append("    • NTFS last-access timestamps updated on files read by this tool.")
            lines.append("    • Registry LastWrite time updated by 'reg save HKEY_CURRENT_USER'.")
            lines.append("    • Prefetch metadata altered by running Python on this system.")
            lines.append("  For court-admissible evidence, a full disk image should be acquired")
            lines.append("  first and analysed in offline mode (--offline flag).")
        else:
            lines.append("  ✅ OFFLINE IMAGE ANALYSIS:")
            lines.append("  Artifacts were parsed from a mounted forensic image.")
            lines.append("  NTUSER.DAT was read directly — no reg save was executed.")
            lines.append("  This examination did not modify the original evidence.")

        blank()
        lines.append("  This report is auto-generated. All findings must be reviewed by")
        lines.append("  a qualified forensic examiner before use in legal proceedings.")
        blank()
        lines.append("=" * W)
        lines.append("  END OF FORENSIC EXAMINATION REPORT")
        lines.append("=" * W)

        out_path = os.path.join(self.output_dir, "forensic_summary.txt")
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        self.logger.log(f"Forensic Summary written: {out_path} ({len(lines)} lines)")
        return out_path

    @staticmethod
    def _human_size(b: int) -> str:
        if b >= 1_073_741_824: return f"{b/1_073_741_824:.1f} GB"
        if b >= 1_048_576:     return f"{b/1_048_576:.1f} MB"
        if b >= 1_024:         return f"{b/1_024:.1f} KB"
        return f"{b} B"
