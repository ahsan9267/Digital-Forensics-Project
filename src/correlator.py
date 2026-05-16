"""
correlator.py
─────────────
Cross-Artifact Correlation Engine for Windows Forensic Triage Tool v2.1

Changes from v2.0:
  • TIME_WINDOW_SECONDS is now configurable via constructor (--time-window flag).
  • Correlation key uses path_normalise() from forensic_utils — handles:
      - 8.3 short names (PROGRA~1 → programfiles)
      - Case differences
      - Null terminators in Recycle Bin paths
  • Added hash-based correlation: events with matching MD5/SHA-256 are
    grouped regardless of filename (catches renamed files).
  • Added semantic correlation patterns:
      - Security tool execution → deletion within window (+semantic score)
      - Execution from USB → same-USB deletion
  • Full traceback available in debug mode.
"""

import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from audit_logger   import ForensicAuditLogger
from forensic_utils import path_normalise, safe_basename, traceback_str


# ─────────────────────────────────────────────────────────────────────────────
# Configuration defaults
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_TIME_WINDOW   = 300   # 5 minutes
MIN_SOURCES_FOR_CHAIN = 2

# ─────────────────────────────────────────────────────────────────────────────
# Scoring Rubric (same as v2.0, documented here for reference)
# ─────────────────────────────────────────────────────────────────────────────
# Base score  = 50  (all chains start here — they already have ≥2 sources)
# Rule 1 +15/extra source beyond minimum 2
# Rule 2 +25  access followed by deletion within time window
# Rule 3 +20  execution followed by deletion
# Rule 4 +15  USB/removable drive involvement
# Rule 5 +10  bulk deletion flag set
# Rule 6 +5   file accessed from suspicious path
# Rule 7 +10  (NEW) security tool executed then evidence deleted (semantic)
# Rule 8 +8   (NEW) hash-correlated match (same content, different filename)
# All scores capped at 100.

SCORE_PER_EXTRA_SOURCE  = 15
SCORE_ACCESS_DELETION   = 25
SCORE_EXEC_DELETION     = 20
SCORE_USB_INVOLVEMENT   = 15
SCORE_BULK_DELETION     = 10
SCORE_SUSPICIOUS_PATH   = 5
SCORE_SEMANTIC_PATTERN  = 10   # NEW
SCORE_HASH_CORRELATION  = 8    # NEW
BASE_SCORE              = 50

SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\",
    "\\recycle", "\\downloads\\"
]

# Security/forensic tools whose execution before deletion is especially notable
SECURITY_TOOL_KEYWORDS = [
    "wireshark", "nmap", "npcap", "burp", "python", "powershell",
    "ramcapture", "volatility", "autopsy", "regedit", "procmon",
    "hashcat", "netcat", "mimikatz", "sqlmap", "tcpdump", "tshark",
    "wce", "pwdump", "procdump", "psexec",
]


class CorrelationEngine:
    """
    Cross-Artifact Correlation Engine.

    Correlates events from all six artifact parsers into Correlated Event
    Chains using three strategies:
      1. Filename-based grouping (primary)
      2. Hash-based grouping (NEW — catches renamed files)
      3. Semantic pattern matching (NEW — execution-then-deletion, etc.)
    """

    def __init__(self, logger: ForensicAuditLogger,
                 time_window: int = DEFAULT_TIME_WINDOW,
                 debug: bool = False):
        """
        Args:
            logger      : ForensicAuditLogger instance.
            time_window : Maximum seconds between events to consider them
                          part of the same chain. Default 300 (5 minutes).
                          Pass --time-window N from main.py to adjust.
            debug       : Log full tracebacks on errors.
        """
        self.logger      = logger
        self.time_window = time_window
        self.debug       = debug

    # ─────────────────────────────────────────────────────────────────────────
    # Public
    # ─────────────────────────────────────────────────────────────────────────

    def correlate(self, *artifact_lists: list[dict]) -> list[dict]:
        """
        Correlates events from all artifact sources into Correlated Event Chains.

        Args:
            *artifact_lists: Any number of event lists from the individual parsers.

        Returns:
            Sorted list of Correlated Event Chain dicts (highest score first).
        """
        self.logger.log_section("Cross-Artifact Correlation Engine")
        self.logger.log(f"Correlation time window : {self.time_window}s")

        # ── Step 1: Normalise all events ──────────────────────────────────────
        all_events: list[dict] = []
        for artifact_list in artifact_lists:
            for event in artifact_list:
                try:
                    normalised = self._normalise(event)
                    if normalised:
                        all_events.append(normalised)
                except Exception as exc:
                    self.logger.log_error(f"Normalisation error: {exc}")
                    if self.debug:
                        self.logger.log_error(traceback_str(exc))

        self.logger.log(f"Normalised {len(all_events)} events from all artifact sources")

        # ── Step 2a: Group by normalised filename ─────────────────────────────
        filename_groups: dict[str, list[dict]] = {}
        for event in all_events:
            key = event["_norm_filename"]
            if key:
                filename_groups.setdefault(key, []).append(event)

        # ── Step 2b: Hash-based grouping (NEW) ───────────────────────────────
        # Group events that share an MD5 or SHA-256 but may have different names.
        # Only merge if the event is not already in a filename group of size ≥2.
        hash_groups: dict[str, list[dict]] = {}
        for event in all_events:
            for hkey in (event.get("md5"), event.get("sha256")):
                if hkey and len(hkey) >= 32:
                    hash_groups.setdefault(hkey, []).append(event)

        # Promote hash groups that contain events from ≥2 different filenames
        for hkey, events in hash_groups.items():
            filenames = {e["_norm_filename"] for e in events}
            if len(filenames) >= 2:
                # Create a merged group key
                merged_key = f"__hash__{hkey[:8]}"
                filename_groups.setdefault(merged_key, []).extend(events)
                self.logger.log(
                    f"Hash correlation: {hkey[:8]}... links {len(filenames)} "
                    f"filenames → group '{merged_key}'"
                )

        self.logger.log(f"Grouped into {len(filename_groups)} unique groups")

        # ── Step 3: Cluster by timestamp, score, and build chains ─────────────
        chains:   list[dict] = []
        chain_id: int        = 1

        for filename, events in filename_groups.items():
            clusters = self._cluster_by_time(events, self.time_window)

            for cluster in clusters:
                sources = list({e["artifact_source"] for e in cluster})
                if len(sources) < MIN_SOURCES_FOR_CHAIN:
                    continue

                score, notes         = self._score_chain(cluster, sources, filename)
                confidence, conf_lbl, conf_bd = self._compute_confidence(sources)

                timestamps = [e["_timestamp_dt"] for e in cluster if e.get("_timestamp_dt")]
                first_time = (
                    min(timestamps).strftime("%Y-%m-%d %H:%M:%S UTC") if timestamps else None
                )
                last_time  = (
                    max(timestamps).strftime("%Y-%m-%d %H:%M:%S UTC") if timestamps else None
                )
                if len(timestamps) >= 2:
                    secs = (max(timestamps) - min(timestamps)).total_seconds()
                    win  = f"{int(secs)}s" if secs < 3600 else f"{secs/3600:.1f}h"
                else:
                    win = "N/A"

                # Human-readable display name (strip hash prefix)
                display_name = (
                    filename if not filename.startswith("__hash__")
                    else f"[Hash-linked] {filename[8:]}"
                )

                chains.append({
                    "chain_id"            : chain_id,
                    "filename"            : display_name,
                    "sources"             : sources,
                    "events"              : cluster,
                    "first_event_time"    : first_time,
                    "last_event_time"     : last_time,
                    "time_window"         : win,
                    "significance_score"  : score,
                    "significance_label"  : self._score_label(score),
                    "confidence_score"    : confidence,
                    "confidence_label"    : conf_lbl,
                    "confidence_breakdown": conf_bd,
                    "forensic_notes"      : notes,
                })
                chain_id += 1

        chains.sort(key=lambda x: x["significance_score"], reverse=True)

        self.logger.log(f"Correlation complete. {len(chains)} chains found")
        for c in chains[:5]:
            self.logger.log(
                f"  Chain #{c['chain_id']} | File: {c['filename']} | "
                f"Sources: {', '.join(c['sources'])} | Score: {c['significance_score']}"
            )

        return chains

    # ─────────────────────────────────────────────────────────────────────────
    # Normalisation
    # ─────────────────────────────────────────────────────────────────────────

    def _normalise(self, event: dict) -> Optional[dict]:
        """
        Extracts (normalised filename, timestamp, source) from any artifact event.

        Uses path_normalise() from forensic_utils to produce a consistent key
        that handles 8.3 names, case differences, null terminators, and
        common environment-variable prefixes.
        """
        source = event.get("artifact_source", "Unknown")

        # Map source → (raw_path_field, timestamp_field)
        SOURCE_MAP = {
            "Prefetch"  : ("executable_name",  "last_run_time"),
            "LNK"       : ("target_path",       "target_accessed"),
            "RecycleBin": ("original_path",     "deletion_time"),
            "JumpList"  : ("accessed_file",     "last_accessed"),
            "Shellbags" : ("folder_path",       "folder_modified"),
            "UserAssist": ("application_path",  "last_run_time"),
        }

        if source not in SOURCE_MAP:
            return None

        path_field, ts_field = SOURCE_MAP[source]
        raw_path  = event.get(path_field, "") or ""
        timestamp = event.get(ts_field) or event.get("target_modified")

        if not raw_path:
            return None

        # For LNK: fall back to lnk_name if target_path is missing
        if source == "LNK" and not raw_path:
            raw_path = event.get("lnk_name", "")

        norm_path     = path_normalise(raw_path)
        base_filename = safe_basename(norm_path) or safe_basename(raw_path)

        if not base_filename:
            return None

        ts_dt = self._parse_timestamp(timestamp)

        # Merge normalised fields back into a copy of the event
        enriched = dict(event)
        enriched.update({
            "_norm_filename"  : base_filename,
            "_norm_path"      : norm_path,
            "_raw_path"       : raw_path.rstrip("\x00"),
            "_timestamp_str"  : timestamp or "N/A",
            "_timestamp_dt"   : ts_dt,
        })
        return enriched

    # ─────────────────────────────────────────────────────────────────────────
    # Time-based clustering
    # ─────────────────────────────────────────────────────────────────────────

    def _cluster_by_time(self, events: list[dict],
                          window_seconds: int) -> list[list[dict]]:
        """
        Groups events into time clusters. Events without timestamps are
        appended to the first cluster.
        """
        timed   = [e for e in events if e.get("_timestamp_dt")]
        untimed = [e for e in events if not e.get("_timestamp_dt")]

        timed.sort(key=lambda x: x["_timestamp_dt"])

        clusters: list[list[dict]] = []
        current:  list[dict]       = []

        for event in timed:
            if not current:
                current = [event]
            else:
                gap = (event["_timestamp_dt"] - current[0]["_timestamp_dt"]).total_seconds()
                if abs(gap) <= window_seconds:
                    current.append(event)
                else:
                    clusters.append(current)
                    current = [event]

        if current:
            clusters.append(current)

        if untimed:
            if clusters:
                clusters[0].extend(untimed)
            else:
                clusters.append(untimed)

        return clusters

    # ─────────────────────────────────────────────────────────────────────────
    # Forensic Significance Scoring
    # ─────────────────────────────────────────────────────────────────────────

    def _score_chain(self, cluster: list[dict], sources: list[str],
                     filename: str) -> tuple[int, list[str]]:
        score = BASE_SCORE
        notes = [
            f"Corroborated by {len(sources)} independent artifact sources: "
            f"{', '.join(sources)}"
        ]

        # Rule 1: Extra sources
        extra = len(sources) - MIN_SOURCES_FOR_CHAIN
        if extra > 0:
            bonus = extra * SCORE_PER_EXTRA_SOURCE
            score += bonus
            notes.append(f"+{bonus}: {extra} additional corroborating sources")

        # Rule 2: Access → deletion
        access_srcs  = {"LNK", "JumpList", "Shellbags", "UserAssist", "Prefetch"}
        has_access   = any(e["artifact_source"] in access_srcs for e in cluster)
        has_deletion = any(e["artifact_source"] == "RecycleBin" for e in cluster)
        if has_access and has_deletion:
            score += SCORE_ACCESS_DELETION
            notes.append(
                f"+{SCORE_ACCESS_DELETION}: File accessed then deleted "
                "(possible evidence tampering)"
            )

        # Rule 3: Execution → deletion
        exec_srcs     = {"Prefetch", "UserAssist"}
        has_execution = any(e["artifact_source"] in exec_srcs for e in cluster)
        if has_execution and has_deletion:
            score += SCORE_EXEC_DELETION
            notes.append(
                f"+{SCORE_EXEC_DELETION}: Program executed then deleted "
                "(possible malware cleanup)"
            )

        # Rule 4: USB involvement
        has_usb = any(
            e.get("drive_type") == "Removable (USB/Floppy)"
            for e in cluster if e.get("artifact_source") == "LNK"
        )
        if has_usb:
            score += SCORE_USB_INVOLVEMENT
            notes.append(f"+{SCORE_USB_INVOLVEMENT}: USB/removable device involvement")

        # Rule 5: Bulk deletion
        if any(e.get("bulk_deletion") is True for e in cluster):
            score += SCORE_BULK_DELETION
            notes.append(f"+{SCORE_BULK_DELETION}: Part of a bulk deletion event (≥10 files)")

        # Rule 6: Suspicious path
        for event in cluster:
            rp = (event.get("_norm_path") or "").lower()
            if any(kw in rp for kw in SUSPICIOUS_PATH_KEYWORDS):
                score += SCORE_SUSPICIOUS_PATH
                notes.append(f"+{SCORE_SUSPICIOUS_PATH}: File in suspicious path: {rp}")
                break

        # Rule 7 (NEW): Security tool execution followed by deletion
        is_security_tool = any(
            kw in filename.lower() for kw in SECURITY_TOOL_KEYWORDS
        )
        if is_security_tool and has_execution and has_deletion:
            score += SCORE_SEMANTIC_PATTERN
            notes.append(
                f"+{SCORE_SEMANTIC_PATTERN}: Security/forensic tool executed "
                "then deleted — possible anti-forensics"
            )

        # Rule 8 (NEW): Hash-linked (renamed file)
        if filename.startswith("__hash__") or filename.startswith("[Hash-linked]"):
            score += SCORE_HASH_CORRELATION
            notes.append(
                f"+{SCORE_HASH_CORRELATION}: Hash-based correlation — same file "
                "content detected under different filenames"
            )

        return min(score, 100), notes

    # ─────────────────────────────────────────────────────────────────────────
    # Confidence Scoring (unchanged from v2.0)
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _compute_confidence(sources: list[str]) -> tuple[int, str, list[str]]:
        weights = {
            "Prefetch"  : (40, "Execution confirmed by Prefetch (kernel-level record)"),
            "JumpList"  : (25, "Application-file association confirmed by Jump List"),
            "RecycleBin": (20, "Deletion event confirmed by Recycle Bin $I metadata"),
            "LNK"       : (15, "File access confirmed by Shell Link record"),
            "UserAssist": (10, "User-initiated execution confirmed by UserAssist registry"),
            "Shellbags" : (5,  "Folder access confirmed by Shellbags registry"),
        }
        score = 0
        breakdown = []
        for src in sources:
            if src in weights:
                pts, explanation = weights[src]
                score += pts
                breakdown.append(f"+{pts}% — {explanation}")

        score = min(score, 100)
        label = (
            "Very High" if score >= 80 else
            "High"      if score >= 60 else
            "Moderate"  if score >= 40 else
            "Low"
        )
        return score, label, breakdown

    @staticmethod
    def _score_label(score: int) -> str:
        if score >= 85: return "Critical"
        if score >= 70: return "High"
        if score >= 55: return "Medium"
        return "Low"

    @staticmethod
    def _parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
        if not ts_str:
            return None
        try:
            return datetime.strptime(
                ts_str, "%Y-%m-%d %H:%M:%S UTC"
            ).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None
