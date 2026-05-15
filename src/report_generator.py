"""
report_generator.py
───────────────────
Generates CSV timeline and interactive HTML forensic report.

Changes from v2.0:
  • Version label updated to v2.1.
  • Added machine_name and mac_address columns to CSV output
    (new fields from updated lnk_parser TrackerDataBlock).
  • No other changes — this module had no issues from the improvement list.
"""

import os
import csv
import json
from datetime import datetime
from jinja2 import Template
from audit_logger import ForensicAuditLogger


SCORE_COLOURS = {
    "Critical": "#C00000",
    "High"    : "#FF6600",
    "Medium"  : "#FFC000",
    "Low"     : "#70AD47",
}


class ReportGenerator:

    def __init__(self, logger: ForensicAuditLogger, output_dir: str = "output"):
        self.logger     = logger
        self.output_dir = output_dir

    # ─────────────────────────────────────────────────────────────────────────
    # CSV Timeline
    # ─────────────────────────────────────────────────────────────────────────

    def generate_csv(self, all_events: list[dict]) -> str:
        csv_path = os.path.join(self.output_dir, "forensic_timeline.csv")

        fieldnames = [
            "artifact_source", "timestamp", "username", "file_or_app_path",
            "detail_1", "detail_2", "drive_type", "volume_serial",
            "machine_name", "mac_address",          # new in v2.1 (LNK TrackerDataBlock)
            "significance_flag", "source_file_md5", "source_file_sha256",
        ]

        rows = [self._flatten_for_csv(e) for e in all_events]
        rows.sort(key=lambda r: r.get("timestamp") or "9999-99-99")

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

        self.logger.log(f"CSV report written: {csv_path} ({len(rows)} events)")
        return csv_path

    # ─────────────────────────────────────────────────────────────────────────
    # HTML Report
    # ─────────────────────────────────────────────────────────────────────────

    def generate_html(self, all_events: list[dict], correlated_chains: list[dict],
                       usb_map: dict, suspicious_findings: list[dict] = None,
                       sus_stats: dict = None, anomalies: list[dict] = None) -> str:
        html_path = os.path.join(self.output_dir, "forensic_report.html")

        source_counts   = {}
        for e in all_events:
            src = e.get("artifact_source", "Unknown")
            source_counts[src] = source_counts.get(src, 0) + 1

        critical_chains = [c for c in correlated_chains if c["significance_label"] == "Critical"]
        high_chains     = [c for c in correlated_chains if c["significance_label"] == "High"]

        template = Template(HTML_TEMPLATE)
        html = template.render(
            generation_time     = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_events        = len(all_events),
            source_counts       = source_counts,
            total_chains        = len(correlated_chains),
            critical_count      = len(critical_chains),
            high_count          = len(high_chains),
            correlated_chains   = correlated_chains,
            usb_map             = usb_map,
            score_colours       = SCORE_COLOURS,
            all_events          = all_events[:500],
            suspicious_findings = (suspicious_findings or []),
            anomalies           = (anomalies or []),
        )

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        self.logger.log(f"HTML report written: {html_path}")
        return html_path

    # ─────────────────────────────────────────────────────────────────────────
    # Private: Flatten one event to CSV row
    # ─────────────────────────────────────────────────────────────────────────

    def _flatten_for_csv(self, event: dict) -> dict:
        source = event.get("artifact_source", "Unknown")

        row = {
            "artifact_source"   : source,
            "username"          : event.get("username", ""),
            "source_file_md5"   : event.get("md5", ""),
            "source_file_sha256": event.get("sha256", ""),
            "significance_flag" : "BULK_DELETION" if event.get("bulk_deletion") else "",
            "machine_name"      : event.get("machine_name", ""),
            "mac_address"       : event.get("mac_address", ""),
        }

        if source == "Prefetch":
            row["timestamp"]        = event.get("last_run_time", "")
            row["file_or_app_path"] = event.get("executable_name", "")
            row["detail_1"]         = f"Run count: {event.get('run_count', 0)}"
            row["detail_2"]         = f"Prefetch hash: {event.get('prefetch_hash', '')}"

        elif source == "LNK":
            row["timestamp"]        = event.get("target_accessed", "")
            row["file_or_app_path"] = event.get("target_path", "")
            row["detail_1"]         = f"Target modified: {event.get('target_modified', '')}"
            row["detail_2"]         = event.get("working_dir", "")
            row["drive_type"]       = event.get("drive_type", "")
            row["volume_serial"]    = event.get("volume_serial", "")

        elif source == "RecycleBin":
            row["timestamp"]        = event.get("deletion_time", "")
            row["file_or_app_path"] = event.get("original_path", "")
            row["detail_1"]         = f"Original size: {event.get('original_size', 0):,} bytes"
            row["detail_2"]         = f"User SID: {event.get('user_sid', '')}"

        elif source == "JumpList":
            row["timestamp"]        = event.get("last_accessed", "")
            row["file_or_app_path"] = event.get("accessed_file", "")
            row["detail_1"]         = f"Application: {event.get('application', '')}"
            row["detail_2"]         = f"Access count: {event.get('access_count', 0)}"

        elif source == "Shellbags":
            row["timestamp"]        = event.get("folder_modified", "")
            row["file_or_app_path"] = event.get("folder_path", "")
            row["detail_1"]         = f"Registry key: {event.get('registry_key', '')}"

        elif source == "UserAssist":
            row["timestamp"]        = event.get("last_run_time", "")
            row["file_or_app_path"] = event.get("application_path", "")
            row["detail_1"]         = f"Run count: {event.get('run_count', 0)}"
            row["detail_2"]         = f"GUID category: {event.get('guid_category', '')}"

        return row


# ─────────────────────────────────────────────────────────────────────────────
# HTML Report Template (Jinja2)
# ─────────────────────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Windows Forensic Triage Tool v2.1 — Forensic Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; }
  header { background: linear-gradient(135deg, #1F4E79, #2E75B6); padding: 30px 40px; }
  header h1 { font-size: 24px; color: white; margin-bottom: 6px; }
  header p  { color: #b0d0f0; font-size: 13px; }
  .container { max-width: 1400px; margin: 0 auto; padding: 30px 40px; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }
  .stat-card { background: #16213e; border-radius: 8px; padding: 20px; text-align: center; border-left: 4px solid #2E75B6; }
  .stat-card .number { font-size: 36px; font-weight: bold; color: #2E75B6; }
  .stat-card .label  { font-size: 13px; color: #aaa; margin-top: 4px; }
  .section-title { font-size: 18px; font-weight: bold; color: #2E75B6; margin: 30px 0 12px; border-bottom: 2px solid #2E75B6; padding-bottom: 6px; }
  .chain-card { background: #16213e; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
  .chain-header { padding: 14px 20px; display: flex; justify-content: space-between; align-items: center; }
  .chain-body { padding: 16px 20px; border-top: 1px solid #2a2a4e; }
  .badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; }
  .note { background: #0d1b2a; border-left: 3px solid #2E75B6; padding: 8px 12px; margin: 6px 0; font-size: 12px; color: #b0d0f0; }
  .event-row { font-size: 12px; background: #0d1b2a; padding: 8px 12px; margin: 4px 0; border-radius: 4px; display: flex; gap: 12px; }
  .source-tag { background: #2E75B6; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px; white-space: nowrap; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; margin: 12px 0; }
  th { background: #1F4E79; color: white; padding: 10px 12px; text-align: left; }
  td { padding: 8px 12px; border-bottom: 1px solid #2a2a4e; }
  tr:nth-child(even) td { background: #16213e; }
  .usb-card { background: #16213e; border-radius: 8px; padding: 16px 20px; margin-bottom: 12px; border-left: 4px solid #FF6600; }
  footer { text-align: center; padding: 20px; color: #666; font-size: 12px; margin-top: 40px; }
</style>
</head>
<body>
<header>
  <h1>🔍 Windows Forensic Triage Tool v2.1 — Investigation Report</h1>
  <p>Generated: {{ generation_time }} | Total Events: {{ total_events }} | Correlated Chains: {{ total_chains }}</p>
</header>
<div class="container">

  <div class="stats-grid">
    <div class="stat-card"><div class="number">{{ total_events }}</div><div class="label">Total Events Parsed</div></div>
    <div class="stat-card"><div class="number">{{ total_chains }}</div><div class="label">Correlated Chains</div></div>
    <div class="stat-card"><div class="number" style="color:#C00000">{{ critical_count }}</div><div class="label">Critical Chains</div></div>
    <div class="stat-card"><div class="number" style="color:#FF6600">{{ high_count }}</div><div class="label">High Priority Chains</div></div>
    {% for src, count in source_counts.items() %}
    <div class="stat-card"><div class="number">{{ count }}</div><div class="label">{{ src }} Events</div></div>
    {% endfor %}
  </div>

  {% if anomalies %}
  <div class="section-title">🔍 Anomaly Detection Results ({{ anomalies|length }} anomalies found)</div>
  {% for a in anomalies %}
  <div class="chain-card" style="border-left:4px solid {{ {'CRITICAL':'#C00000','HIGH':'#FF6600','MEDIUM':'#FFC000'}.get(a.severity,'#888') }}">
    <div class="chain-header">
      <div><strong>{{ a.anomaly_type }}</strong></div>
      <span class="badge" style="background:{{ {'CRITICAL':'#C00000','HIGH':'#FF6600','MEDIUM':'#FFC000'}.get(a.severity,'#888') }}">{{ a.severity }}</span>
    </div>
    <div class="chain-body">
      <div style="font-size:13px;margin-bottom:10px">{{ a.description }}</div>
      <div style="font-size:12px;color:#2E75B6;margin-top:8px"><strong>Recommendation:</strong> {{ a.recommendation }}</div>
    </div>
  </div>
  {% endfor %}
  {% endif %}

  {% if suspicious_findings %}
  <div class="section-title">⚠️ Suspicious Execution Risk Matrix ({{ suspicious_findings|length }} flagged)</div>
  <table>
    <tr><th>Risk</th><th>Source</th><th>Executable / App</th><th>Reason</th><th>Flagged Path</th><th>Last Executed</th></tr>
    {% for f in suspicious_findings %}
    <tr>
      <td><span class="badge" style="background:{{ {'HIGH':'#C00000','MEDIUM':'#FF6600','LOW':'#FFC000'}.get(f.risk_level,'#888') }}">{{ f.risk_level }}</span></td>
      <td><span class="source-tag">{{ f.source_artifact or '' }}</span></td>
      <td style="font-family:monospace;font-size:11px">{{ f.executable_name or '' }}</td>
      <td style="font-size:11px">{{ f.forensic_note or '' }}</td>
      <td style="font-family:monospace;font-size:10px">{{ (f.full_path or '')[:60] }}</td>
      <td style="font-size:11px">{{ f.timestamp or 'N/A' }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  <div class="section-title">⚠️ Correlated Event Chains (sorted by forensic significance)</div>
  {% for chain in correlated_chains %}
  <div class="chain-card">
    <div class="chain-header" style="background: {{ score_colours.get(chain.significance_label, '#333') }}22; border-left: 4px solid {{ score_colours.get(chain.significance_label, '#333') }}">
      <div>
        <strong>Chain #{{ chain.chain_id }} — {{ chain.filename }}</strong>
        <span style="color:#aaa; font-size:12px; margin-left:12px">{{ chain.first_event_time }} → {{ chain.last_event_time }}</span>
        <span style="color:#aaa; font-size:12px; margin-left:8px">| Window: {{ chain.time_window or 'N/A' }}</span>
      </div>
      <div style="text-align:right">
        <span class="badge" style="background:{{ score_colours.get(chain.significance_label, '#333') }}">
          {{ chain.significance_label }} ({{ chain.significance_score }}/100)
        </span>
        <span class="badge" style="background:#1F4E79;margin-left:6px">
          Confidence: {{ chain.confidence_score }}% {{ chain.confidence_label }}
        </span>
      </div>
    </div>
    <div class="chain-body">
      <div style="margin-bottom:10px">
        {% for src in chain.sources %}<span class="source-tag" style="margin-right:4px">{{ src }}</span>{% endfor %}
      </div>
      {% if chain.confidence_breakdown %}
      <div style="font-size:12px;color:#70AD47;margin-bottom:8px">
        <strong>Confidence Breakdown:</strong>
        {% for cb in chain.confidence_breakdown %}<div style="margin-left:12px">• {{ cb }}</div>{% endfor %}
      </div>
      {% endif %}
      {% for note in chain.forensic_notes %}<div class="note">{{ note }}</div>{% endfor %}
      <div style="margin-top:12px; font-size:12px; color:#aaa">Events in this chain:</div>
      {% for event in chain.events %}
      <div class="event-row">
        <span class="source-tag">{{ event.artifact_source }}</span>
        <span>{{ event.get('_timestamp_str', 'N/A') }}</span>
        <span style="color:#aaa">{{ event.get('_raw_path', '') }}</span>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endfor %}

  {% if usb_map %}
  <div class="section-title">🔌 USB Provenance Map</div>
  {% for serial, files in usb_map.items() %}
  <div class="usb-card">
    <strong>Volume Serial: {{ serial }}</strong> — {{ files|length }} files accessed
    <table style="margin-top:10px">
      <tr><th>File Path</th><th>Last Accessed</th><th>Username</th><th>Machine</th><th>MAC Address</th></tr>
      {% for f in files %}
      <tr>
        <td>{{ f.file_path }}</td>
        <td>{{ f.last_accessed }}</td>
        <td>{{ f.username }}</td>
        <td>{{ f.machine_name or '—' }}</td>
        <td style="font-family:monospace">{{ f.mac_address or '—' }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endfor %}
  {% endif %}

  <div class="section-title">📋 Full Event Timeline (first 500 events)</div>
  <table>
    <tr><th>Source</th><th>Timestamp</th><th>Username</th><th>File / Application</th><th>Detail</th></tr>
    {% for event in all_events %}
    <tr>
      <td><span class="source-tag">{{ event.artifact_source }}</span></td>
      <td>{{ event.get('last_run_time') or event.get('target_accessed') or event.get('deletion_time') or event.get('last_accessed') or event.get('folder_modified') or 'N/A' }}</td>
      <td>{{ event.get('username', '') }}</td>
      <td style="font-family:monospace; font-size:11px">{{ event.get('executable_name') or event.get('target_path') or event.get('original_path') or event.get('accessed_file') or event.get('folder_path') or event.get('application_path') or '' }}</td>
      <td>{{ event.get('run_count', '') or event.get('drive_type', '') or event.get('application', '') }}</td>
    </tr>
    {% endfor %}
  </table>

</div>
<footer>Windows Forensic Triage Tool v2.1 | Riphah International University | BS Cybersecurity Spring 2026 | Generated {{ generation_time }}</footer>
</body>
</html>"""
