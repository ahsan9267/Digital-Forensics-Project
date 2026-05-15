"""
timeline_visualizer.py
──────────────────────
Generates an interactive HTML timeline visualization.

Changes from v2.0:
  • Version label updated to v2.1.
  • No other changes — this module had no issues from the improvement list.
"""

import os
import json
from collections import defaultdict
from audit_logger import ForensicAuditLogger

SOURCE_COLOURS = {
    "Prefetch"  : "#2E75B6",
    "LNK"       : "#70AD47",
    "RecycleBin": "#C00000",
    "JumpList"  : "#FFC000",
    "Shellbags" : "#9B59B6",
    "UserAssist": "#FF6600",
}


class TimelineVisualizer:

    def __init__(self, logger: ForensicAuditLogger, output_dir: str = "output"):
        self.logger     = logger
        self.output_dir = output_dir

    def generate(self, all_events: list[dict]) -> str:
        self.logger.log("Generating interactive timeline visualization")

        monthly         = defaultdict(lambda: defaultdict(int))
        total_by_source = defaultdict(int)

        for event in all_events:
            source = event.get("artifact_source", "Unknown")
            ts     = self._get_ts(event)
            if ts and len(ts) >= 7:
                monthly[ts[:7]][source] += 1
                total_by_source[source] += 1

        all_months  = sorted(monthly.keys())
        all_sources = [s for s in SOURCE_COLOURS if total_by_source[s] > 0]

        datasets = [{
            "label"          : src,
            "data"           : [monthly[m].get(src, 0) for m in all_months],
            "backgroundColor": SOURCE_COLOURS[src],
            "borderColor"    : SOURCE_COLOURS[src],
            "borderWidth"    : 1,
        } for src in all_sources]

        # Top deleted files by size
        deleted = sorted(
            [
                {
                    "name": os.path.basename(
                        e.get("original_path", "")
                    ).rstrip("\x00"),
                    "size": e.get("original_size", 0),
                    "time": e.get("deletion_time", ""),
                }
                for e in all_events
                if e.get("artifact_source") == "RecycleBin"
                and os.path.basename(
                    e.get("original_path", "")
                ).rstrip("\x00")
            ],
            key=lambda x: x["size"],
            reverse=True,
        )[:10]

        # Top executed by run count
        execs = sorted(
            [
                {
                    "name" : e.get("executable_name", ""),
                    "count": e.get("run_count", 0),
                    "last" : e.get("last_run_time", ""),
                }
                for e in all_events
                if e.get("artifact_source") == "Prefetch"
            ],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

        out_path = os.path.join(self.output_dir, "timeline_visual.html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(
                self._html(all_months, datasets, deleted, execs,
                           total_by_source, len(all_events))
            )
        self.logger.log(f"Timeline visualization written: {out_path}")
        return out_path

    def _get_ts(self, e: dict) -> str:
        return (
            e.get("last_run_time")
            or e.get("target_accessed")
            or e.get("deletion_time")
            or e.get("last_accessed")
            or e.get("folder_modified")
            or ""
        )

    def _html(self, months, datasets, deleted, execs, totals, grand_total) -> str:
        del_rows  = "".join(
            f"<tr><td>{d['name']}</td><td>{d['size']:,}</td><td>{d['time']}</td></tr>"
            for d in deleted
        )
        exec_rows = "".join(
            f"<tr><td>{e['name']}</td><td>{e['count']}</td><td>{e['last']}</td></tr>"
            for e in execs
        )
        src_rows = "".join(
            f"<tr><td>"
            f"<span style='display:inline-block;width:10px;height:10px;"
            f"background:{SOURCE_COLOURS.get(s, '#888')};"
            f"margin-right:6px;border-radius:2px'></span>{s}</td>"
            f"<td>{c:,}</td><td>{c/grand_total*100:.1f}%</td></tr>"
            for s, c in totals.items() if c > 0
        )
        stat_cards = "".join(
            "<div class='stat'><div class='n' style='color:" + SOURCE_COLOURS.get(s, '#888') + "'>" +
            str(c) + "</div><div class='l'>" + s + "</div></div>"
            for s, c in totals.items() if c > 0
        )

        chart_json = json.dumps({"labels": months, "datasets": datasets})
        pie_json   = json.dumps({
            "labels": [s for s in totals if totals[s] > 0],
            "data"  : [totals[s] for s in totals if totals[s] > 0],
            "colors": [SOURCE_COLOURS.get(s, "#888") for s in totals if totals[s] > 0],
        })

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Forensic Timeline Visualization</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#1a1a2e;color:#e0e0e0}}
header{{background:linear-gradient(135deg,#1F4E79,#2E75B6);padding:28px 40px}}
header h1{{font-size:22px;color:white}} header p{{color:#b0d0f0;font-size:13px;margin-top:4px}}
.container{{max-width:1400px;margin:0 auto;padding:28px 40px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px}}
.stat{{background:#16213e;border-radius:8px;padding:18px;text-align:center;border-left:4px solid #2E75B6}}
.stat .n{{font-size:30px;font-weight:bold}} .stat .l{{font-size:12px;color:#aaa;margin-top:4px}}
.card{{background:#16213e;border-radius:8px;padding:20px;margin-bottom:20px}}
.card h3{{font-size:15px;color:#2E75B6;margin-bottom:14px;border-bottom:1px solid #2a2a4e;padding-bottom:8px}}
.grid2{{display:grid;grid-template-columns:2fr 1fr;gap:20px;margin-bottom:20px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#1F4E79;color:white;padding:8px 10px;text-align:left}}
td{{padding:7px 10px;border-bottom:1px solid #2a2a4e}}
tr:nth-child(even) td{{background:#0d1b2a}}
footer{{text-align:center;color:#555;font-size:11px;padding:20px}}
</style></head><body>
<header>
  <h1>📊 Windows Forensic Triage Tool v2.1 — Interactive Timeline Visualization</h1>
  <p>Total Events: {grand_total:,} &nbsp;|&nbsp; Windows Forensic Triage Tool v2.1 &nbsp;|&nbsp; Riphah International University</p>
</header>
<div class="container">
  <div class="stats">{stat_cards}
    <div class="stat"><div class="n">{grand_total:,}</div><div class="l">Total Events</div></div>
  </div>
  <div class="card">
    <h3>📅 Monthly Forensic Activity — Events by Artifact Source (Stacked Bar Chart)</h3>
    <canvas id="barChart" height="75"></canvas>
  </div>
  <div class="grid2">
    <div class="card">
      <h3>🗑️ Top Deleted Files by Size (Recycle Bin)</h3>
      <table><tr><th>Filename</th><th>Size (bytes)</th><th>Deletion Time</th></tr>{del_rows}</table>
    </div>
    <div class="card">
      <h3>🥧 Event Distribution by Source</h3>
      <canvas id="pieChart" height="180"></canvas>
      <table style="margin-top:10px"><tr><th>Source</th><th>Count</th><th>%</th></tr>{src_rows}</table>
    </div>
  </div>
  <div class="card">
    <h3>⚡ Top Executed Programs by Run Count (Prefetch)</h3>
    <table><tr><th>Executable</th><th>Run Count</th><th>Last Executed (UTC)</th></tr>{exec_rows}</table>
  </div>
</div>
<footer>Windows Forensic Triage Tool v2.1 | Riphah International University | BS Cybersecurity Spring 2026</footer>
<script>
const cd={chart_json};
const pd={pie_json};
new Chart(document.getElementById('barChart'),{{type:'bar',data:cd,options:{{responsive:true,
  plugins:{{legend:{{labels:{{color:'#e0e0e0',font:{{size:11}}}}}}}},
  scales:{{x:{{stacked:true,ticks:{{color:'#aaa'}},grid:{{color:'#2a2a4e'}}}},
           y:{{stacked:true,ticks:{{color:'#aaa'}},grid:{{color:'#2a2a4e'}}}}}}
}}}});
new Chart(document.getElementById('pieChart'),{{type:'doughnut',
  data:{{labels:pd.labels,datasets:[{{data:pd.data,backgroundColor:pd.colors,borderWidth:0}}]}},
  options:{{responsive:true,plugins:{{legend:{{display:false}}}}}}
}});
</script></body></html>"""