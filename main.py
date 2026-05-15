"""
main.py
───────
Windows Forensic Triage Tool v2.1
Riphah International University — BS Cybersecurity | Digital Forensics Spring 2026

IMPORTANT — FORENSIC SOUNDNESS WARNING
═══════════════════════════════════════
Running this tool directly on a LIVE system is NOT forensically sound for
court-admissible evidence. Live analysis modifies:
  • File access timestamps (NTFS $MFT entries)
  • Registry LastWrite times (reg save HKEY_CURRENT_USER)
  • Page file, prefetch metadata, and event logs

For legally admissible investigations:
  1. Acquire a full disk image first (e.g. FTK Imager, dd, Guymager).
  2. Mount the image read-only.
  3. Run this tool in --offline mode pointing at the mount point:
       python main.py --offline E:\\MountedImage --output E:\\Output

The --live flag explicitly acknowledges this risk and proceeds anyway
(suitable for academic triage, IR first-response, or CTF scenarios).
"""

import os
import sys
import argparse
import textwrap
from datetime import datetime

from audit_logger             import ForensicAuditLogger
from forensic_utils           import ForensicPaths, get_platform_string
from prefetch_parser          import PrefetchParser
from lnk_parser               import LNKParser
from recycle_bin_parser       import RecycleBinParser
from jumplists_parser         import JumpListsParser
from shellbags_parser         import ShellbagsParser
from userassist_parser        import UserAssistParser
from correlator               import CorrelationEngine
from suspicious_exec_detector import SuspiciousExecutionDetector
from anomaly_detector         import AnomalyDetector
from timeline_visualizer      import TimelineVisualizer
from forensic_summary_writer  import ForensicSummaryWriter
from report_generator         import ReportGenerator


# ─────────────────────────────────────────────────────────────────────────────
# Registry Hive Export (live mode only)
# ─────────────────────────────────────────────────────────────────────────────

def export_ntuser_hive(username: str, output_dir: str, logger: ForensicAuditLogger):
    """
    Exports HKEY_CURRENT_USER to a temp .dat file using 'reg save'.

    ⚠ FORENSIC NOTE:
    'reg save' on a live system updates the hive's LastWrite timestamp,
    which technically modifies the evidence. For court-grade work, copy
    the raw hive files (NTUSER.DAT) from the mounted offline image instead.

    The offline path for NTUSER.DAT is:
        <image_root>\\Users\\<username>\\NTUSER.DAT

    Args:
        username   : Currently logged-in Windows username.
        output_dir : Where to write the exported .dat file.
        logger     : ForensicAuditLogger instance.

    Returns:
        Path to exported .dat file, or None on failure.
    """
    export_path = os.path.join(output_dir, f"NTUSER_{username}.dat")
    logger.log("[WARN] reg save modifies LastWrite time on live hive — see forensic note in main.py")
    ret = os.system(f'reg save "HKEY_CURRENT_USER" "{export_path}" /y')
    if ret != 0 or not os.path.exists(export_path):
        logger.log_error("Could not export NTUSER.DAT — Shellbags/UserAssist will be skipped.")
        print("      [WARNING] Could not export NTUSER.DAT — Shellbags/UserAssist skipped.")
        return None
    return export_path


def find_ntuser_offline(paths: ForensicPaths, username: str,
                        logger: ForensicAuditLogger) -> str | None:
    """
    Locates NTUSER.DAT directly on an offline (mounted) image without
    calling 'reg save'. This is the forensically sound approach.

    Searches:
      <root>/Users/<username>/NTUSER.DAT
      <root>/Users/*/NTUSER.DAT  (if username is unknown)

    Returns:
        Path to NTUSER.DAT, or None if not found.
    """
    # Direct path when username is known
    if username and username.lower() not in ("unknownuser", ""):
        candidate = os.path.join(paths.users_dir, username, "NTUSER.DAT")
        if os.path.isfile(candidate):
            logger.log(f"Found NTUSER.DAT (offline): {candidate}")
            return candidate

    # Fallback: scan all user dirs
    if os.path.isdir(paths.users_dir):
        for uname in os.listdir(paths.users_dir):
            candidate = os.path.join(paths.users_dir, uname, "NTUSER.DAT")
            if os.path.isfile(candidate):
                logger.log(f"Found NTUSER.DAT for user '{uname}': {candidate}")
                return candidate

    logger.log_error(f"NTUSER.DAT not found under: {paths.users_dir}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Live-System Warning Banner
# ─────────────────────────────────────────────────────────────────────────────

LIVE_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║          ⚠  FORENSIC SOUNDNESS WARNING — LIVE SYSTEM ANALYSIS  ⚠           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  You are running this tool DIRECTLY on a live Windows system.               ║
║                                                                              ║
║  This will:                                                                  ║
║    • Update NTFS last-access timestamps on every file read                  ║
║    • Modify registry LastWrite times (reg save HKEY_CURRENT_USER)           ║
║    • Alter Prefetch metadata by running Python                               ║
║                                                                              ║
║  For COURT-ADMISSIBLE evidence, you should:                                  ║
║    1. Acquire a forensic image (FTK Imager / dd / Guymager)                 ║
║    2. Mount it read-only                                                     ║
║    3. Re-run with:  python main.py --offline <mount_point>                  ║
║                                                                              ║
║  For academic triage / IR first-response, use --live to proceed.            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

OFFLINE_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ✅  OFFLINE (IMAGE) ANALYSIS MODE                        ║
║  All artifact paths are rooted at the provided image mount point.           ║
║  NTUSER.DAT will be read directly — no reg save will be executed.           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────────────────────────────────────
# Argument Parser
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="forensic_triage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Windows Forensic Triage Tool v2.1
            Riphah International University — BS Cybersecurity

            ACQUISITION MODES
            ─────────────────
            --live              Analyse the live running system (fast, but modifies evidence).
            --offline <PATH>    Analyse a mounted forensic image at <PATH> (recommended).

            EXAMPLES
            ────────
            Live triage (academic / IR):
              python main.py --live --output ./output

            Offline image analysis (forensically sound):
              python main.py --offline E:\\ --output E:\\output

            Offline with explicit paths:
              python main.py --offline E:\\ --prefetch E:\\Windows\\Prefetch \\
                             --users E:\\Users --recycle "E:\\$Recycle.Bin"
        """),
    )

    # ── Mode flags (mutually exclusive) ──────────────────────────────────────
    mode_grp = ap.add_mutually_exclusive_group(required=True)
    mode_grp.add_argument(
        "--live",
        action="store_true",
        help="Run on the live system. Acknowledges evidence modification risk."
    )
    mode_grp.add_argument(
        "--offline",
        metavar="IMAGE_ROOT",
        help="Root directory of a mounted forensic image (e.g. E:\\\\)."
    )

    # ── Optional path overrides ───────────────────────────────────────────────
    ap.add_argument("--output",   default="output",
                    help="Output directory for all reports (default: ./output)")
    ap.add_argument("--prefetch", default=None,
                    help="Override Prefetch directory path.")
    ap.add_argument("--users",    default=None,
                    help="Override Users directory path.")
    ap.add_argument("--recycle",  default=None,
                    help="Override $Recycle.Bin directory path.")
    ap.add_argument("--username", default=None,
                    help="Target username (used for UserAssist / Shellbags).")
    ap.add_argument(
        "--hive",
        default=None,
        metavar="HIVE_PATH",
        help=(
            "Direct path to an NTUSER.DAT / exported .dat file. "
            "Bypasses both reg save (live) and the offline NTUSER.DAT scan. "
            "Example: --hive D:\\df_project\\src\\output\\NTUSER_USER.dat"
        ),
    )
    ap.add_argument(
        "--usrclass",
        default=None,
        metavar="USRCLASS_PATH",
        help=(
            "Direct path to UsrClass.dat (Windows 10/11 shellbags hive). "
            "On Win10/11 shellbags live here, not in NTUSER.DAT. "
            "Export with: reg save HKCU\\Software\\Classes UsrClass.dat /y"
        ),
    )

    # ── Debug flag ────────────────────────────────────────────────────────────
    ap.add_argument(
        "--debug",
        action="store_true",
        help="Log full tracebacks on parser errors (verbose)."
    )

    # ── Correlation tuning ────────────────────────────────────────────────────
    ap.add_argument(
        "--time-window",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Correlation time window in seconds (default: 300 = 5 minutes)."
    )

    return ap


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap   = build_arg_parser()
    args = ap.parse_args()

    # ── Build ForensicPaths ───────────────────────────────────────────────────
    if args.live:
        paths = ForensicPaths.live(output_dir=args.output)
        print(LIVE_WARNING)
    else:
        paths = ForensicPaths.offline(image_root=args.offline, output_dir=args.output)
        print(OFFLINE_BANNER)

    # Apply any path overrides the user supplied
    if args.prefetch: paths.prefetch_dir = args.prefetch
    if args.users:    paths.users_dir    = args.users
    if args.recycle:  paths.recycle_dir  = args.recycle

    os.makedirs(paths.output_dir, exist_ok=True)

    # ── Initialise logger ─────────────────────────────────────────────────────
    logger = ForensicAuditLogger(output_dir=paths.output_dir)
    logger.log("=" * 70)
    logger.log("WINDOWS FORENSIC TRIAGE TOOL v2.1 — SESSION START")
    logger.log(f"Run timestamp    : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    logger.log(f"Operating system : {sys.platform}")
    logger.log(f"Python version   : {sys.version}")
    logger.log(f"Analysis mode    : {paths.mode.upper()}")
    logger.log(f"Debug mode       : {'ON' if args.debug else 'OFF'}")
    logger.log(f"Correlation win  : {args.time_window}s")
    logger.log("")
    logger.log("Configured paths:")
    logger.log(paths.summary())
    logger.log("=" * 70)

    if paths.mode == "live":
        logger.log("[WARN] LIVE system analysis — evidence timestamps may be altered")

    print("\n" + "=" * 60)
    print("  Windows Forensic Triage Tool  v2.1")
    print("  Riphah International University | BS Cybersecurity")
    print(f"  Mode : {paths.mode.upper()}")
    print("=" * 60)
    print(paths.summary())

    all_events: list[dict] = []
    username = args.username or os.environ.get("USERNAME", "UnknownUser")

    # ── Module 1 — Prefetch ───────────────────────────────────────────────────
    print("\n[1/6] Parsing Prefetch files...")
    prefetch_events = PrefetchParser(logger, debug=args.debug).parse_directory(
        paths.prefetch_dir
    )
    all_events.extend(prefetch_events)
    print(f"      → {len(prefetch_events)} execution records found")

    # ── Module 2 — LNK ───────────────────────────────────────────────────────
    print("\n[2/6] Parsing LNK shortcut files...")
    lnk_p      = LNKParser(logger, debug=args.debug)
    lnk_events = lnk_p.parse_recent_folder(paths.users_dir)
    usb_map    = lnk_p.build_usb_provenance_map(lnk_events)
    all_events.extend(lnk_events)
    print(f"      → {len(lnk_events)} file access records | {len(usb_map)} USB devices")

    # ── Module 3 — Recycle Bin ────────────────────────────────────────────────
    print("\n[3/6] Parsing Recycle Bin $I files...")
    recycle_events = RecycleBinParser(logger, debug=args.debug).parse_recycle_bin(
        paths.recycle_dir
    )
    all_events.extend(recycle_events)
    print(f"      → {len(recycle_events)} deletion records found")

    # ── Module 4 — Jump Lists ─────────────────────────────────────────────────
    print("\n[4/6] Parsing Jump Lists...")
    jl_events = JumpListsParser(logger, debug=args.debug).parse_jump_lists(paths.users_dir)
    all_events.extend(jl_events)
    print(f"      → {len(jl_events)} Jump List entries found")

    # ── Module 5 & 6 — Shellbags + UserAssist ────────────────────────────────
    print(f"\n[5/6] Locating NTUSER.DAT for user: {username}...")
    shellbag_events   = []
    userassist_events = []

    if paths.mode == "offline":
        # Forensically sound: read NTUSER.DAT directly from image
        hive_path = args.hive or find_ntuser_offline(paths, username, logger)
    else:
        # Live: reg save (modifies LastWrite — acknowledged by --live flag)
        hive_path = args.hive or export_ntuser_hive(username, paths.output_dir, logger)

    if hive_path:
        shellbag_events = ShellbagsParser(logger, debug=args.debug).parse_from_hive(
            hive_path, username,
            usrclass_path=getattr(args, "usrclass", None)
        )
        all_events.extend(shellbag_events)
        print(f"      → {len(shellbag_events)} Shellbag folder records")

        print("\n[6/6] Parsing UserAssist...")
        userassist_events = UserAssistParser(logger, debug=args.debug).parse_from_hive(
            hive_path, username
        )
        all_events.extend(userassist_events)
        print(f"      → {len(userassist_events)} application execution records")
    else:
        print("      [SKIPPED] NTUSER.DAT not available — Shellbags & UserAssist skipped")

    # ── Module 7 — Correlation Engine ────────────────────────────────────────
    print(f"\n[CORRELATOR] Correlating {len(all_events)} events...")
    chains = CorrelationEngine(logger, time_window=args.time_window).correlate(
        prefetch_events, lnk_events, recycle_events,
        jl_events, shellbag_events, userassist_events
    )
    crit_c = sum(1 for c in chains if c["significance_label"] == "Critical")
    high_c = sum(1 for c in chains if c["significance_label"] == "High")
    print(f"             → {len(chains)} chains | CRITICAL: {crit_c} | HIGH: {high_c}")

    # ── Module 8 — Suspicious Execution Detector ──────────────────────────────
    detector   = SuspiciousExecutionDetector(logger, debug=args.debug)
    sus_list   = detector.analyse(prefetch_events, userassist_events)
    sus_events = sus_list
    sus_stats  = {
        "HIGH":            sum(1 for f in sus_list if f["risk_level"] == "HIGH"),
        "MEDIUM":          sum(1 for f in sus_list if f["risk_level"] == "MEDIUM"),
        "LOW":             sum(1 for f in sus_list if f["risk_level"] == "LOW"),
        "total_scanned":   len(prefetch_events) + len(userassist_events),
    }
    print(
        f"             → {len(sus_events)} flagged "
        f"(HIGH:{sus_stats['HIGH']} MED:{sus_stats['MEDIUM']} LOW:{sus_stats['LOW']})"
    )

    # ── Module 9 — Anomaly Detector ───────────────────────────────────────────
    print("\n[ANOMALY DETECTOR] Detecting anomalies...")
    anomalies = AnomalyDetector(logger).detect(
        prefetch_events, userassist_events,
        recycle_events, lnk_events, jl_events
    )
    crit_a = sum(1 for a in anomalies if a["severity"] == "CRITICAL")
    high_a = sum(1 for a in anomalies if a["severity"] == "HIGH")
    print(f"             → {len(anomalies)} anomalies (CRITICAL:{crit_a} HIGH:{high_a})")

    # ── Module 10 — Timeline Visualizer ──────────────────────────────────────
    print("\n[REPORT] Generating all output files...")
    viz_path = TimelineVisualizer(logger, paths.output_dir).generate(all_events)

    # ── Module 11 — Forensic Summary ─────────────────────────────────────────
    summary_path = ForensicSummaryWriter(logger, paths.output_dir).write(
        all_events, chains, anomalies, sus_events, sus_stats, usb_map, username,
        mode=paths.mode,
    )

    # ── Module 12 — CSV + HTML Report ────────────────────────────────────────
    reporter  = ReportGenerator(logger, paths.output_dir)
    csv_path  = reporter.generate_csv(all_events)
    html_path = reporter.generate_html(
        all_events, chains, usb_map, sus_events, sus_stats, anomalies
    )

    logger.log(
        f"Run complete. Events:{len(all_events)} "
        f"Chains:{len(chains)} Anomalies:{len(anomalies)}"
    )

    # ── Final Summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  ✅  ACQUISITION & ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"\n  📄 CSV Timeline      : {csv_path}")
    print(f"  🌐 HTML Report       : {html_path}")
    print(f"  📊 Timeline Chart    : {viz_path}")
    print(f"  📋 Forensic Summary  : {summary_path}")
    print(f"  🔍 Audit Log         : {os.path.join(paths.output_dir, 'audit_log.txt')}")
    print(f"  🔐 Hash Log          : {os.path.join(paths.output_dir, 'hashes.txt')}")
    print(f"\n  Total events        : {len(all_events):,}")
    print(f"  Correlated chains   : {len(chains)}")
    print(f"  Anomalies detected  : {len(anomalies)} ({crit_a} CRITICAL, {high_a} HIGH)")
    print(f"  Suspicious execs    : {len(sus_events)}")
    if paths.mode == "live":
        print(
            "\n  ⚠️  LIVE MODE: Some timestamps may have been altered during analysis."
            "\n     Screenshots must show taskbar date/time."
            "\n     For court-admissible work, use --offline with a disk image.\n"
        )


if __name__ == "__main__":
    main()