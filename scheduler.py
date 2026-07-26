"""
scheduler.py -- Scheduled scan / auto-clean via launchd
Generates and manages LaunchAgent plists for periodic scans.
"""
import plistlib
import subprocess
from pathlib import Path
from datetime import datetime

LAUNCH_AGENT_LABEL = "com.cleanmymac-free.scheduler"
LAUNCH_AGENT_PLIST = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"

# Intervals supported: keys map to (calendar interval dict, human label)
INTERVALS = {
    "daily": {"interval": 1, "unit": "Day", "label": "Daily"},
    "weekly": {"interval": 1, "unit": "Week", "label": "Weekly"},
    "monthly": {"interval": 1, "unit": "Month", "label": "Monthly"},
}


def get_schedule() -> dict:
    """Check if a schedule is currently installed. Returns info dict."""
    if not LAUNCH_AGENT_PLIST.exists():
        return {"installed": False}
    try:
        with open(LAUNCH_AGENT_PLIST, "rb") as f:
            pl = plistlib.load(f)
        start_cal = pl.get("StartCalendarInterval", {})
        interval = start_cal.get("interval", "?")
        unit = start_cal.get("unit", "?")
        # Find matching preset
        schedule_key = None
        for key, val in INTERVALS.items():
            if val["interval"] == interval and val["unit"] == unit:
                schedule_key = key
                break
        return {
            "installed": True,
            "schedule": schedule_key,
            "label": INTERVALS.get(schedule_key, {}).get("label", "Custom"),
            "plist_path": str(LAUNCH_AGENT_PLIST),
            "program": pl.get("ProgramArguments", []),
        }
    except Exception:
        return {"installed": False, "error": "Could not read plist"}


def create_schedule(interval_key: str) -> tuple[bool, str]:
    """Create a launchd schedule. Returns (success, message)."""
    if interval_key not in INTERVALS:
        return False, f"Unknown interval: {interval_key}"

    interval_info = INTERVALS[interval_key]
    python_path = subprocess.run(["which", "python3"], capture_output=True, text=True).stdout.strip()
    if not python_path:
        python_path = "/usr/bin/python3"

    main_script = str(Path(__file__).parent / "main.py")
    plist_data = {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [python_path, main_script, "--headless", "--clean-system-junk"],
        "StartCalendarInterval": {"interval": interval_info["interval"], "unit": interval_info["unit"]},
        "StandardOutPath": str(Path.home() / ".cleanmymac-free-schedule.log"),
        "StandardErrorPath": str(Path.home() / ".cleanmymac-free-schedule.log"),
        "RunAtLoad": False,
    }

    try:
        # Ensure LaunchAgents dir exists
        LAUNCH_AGENT_PLIST.parent.mkdir(parents=True, exist_ok=True)
        with open(LAUNCH_AGENT_PLIST, "wb") as f:
            plistlib.dump(plist_data, f)
        # Load the agent
        result = subprocess.run(
            ["launchctl", "load", str(LAUNCH_AGENT_PLIST)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            # Already loaded — try unload then load
            subprocess.run(["launchctl", "unload", str(LAUNCH_AGENT_PLIST)],
                           capture_output=True, text=True)
            result = subprocess.run(
                ["launchctl", "load", str(LAUNCH_AGENT_PLIST)],
                capture_output=True, text=True
            )
        if result.returncode == 0:
            return True, f"Schedule created: {interval_info['label']} scan."
        return False, f"Failed to load schedule: {result.stderr}"
    except OSError as e:
        return False, f"Failed to create schedule: {e}"


def remove_schedule() -> tuple[bool, str]:
    """Remove the launchd schedule. Returns (success, message).
    SAFETY: Checks _is_protected() before unlink — the rule on unlink
    protection has no exceptions, even for app-managed plist paths."""
    if not LAUNCH_AGENT_PLIST.exists():
        return True, "No schedule to remove."
    # SAFETY: never unlink a protected path (rule applies to all unlink calls)
    from scanners import _is_protected
    if _is_protected(LAUNCH_AGENT_PLIST):
        return False, f"Refused: {LAUNCH_AGENT_PLIST} is protected"
    try:
        subprocess.run(["launchctl", "unload", str(LAUNCH_AGENT_PLIST)],
                       capture_output=True, text=True)
        LAUNCH_AGENT_PLIST.unlink()
        return True, "Schedule removed."
    except OSError as e:
        return False, f"Failed to remove schedule: {e}"