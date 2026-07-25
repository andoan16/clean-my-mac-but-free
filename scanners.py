"""
scanners.py -- all scan/clean engines
Reverse-engineered from CleanMyMac 5.5.7 framework analysis.

Modules match the original's Framework structure:
  SystemJunkScanning, MailJunkScanning, TrashJunkScanning,
  DownloadsScanning, UnusedDiskImagesScanning,
  PrivacyScanning, MalwareScanning,
  PerformanceScanning, UninstallerScanning, UpdaterScanning,
  SpaceLensScanning, OrganizeScanning (LAOF + Duplicates + SimilarImages),
  Shredder, CloudStorageScanning
"""
import os
import glob
import shutil
import time
import hashlib
import struct
import plistlib
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from utils import expand, file_size, human_size, safe_remove, file_hash, run_shell, run_sudo, file_age_days, dir_walk

# ──────────────────────────────────────────────────────────────
#  Data models
# ──────────────────────────────────────────────────────────────

@dataclass
class ScanItem:
    """One junk/malware/file entry found during scan."""
    path: str
    size: int = 0
    category: str = ""
    detail: str = ""
    selected: bool = True
    removable: bool = True

@dataclass
class ScanResult:
    """Collection of items from one scanner."""
    module: str
    items: list[ScanItem] = field(default_factory=list)
    total_size: int = 0
    metadata: dict = field(default_factory=dict)

    def add(self, item: ScanItem):
        self.items.append(item)
        self.total_size += item.size

# ──────────────────────────────────────────────────────────────
#  1. System Junk  (SystemJunkScanning.framework)
# ──────────────────────────────────────────────────────────────

# Cache locations — safe to clean CONTENTS (not the dirs themselves).
# Each entry: (path, removable) — removable=False means info-only display.
# IMPORTANT: Only cache/log directories belong here. App data dirs (WeChat,
# Telegram, etc.) and user dirs (~/Downloads) must NEVER be here.
SYSTEM_JUNK_PATHS = {
    "User Cache": ("~/Library/Caches", True),
    "System Cache": ("/Library/Caches", False),  # system path — info only
    "User Logs": ("~/Library/Logs", True),
    "System Logs": ("/Library/Logs", False),  # system path — info only
    "System Migration": ("/Library/SystemMigration/History", False),
    "Adobe Media Cache": ("~/Library/Application Support/Adobe/Common/Media Cache Files", True),
    "Spotify Cache": ("~/Library/Application Support/Spotify/PersistentCache/Storage", True),
    "Photos Cache": ("~/Library/Containers/com.apple.Photos/Data/Library/Caches", False),  # inside Containers — protected, info only
    "Xcode DerivedData": ("~/Library/Developer/Xcode/DerivedData", True),
    "Xcode Archives": ("~/Library/Developer/Xcode/Archives", False),  # user archives — info only
    "Xcode iOS Device Support": ("~/Library/Developer/Xcode/iOS DeviceSupport", True),
    "Xcode CoreSimulator": ("~/Library/Developer/CoreSimulator/Caches", True),
    "Xcode Device Logs": ("~/Library/Developer/Xcode/iOS Device Logs", True),
}

def scan_system_junk() -> ScanResult:
    """Scan all system junk cache/log locations."""
    result = ScanResult(module="System Junk")
    for category, (path_str, removable) in SYSTEM_JUNK_PATHS.items():
        p = expand(path_str)
        if not p.exists():
            continue
        if p.is_file():
            sz = file_size(p)
            if sz > 0:
                result.add(ScanItem(path=str(p), size=sz, category=category,
                                    detail=category, removable=removable))
        elif p.is_dir():
            sz = file_size(p)
            if sz > 1024:  # skip tiny
                result.add(ScanItem(path=str(p), size=sz, category=category,
                                    detail=f"{category} ({human_size(sz)})",
                                    removable=removable))
    # Unused disk images in Downloads
    downloads = expand("~/Downloads")
    if downloads.exists():
        for dmg in downloads.glob("*.dmg"):
            try:
                sz = dmg.stat().st_size
                if sz > 0:
                    result.add(ScanItem(path=str(dmg), size=sz, category="Disk Image",
                                        detail=f"Unused DMG: {dmg.name}", removable=False))
            except OSError:
                pass
        for iso in downloads.glob("*.iso"):
            try:
                sz = iso.stat().st_size
                if sz > 0:
                    result.add(ScanItem(path=str(iso), size=sz, category="Disk Image",
                                        detail=f"Unused ISO: {iso.name}", removable=False))
            except OSError:
                pass
    # Broken login items
    launch_agents = expand("~/Library/LaunchAgents")
    if launch_agents.exists():
        for plist_path in launch_agents.glob("*.plist"):
            try:
                with open(plist_path, "rb") as f:
                    plistlib.load(f)
            except Exception:
                result.add(ScanItem(path=str(plist_path), size=plist_path.stat().st_size,
                                    category="Broken Login Item",
                                    detail=f"Corrupt: {plist_path.name}",
                                    removable=False))  # info-only — user decides
    return result

# ──────────────────────────────────────────────────────────────
#  2. Mail Attachments  (MailJunkScanning.framework)
# ──────────────────────────────────────────────────────────────

def scan_mail_attachments() -> ScanResult:
    """Scan for downloaded Mail attachments (local copies only).
    Info-only — user should clean via Mail app to avoid data loss."""
    result = ScanResult(module="Mail Attachments")
    mail_paths = [
        "~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads",
        "~/Library/Containers/com.apple.mail/Data/Library/Attachments",
        "~/Library/Mail Downloads",
    ]
    for mp in mail_paths:
        p = expand(mp)
        if p.exists():
            sz = file_size(p)
            if sz > 0:
                result.add(ScanItem(path=str(p), size=sz, category="Mail Attachments",
                                    detail=f"Mail downloads ({human_size(sz)})",
                                    removable=False))  # info-only — don't rmtree mail containers
    return result

# ──────────────────────────────────────────────────────────────
#  3. Trash Bins  (TrashJunkScanning.framework)
# ──────────────────────────────────────────────────────────────

def scan_trash_bins() -> ScanResult:
    """Scan all trash locations: user trash, Mail trash, Photos trash, iCloud trash.
    Trash bins are emptied (contents deleted), the trash folder itself is preserved."""
    result = ScanResult(module="Trash Bins")
    trash_paths = [
        ("User Trash", "~/.Trash", True),
        ("iCloud Trash", "~/Library/Mobile Documents/com~apple~CloudDocs/.Trash", True),
        ("Mail Trash", "~/Library/Containers/com.apple.mail/Data/Library/Mail/V10/MailData/Trash", False),
        # Photos trash is a directory inside the Photos library, NOT Photos.sqlite
        ("Photos Trash", "~/Library/Containers/com.apple.Photos/Data/Library/Photos", False),
    ]
    for name, tp, removable in trash_paths:
        p = expand(tp)
        if p.exists():
            sz = file_size(p) if p.is_dir() else (p.stat().st_size if p.is_file() else 0)
            if sz > 0:
                result.add(ScanItem(path=str(p), size=sz, category=name,
                                    detail=f"{name} ({human_size(sz)})",
                                    removable=removable))
    return result

# ──────────────────────────────────────────────────────────────
#  4. Downloads  (DownloadsScanning.framework)
#  Covers Safari, Chrome, Slack download history
# ──────────────────────────────────────────────────────────────

def scan_downloads() -> ScanResult:
    """Scan browser download folders."""
    result = ScanResult(module="Downloads")
    dl_paths = [
        ("Safari Downloads", "~/Downloads"),
        ("Chrome Downloads", "~/Downloads"),
        ("Slack Downloads", "~/Downloads/Slack"),
    ]
    seen = set()
    for name, dp in dl_paths:
        p = expand(dp)
        if p.exists() and str(p) not in seen:
            seen.add(str(p))
            for f in p.iterdir():
                if f.is_file() and not f.name.startswith("."):
                    try:
                        sz = f.stat().st_size
                        age = file_age_days(f)
                        if sz > 1_000_000:  # > 1MB
                            # SAFETY: ~/Downloads is user data — do not mark as
                            # removable junk. User must explicitly choose to delete.
                            result.add(ScanItem(path=str(f), size=sz, category=name,
                                detail=f"{f.name} ({human_size(sz)}, {age}d old)",
                                removable=False, selected=False))
                    except OSError:
                        pass
    return result

# ──────────────────────────────────────────────────────────────
#  5. Unused Disk Images  (UnusedDiskImagesScanning.framework)
# ──────────────────────────────────────────────────────────────

def scan_unused_disk_images() -> ScanResult:
    """Find .dmg/.iso/.img files that are not currently mounted."""
    result = ScanResult(module="Unused Disk Images")
    # Check which DMGs are currently mounted — don't list mounted images as unused
    mounted_images = set()
    code, out = run_shell(["hdiutil", "info"])
    if code == 0:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("/") and (line.endswith(".dmg") or line.endswith(".iso")
                                          or line.endswith(".img") or line.endswith(".sparseimage")):
                mounted_images.add(line)
    search_dirs = ["~/Downloads", "~/Desktop", "~/Documents"]
    for sd in search_dirs:
        p = expand(sd)
        if not p.exists():
            continue
        for ext in ["*.dmg", "*.iso", "*.img", "*.smi", "*.sparseimage"]:
            for f in p.rglob(ext):
                try:
                    # Skip mounted DMGs — they are in use
                    if str(f) in mounted_images:
                        continue
                    sz = f.stat().st_size
                    if sz > 0:
                        result.add(ScanItem(path=str(f), size=sz, category="Disk Image", detail=f"{f.name} ({human_size(sz)})", removable=False))
                except OSError:
                    pass
    return result

# ──────────────────────────────────────────────────────────────
#  6. Privacy  (PrivacyScanning.framework)
#  Browser history, cookies, sessions, recent items, app permissions
# ──────────────────────────────────────────────────────────────

PRIVACY_PATHS = {
    "Safari History": "~/Library/Safari/History.db",
    "Safari Cookies": "~/Library/Cookies/Cookies.binarycookies",
    "Safari Downloads": "~/Library/Safari/Downloads.plist",
    "Safari Top Sites": "~/Library/Safari/TopSites.plist",
    "Safari Last Session": "~/Library/Safari/LastSession.plist",
    "Chrome History": "~/Library/Application Support/Google/Chrome/Default/History",
    "Chrome Cookies": "~/Library/Application Support/Google/Chrome/Default/Cookies",
    "Chrome Cache": "~/Library/Caches/Google/Chrome/Default/Cache",
    "Firefox History": "~/Library/Application Support/Firefox/Profiles/*/places.sqlite",
    "Firefox Cookies": "~/Library/Application Support/Firefox/Profiles/*/cookies.sqlite",
    "Firefox Cache": "~/Library/Caches/Firefox/Profiles/*/cache2",
    "Recent Items": "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments",
    "Finder Recent": "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments",
}

def scan_privacy() -> ScanResult:
    """Scan for privacy traces: browser data + recent items."""
    result = ScanResult(module="Privacy")
    for name, pattern in PRIVACY_PATHS.items():
        # Handle glob patterns — expand() calls .resolve() which treats * as
        # a literal character, so we split at the first * segment and glob
        # from the parent that exists.
        if "*" in pattern:
            # Split pattern into the non-glob prefix and the glob suffix
            parts = pattern.split("*", 1)
            prefix = parts[0]  # e.g. ~/Library/Application Support/Firefox/Profiles/
            suffix = "*" + parts[1]  # e.g. */places.sqlite
            # Expand the prefix (everything before the first *)
            prefix_path = expand(prefix.rstrip("/"))
            if prefix_path.exists() and prefix_path.is_dir():
                # Glob the remaining pattern from the prefix parent
                # Use the original pattern relative to the prefix
                glob_pattern = Path(suffix).as_posix()
                # Walk: glob from prefix_path using the suffix pattern
                # suffix starts with * — glob the full remaining path
                remaining = suffix.lstrip("/")
                for m in prefix_path.glob(remaining):
                    if m.exists():
                        sz = file_size(m)
                        result.add(ScanItem(path=str(m), size=sz, category=name, detail=name))
            continue
        # Non-glob pattern — direct match
        expanded = expand(pattern)
        if expanded.exists():
            sz = file_size(expanded)
            result.add(ScanItem(path=str(expanded), size=sz, category=name, detail=name))
    # Recent items lists
    recent_paths = [
        ("Recent Apps", "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentApplications"),
        ("Recent Docs", "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments"),
        ("Recent Servers", "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentServers"),
    ]
    for name, rp in recent_paths:
        p = expand(rp)
        if p.exists():
            result.add(ScanItem(path=str(p), size=file_size(p), category="Recent Items", detail=name))
    return result

# ──────────────────────────────────────────────────────────────
#  7. Malware Scan  (MalwareScanning + PANEngine + MalwareRulesRoutines)
#  Rule-based detection: launch agents, login items, browser extensions,
#  configuration profiles, YARA-style hash matching
# ──────────────────────────────────────────────────────────────

# Known malware/adware bundle IDs and paths (from public macOS adware databases)
KNOWN_ADWARE_BUNDLE_IDS = {
    "com.genieo.GenieoEngine", "com.genieo.completemac",
    "com.installermac.InstallerMac", "com.mackeeper.MacKeeper",
    "com.techyawn.MacHub", "com.downloadaction.DownloadActionNet",
    "com.vsearch.Helper", "com.vsearch.agent", "com.vsearch.daemon",
    "com.conduit.MyBrand", "com.conduit.helper",
    "com.crossrider....", "com.shockwave....",
    "com.spigot....", "search.spigot....",
    "com.browsefox....", "com.savingsbull....",
    "com.dealply....", "com.superfish....",
    "com.yontoo....", "com.offerbox....",
    "com.level1network....", "com.betterbrain....",
    "com.mywebsearch....", "com.pcvark....",
    "com.maware....", "com.syssecure....",
    "com.fasttrack....", "com.searchfusion....",
    "com.bingsearch....", "com.macsearch....",
    "comTrovi....", "com.Trovi....",
    "com.Cinema-Plus...", "cinema-plus...",
    "com.zebromac...", "com.zebroMac...",
}

KNOWN_ADWARE_PATHS = [
    "~/Library/Application Support/Genieo",
    "~/Library/Application Support/com.genieo",
    "~/Library/LaunchAgents/com.genieo.GenieoEngine.plist",
    "~/Library/LaunchAgents/com.vsearch.agent.plist",
    "~/Library/LaunchAgents/com.vsearch.helper.plist",
    "~/Library/LaunchAgents/com.vsearch.daemon.plist",
    "~/Library/Application Support/VSearch",
    "/Library/LaunchDaemons/com.conduit.loader.daemon.plist",
    "~/Library/Application Support/com.conduit",
    "~/Library/Application Support/com.mackeeper.MacKeeper",
    "/Applications/MacKeeper.app",
    "~/Library/Application Support/MacKeeper",
    "/Library/LaunchDaemons/com.mackeeper.MacKeeper.app.plist",
    "~/Library/Application Support/com.installermac",
    "~/Library/LaunchAgents/com.installermac.InstallerMac.plist",
    "~/Library/Application Support/Spigot",
    "~/Library/Application Support/com.spigot",
    "~/Library/Internet Plug-Ins/ConduitNPAPIPlugin.plugin",
    "~/Library/Application Support/SafariExtensions/PFastSearch.safariextz",
]

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def scan_malware() -> ScanResult:
    """Rule-based malware/adware scan."""
    result = ScanResult(module="Malware")

    # 1. Known adware bundle IDs in LaunchAgents/LaunchDaemons
    for launch_dir in ["~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"]:
        d = expand(launch_dir)
        if not d.exists():
            continue
        for plist in d.glob("*.plist"):
            name = plist.stem
            for bad in KNOWN_ADWARE_BUNDLE_IDS:
                if bad.rstrip(".") in name or name in bad:
                    result.add(ScanItem(path=str(plist), size=plist.stat().st_size, category="Adware LaunchAgent", detail=f"Known adware: {name}"))
                    break

    # 2. Known adware file paths
    for ap in KNOWN_ADWARE_PATHS:
        p = expand(ap)
        if p.exists():
            sz = file_size(p)
            result.add(ScanItem(path=str(p), size=sz, category="Adware", detail=f"Known adware path: {p.name}"))

    # 3. Suspicious browser extensions (Chrome/Safari)
    chrome_ext = expand("~/Library/Application Support/Google/Chrome/Default/Extensions")
    if chrome_ext.exists():
        try:
            for ext_dir in chrome_ext.iterdir():
                if not ext_dir.is_dir():
                    continue
                # Check for known bad extension IDs
                manifest = ext_dir / "1.0" / "manifest.json"
                if not manifest.exists():
                    for v in ext_dir.iterdir():
                        manifest = v / "manifest.json"
                        if manifest.exists():
                            break
                if manifest.exists():
                    try:
                        import json
                        with open(manifest) as f:
                            data = json.load(f)
                            perms = data.get("permissions", [])
                            if "history" in perms and "tabs" in perms and "webRequest" in perms:
                                result.add(ScanItem(path=str(ext_dir), size=file_size(ext_dir), category="Suspicious Extension", detail=f"Chrome ext: {data.get('name', ext_dir.name)}"))
                    except Exception:
                        pass
        except (OSError, PermissionError):
            pass

    # 4. Suspicious configuration profiles (mdm hijack)
    code, out = run_shell(["profiles", "-C"])
    if code == 0 and out.strip():
        # Non-system profiles
        for line in out.strip().split("\n"):
            if line.strip() and not line.startswith("_") and "attribute" not in line.lower():
                result.add(ScanItem(path="configuration-profile", size=0, category="Config Profile", detail=f"Profile: {line.strip()[:80]}"))

    # 5. EICAR test (if present) — verify content, not just filename
    for d in ["~/Downloads", "~/Desktop", "~/Documents"]:
        p = expand(d)
        if p.exists():
            for f in p.glob("*eicar*test*"):
                try:
                    if f.is_file() and EICAR in f.read_text(errors="ignore"):
                        result.add(ScanItem(path=str(f), size=f.stat().st_size, category="Test Virus", detail="EICAR test file"))
                except OSError:
                    pass

    return result

# ──────────────────────────────────────────────────────────────
#  8. Performance / Maintenance  (PerformanceScanning + PerformanceService)
#  Login Items, Background Items, RAM, DNS, Spotlight, Permissions, TM snapshots
# ──────────────────────────────────────────────────────────────

def scan_login_items() -> ScanResult:
    """List login items and launch agents."""
    result = ScanResult(module="Login Items")

    # System login items via osascript
    code, out = run_shell(["osascript", "-e", "tell application \"System Events\" to get the name of every login item"])
    if code == 0 and out.strip():
        for name in out.strip().split(", "):
            if name.strip():
                result.add(ScanItem(path="login-item", size=0, category="Login Item", detail=name.strip(), removable=False))

    # User Launch Agents
    la = expand("~/Library/LaunchAgents")
    if la.exists():
        for plist in la.glob("*.plist"):
            result.add(ScanItem(path=str(plist), size=plist.stat().st_size, category="Launch Agent", detail=plist.stem, removable=False))

    # System Launch Daemons (non-Apple)
    ld = Path("/Library/LaunchDaemons")
    if ld.exists():
        for plist in ld.glob("*.plist"):
            if not plist.stem.startswith("com.apple"):
                result.add(ScanItem(path=str(plist), size=plist.stat().st_size, category="Launch Daemon", detail=plist.stem, removable=False))

    return result

def scan_background_items() -> ScanResult:
    """List running background processes (non-system)."""
    result = ScanResult(module="Background Items")
    code, out = run_shell(["ps", "aux"])
    if code == 0:
        for line in out.strip().split("\n")[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                cmd = parts[10]
                # Skip system processes
                if any(s in cmd for s in ["/usr/libexec/", "/usr/sbin/", "/System/", "kernel_task", "launchd"]):
                    continue
                if any(s in cmd for s in ["CleanMyMac", "python3", "tk"]):
                    continue
                result.add(ScanItem(path=cmd, size=0, category="Background Process", detail=parts[10][:80], removable=False))
    return result

def run_maintenance_task(task: str) -> tuple[bool, str]:
    """Run a maintenance task. Returns (success, message)."""
    tasks = {
        "Free up RAM": "sudo purge",
        "Flush DNS Cache": "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder",
        "Reindex Spotlight": "sudo mdutil -E /",
        "Repair Disk Permissions": None,  # deprecated on APFS — no-op
        "Run Maintenance Scripts": "sudo periodic daily weekly monthly",
        "Free Up Purgeable Space": "sudo purge",
        "Speed Up Mail": "sqlite3 ~/Library/Mail/V*/MailData/Envelope\\ Index vacuum",
        "Thin Time Machine Snapshots": "tmutil thinLocalsnapshots / 10000000000 1",
    }
    cmd = tasks.get(task)
    if not cmd:
        if task == "Repair Disk Permissions":
            return False, "Repair Disk Permissions is deprecated on APFS and has no effect."
        return False, f"Unknown task: {task}"
    # SAFETY: Never VACUUM Mail's database while Mail is running —
    # VACUUM on an open database can corrupt it.
    if task == "Speed Up Mail":
        code, out = run_shell(["pgrep", "-x", "Mail"])
        if code == 0 and out.strip():
            return False, "Mail is running. Quit Mail before running Speed Up Mail."
    code, out = run_sudo(cmd.replace("~", str(Path.home())))
    if code == 0:
        return True, f"{task} completed"
    return False, f"{task} failed: {out}"

# ──────────────────────────────────────────────────────────────
#  9. Uninstaller  (UninstallerScanning.framework)
#  Full app removal including leftovers: caches, prefs, logs, containers
# ──────────────────────────────────────────────────────────────

def scan_installed_apps() -> ScanResult:
    """List all installed applications."""
    result = ScanResult(module="Installed Apps")
    app_dirs = [Path("/Applications"), Path("/System/Applications"), expand("~/Applications")]
    seen = set()
    for ad in app_dirs:
        if not ad.exists():
            continue
        for app in ad.glob("*.app"):
            if app.name in seen:
                continue
            seen.add(app.name)
            try:
                sz = file_size(app)
                # Get version
                info_plist = app / "Contents" / "Info.plist"
                version = ""
                if info_plist.exists():
                    try:
                        with open(info_plist, "rb") as f:
                            pl = plistlib.load(f)
                            version = pl.get("CFBundleShortVersionString", "")
                    except Exception:
                        pass
                # SAFETY: Mark Apple system apps as non-removable.
                # /System/Applications apps are also blocked by _is_protected()
                # (PROTECTED_DESCENDANTS), but removable=False prevents them from
                # even appearing as deletable in the UI.
                is_apple_app = False
                if info_plist.exists():
                    try:
                        with open(info_plist, "rb") as f:
                            pl = plistlib.load(f)
                            version = pl.get("CFBundleShortVersionString", "")
                            bid = pl.get("CFBundleIdentifier", "")
                            if bid.startswith("com.apple."):
                                is_apple_app = True
                    except Exception:
                        pass
                # Apps in /System/Applications are always Apple apps
                if ad == Path("/System/Applications"):
                    is_apple_app = True
                result.add(ScanItem(path=str(app), size=sz, category="Application",
                                    detail=f"{app.name} v{version} ({human_size(sz)})",
                                    removable=not is_apple_app))
            except OSError:
                pass
    return result

def find_app_leftovers(app_name: str) -> list[Path]:
    """Find leftover files from an uninstalled app.
    Uses bundle ID from Info.plist for precise matching when available,
    falling back to app name only if plist is unreadable."""
    name = app_name.replace(".app", "")
    # Try to extract bundle ID from Info.plist for precise matching
    bundle_id = None
    app_path = None
    for ad in [Path("/Applications"), expand("~/Applications")]:
        candidate = ad / app_name if not app_name.endswith(".app") else ad / app_name
        if candidate.exists():
            app_path = candidate
            break
    if app_path and (app_path / "Contents" / "Info.plist").exists():
        try:
            with open(app_path / "Contents" / "Info.plist", "rb") as f:
                pl = plistlib.load(f)
                bundle_id = pl.get("CFBundleIdentifier", "")
        except Exception:
            pass

    # Build search patterns — prefer bundle ID, fall back to app name
    search_patterns = []
    if bundle_id:
        search_patterns.extend([
            f"~/Library/Caches/{bundle_id}",
            f"~/Library/Preferences/{bundle_id}.plist",
            f"~/Library/Application Support/{bundle_id}",
            f"~/Library/Logs/{bundle_id}",
            f"~/Library/Saved Application State/{bundle_id}.savedState",
            f"~/Library/Containers/{bundle_id}",
            f"~/Library/Group Containers/{bundle_id}",   # exact match, NOT *{first_segment}*
            f"~/Library/Cookies/{bundle_id}.binarycookies",
            f"/Library/Caches/{bundle_id}",
            f"~/Library/LaunchAgents/{bundle_id}.plist",
        ])
    else:
        # When bundle_id is unavailable, use EXACT name match (not glob *{name}*).
        # Name-based globs are too dangerous — an app named "Mail" would match
        # com.apple.mail.plist in Preferences. Skip Preferences, Containers,
        # Group Containers, and Saved Application State entirely.
        search_patterns.extend([
            f"~/Library/Application Support/{name}",
            f"~/Library/Caches/{name}",
            f"~/Library/Logs/{name}",
        ])
    leftovers = []
    seen = set()
    for pattern in search_patterns:
        p = expand(pattern)
        parent = p.parent
        if parent.exists():
            for match in parent.glob(p.name):
                if match.exists() and str(match) not in seen:
                    if app_path and match == app_path:
                        continue
                    seen.add(str(match))
                    leftovers.append(match)
    return leftovers

# ──────────────────────────────────────────────────────────────
#  10. App Updater  (UpdaterScanning.framework)
# ──────────────────────────────────────────────────────────────

def scan_app_updates() -> ScanResult:
    """Check for app updates via Homebrew casks and mas."""
    result = ScanResult(module="App Updates")
    # Homebrew casks
    code, out = run_shell(["brew", "list", "--cask", "--versions"], timeout=15)
    if code == 0:
        for line in out.strip().split("\n"):
            if line.strip():
                parts = line.split()
                if parts:
                    result.add(ScanItem(path="brew-cask", size=0, category="Homebrew Cask", detail=parts[0], removable=False))
    # Homebrew outdated
    code, out = run_shell(["brew", "outdated", "--cask", "--quiet"], timeout=30)
    if code == 0:
        for line in out.strip().split("\n"):
            if line.strip():
                result.add(ScanItem(path="brew-outdated", size=0, category="Outdated (Brew)", detail=line.strip(), removable=False))
    # Mac App Store outdated
    code, out = run_shell(["mas", "outdated"], timeout=15)
    if code == 0:
        for line in out.strip().split("\n"):
            if line.strip():
                result.add(ScanItem(path="mas-outdated", size=0, category="Outdated (App Store)", detail=line.strip(), removable=False))
    return result

# ──────────────────────────────────────────────────────────────
#  11. Space Lens  (SpaceLensScanning.framework)
#  Drive visualizer - biggest folders/files
# ──────────────────────────────────────────────────────────────

def scan_space_lens(target: str = "~", depth: int = 2) -> ScanResult:
    """Scan directory and return biggest items."""
    result = ScanResult(module="Space Lens")
    p = expand(target)
    if not p.exists():
        return result
    entries = []
    try:
        for entry in p.iterdir():
            if entry.name.startswith(".") and entry.name not in [".Trash"]:
                continue
            sz = file_size(entry)
            if sz > 1024:
                entries.append(ScanItem(path=str(entry), size=sz,
                                category="Folder" if entry.is_dir() else "File",
                                detail=f"{entry.name} ({human_size(sz)})",
                                removable=False))  # Space Lens is visualization-only
    except (OSError, PermissionError):
        pass
    entries.sort(key=lambda x: x.size, reverse=True)
    result.items = entries[:50]
    result.total_size = sum(e.size for e in entries)
    return result

# ──────────────────────────────────────────────────────────────
#  12. Large & Old Files  (LAOFScanning.framework)
# ──────────────────────────────────────────────────────────────

def scan_large_old_files(min_size_mb: int = 100, min_age_days: int = 90) -> ScanResult:
    """Find large files not accessed in a while."""
    result = ScanResult(module="Large & Old Files")
    search_dirs = ["~/Documents", "~/Downloads", "~/Desktop", "~/Movies", "~/Music"]
    for sd in search_dirs:
        p = expand(sd)
        if not p.exists():
            continue
        for f in dir_walk(p, skip_hidden=True):
            try:
                if not f.is_file() or f.is_symlink():
                    continue
                sz = f.stat().st_size
                if sz < min_size_mb * 1_000_000:
                    continue
                age = file_age_days(f)
                if age >= min_age_days:
                    # SAFETY: Don't pre-select user files for deletion —
                    # user must explicitly choose which to delete.
                    result.add(ScanItem(path=str(f), size=sz, category="Large & Old",
                                detail=f"{f.name} ({human_size(sz)}, {age}d old)",
                                selected=False, removable=False))
            except OSError:
                pass
    return result

# ──────────────────────────────────────────────────────────────
#  13. Shredder  (secure delete)
#  Overwrite file with random data before unlink, 3 passes
# ──────────────────────────────────────────────────────────────

def shred_file(path: str, passes: int = 3) -> tuple[bool, str]:
    """Securely delete a file by overwriting then unlinking.
    SAFETY: Validates path is not protected, checks writability before
    overwriting so we don't destroy content if unlink will fail."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return False, f"File not found: {path}"
    # SAFETY: never shred protected paths
    if _is_protected(p):
        return False, f"Refused: {path} is in a protected directory"
    # SAFETY: check that we can write and delete before overwriting.
    # This prevents destroying file content when unlink would fail anyway.
    if not os.access(p, os.W_OK):
        return False, f"Refused: {path} is not writable (cannot shred)"
    try:
        # Verify the file can be unlinked (check parent dir write permission)
        if not os.access(p.parent, os.W_OK):
            return False, f"Refused: cannot delete from {p.parent} (not writable)"
        # SAFETY: check for immutable flag — if set, unlink will fail after
        # we overwrite, destroying the content while the file still exists.
        import stat as _stat
        st = p.stat()
        if hasattr(_stat, "UF_IMMUTABLE") and st.st_flags & _stat.UF_IMMUTABLE:
            return False, f"Refused: {path} has the immutable flag set (cannot unlink)"
        size = p.stat().st_size
        for _ in range(passes):
            with open(p, "r+b") as f:
                # Overwrite with random bytes
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, 65536)
                    f.write(os.urandom(chunk))
                    remaining -= chunk
                f.flush()
                os.fsync(f.fileno())
        # Final overwrite with zeros
        with open(p, "r+b") as f:
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
        p.unlink()
        return True, f"Shredded: {path}"
    except (OSError, PermissionError) as e:
        return False, f"Failed to shred {path}: {e}"

# ──────────────────────────────────────────────────────────────
#  14. Duplicate Finder  (OrganizeScanning - Duplicates)
# ──────────────────────────────────────────────────────────────

def scan_duplicates(target: str = "~", min_size_mb: float = 1) -> ScanResult:
    """Find duplicate files by hash."""
    result = ScanResult(module="Duplicate Finder")
    p = expand(target)
    if not p.exists():
        return result
    # Group by (size, first_4k_hash) then full hash
    size_groups: dict[int, list[Path]] = {}
    for f in dir_walk(p, skip_hidden=True):
        try:
            if not f.is_file() or f.is_symlink():
                continue
            sz = f.stat().st_size
            if sz < min_size_mb * 1_000_000:
                continue
            size_groups.setdefault(sz, []).append(f)
        except OSError:
            pass
    # For each size group with >1 file, hash and find dupes
    for sz, files in size_groups.items():
        if len(files) < 2:
            continue
        hash_groups: dict[str, list[Path]] = {}
        for f in files:
            h = file_hash(f)
            if h:
                hash_groups.setdefault(h, []).append(f)
        for h, dupes in hash_groups.items():
            if len(dupes) >= 2:
                # Keep first, mark rest as duplicates
                for i, d in enumerate(dupes):
                    removable = i > 0 and not _is_protected(d)
                    result.add(ScanItem(path=str(d), size=sz, category="Duplicate", detail=f"Dup group {h[:8]} ({d.name})", selected=removable, removable=removable))
    return result

# ──────────────────────────────────────────────────────────────
#  15. Similar Images  (OrganizeScanning - SimilarImages)
#  Group by image dimensions + file size proximity
# ──────────────────────────────────────────────────────────────

def scan_similar_images(target: str = "~") -> ScanResult:
    """Find visually similar images (same dimensions, similar size)."""
    result = ScanResult(module="Similar Images")
    p = expand(target)
    if not p.exists():
        return result
    # Collect images
    image_exts = {".jpg", ".jpeg", ".png", ".heic", ".tiff", ".bmp", ".gif", ".webp"}
    images: list[Path] = []
    for f in dir_walk(p, skip_hidden=True):
        try:
            if f.is_file() and f.suffix.lower() in image_exts:
                images.append(f)
        except OSError:
            pass
    # Group by file size (±10%)
    size_groups: dict[int, list[Path]] = {}
    for img in images:
        try:
            sz = img.stat().st_size
            # Bucket by 10% ranges
            bucket = int(sz * 0.9 / 1000)
            size_groups.setdefault(bucket, []).append(img)
        except OSError:
            pass
    for bucket, imgs in size_groups.items():
        if len(imgs) < 2:
            continue
        # Check actual dimensions via sips
        dims: dict[tuple[int, int], list[Path]] = {}
        for img in imgs:
            code, out = run_shell(["sips", "-g", "pixelWidth", "-g", "pixelHeight", str(img)], timeout=5)
            if code == 0:
                w = h = 0
                for line in out.split("\n"):
                    if "pixelWidth" in line:
                        w = int(line.split(":")[-1].strip())
                    elif "pixelHeight" in line:
                        h = int(line.split(":")[-1].strip())
                if w and h:
                    dims.setdefault((w, h), []).append(img)
        for dim, group in dims.items():
            if len(group) >= 2:
                for i, img in enumerate(group):
                    # Don't pre-select — user must manually choose which to delete.
                    # CleanMyMac doesn't auto-select similar images either.
                    result.add(ScanItem(path=str(img), size=img.stat().st_size,
                                category="Similar Image",
                                detail=f"{img.name} ({dim[0]}x{dim[1]})",
                                selected=False, removable=False))
    return result

# ──────────────────────────────────────────────────────────────
#  16. Cloud Storage  (CloudStorageScanning.framework)
#  iCloud, Dropbox, Google Drive local storage analysis
# ──────────────────────────────────────────────────────────────

def scan_cloud_storage() -> ScanResult:
    """Scan cloud storage local copies."""
    result = ScanResult(module="Cloud Storage")
    cloud_paths = {
        "iCloud Drive": "~/Library/Mobile Documents/com~apple~CloudDocs",
        "iCloud Desktop": "~/Library/Mobile Documents/com~apple~CloudDocs/Desktop",
        "iCloud Documents": "~/Library/Mobile Documents/com~apple~CloudDocs/Documents",
        "Dropbox": "~/Dropbox",
        "Google Drive": "~/Google Drive",
        "Google Drive (Backup and Sync)": "~/Google Drive File Stream",
        "OneDrive": "~/OneDrive",
        "iCloud Photos": "~/Library/Application Support/CloudDocs",
    }
    for name, cp in cloud_paths.items():
        p = expand(cp)
        if p.exists():
            sz = file_size(p)
            if sz > 0:
                result.add(ScanItem(path=str(p), size=sz, category=name, detail=f"{name} ({human_size(sz)})", removable=False))
    return result

# ──────────────────────────────────────────────────────────────
#  17. Extensions  (ApplicationsModule - Extensions)
# ──────────────────────────────────────────────────────────────

def scan_extensions() -> ScanResult:
    """Find system extensions, Safari extensions, Spotlight plugins."""
    result = ScanResult(module="Extensions")
    ext_paths = {
        "Safari Extensions": "~/Library/Safari/Extensions",
        "Internet Plugins": "~/Library/Internet Plug-Ins",
        "Input Methods": "~/Library/Input Methods",
        "Audio Plugins": "~/Library/Audio/Plug-Ins",
        "Spotlight Plugins": "~/Library/Spotlight",
        "Screen Savers": "~/Library/Screen Savers",
        "ColorSync": "~/Library/ColorSync",
    }
    for name, ep in ext_paths.items():
        p = expand(ep)
        if p.exists() and p.is_dir():
            for item in p.iterdir():
                if not item.name.startswith("."):
                    result.add(ScanItem(path=str(item), size=file_size(item), category=name, detail=item.name, removable=False))
    return result

# ──────────────────────────────────────────────────────────────
#  Smart Scan  (SmartCareModule.framework)
#  Runs: System Junk + Mail + Trash + Malware + Login Items + Updates
# ──────────────────────────────────────────────────────────────

def smart_scan() -> dict[str, ScanResult]:
    """Run the Smart Care scan combining core modules."""
    results = {}
    results["System Junk"] = scan_system_junk()
    results["Mail Attachments"] = scan_mail_attachments()
    results["Trash Bins"] = scan_trash_bins()
    results["Malware"] = scan_malware()
    results["Login Items"] = scan_login_items()
    results["App Updates"] = scan_app_updates()
    return results

# ──────────────────────────────────────────────────────────────
#  Cleanup
# ──────────────────────────────────────────────────────────────

# Paths that must NEVER be deleted — deleting these would cause data loss
# or system corruption. clean_items() checks this list before any deletion.
#
# Two protection tiers:
#   1. PROTECTED_EXACT  — the directory ITSELF is protected from rmtree/unlink,
#      but its children may still be cleaned (e.g. ~/Library/Caches contents,
#      /Library/Caches contents, ~/.Trash contents). This is essential: if
#      Path.home() or /Library were in the descendant-protected set, cleaning
#      ~/Library/Caches, ~/.Trash, /Library/Caches, /Library/Logs would all be
#      blocked — the app's primary function would be broken.
#   2. PROTECTED_DESCENDANTS — the directory AND every descendant is protected.
#      Used for user data dirs (Downloads, Documents, ...) and app data dirs
#      (Containers, Group Containers, Preferences) where no auto-deletion is
#      ever safe.
PROTECTED_EXACT = {
    Path.home(),                       # ~ itself — never rmtree the home dir
    Path("/Library"),                  # /Library itself — but /Library/Caches cleanable
    Path("/System"),
    Path("/Applications"),             # /Applications itself — individual .app ok
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
}

PROTECTED_DESCENDANTS = {
    # System apps — protect the dir AND all children (never delete Apple apps)
    Path("/System/Applications"),
    # User data directories — protect the dir AND all children
    Path.home() / "Downloads",
    Path.home() / "Documents",
    Path.home() / "Desktop",
    Path.home() / "Pictures",
    Path.home() / "Movies",
    Path.home() / "Music",
    # Critical Library subdirs — app data, never auto-delete
    Path.home() / "Library" / "Containers",         # app data — chat history, docs
    Path.home() / "Library" / "Group Containers",   # shared app data — never auto-delete
    Path.home() / "Library" / "Preferences",        # app prefs — never auto-delete
    # NOTE: ~/Library/Caches and ~/Library/Logs are intentionally NOT protected
    # here — their contents need cleaning via _delete_dir_contents(). The dirs
    # themselves are safe because their parent (~/Library) is not in
    # PROTECTED_DESCENDANTS, and clean_items uses _delete_dir_contents (not
    # rmtree) on them.
    # NOTE: /Library/Caches and /Library/Logs likewise NOT protected — contents
    # cleaned via _delete_dir_contents(); /Library is in PROTECTED_EXACT so the
    # dir itself cannot be rmtree'd.
    # NOTE: /System/Applications is in PROTECTED_DESCENDANTS (not PROTECTED_EXACT)
    # so that all .app bundles inside it are protected from deletion.
}

# Backward-compat alias: union of both sets (some callers iterate PROTECTED_PATHS)
PROTECTED_PATHS = PROTECTED_EXACT | PROTECTED_DESCENDANTS


def _is_protected(path: Path) -> bool:
    """Check if a path is protected.

    PROTECTED_EXACT: only the exact directory is protected (rmtree on the dir
    itself is refused, but its children can be cleaned via _delete_dir_contents).
    PROTECTED_DESCENDANTS: the directory AND every descendant is protected —
    no auto-deletion anywhere under it.
    """
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError):
        return True  # if we can't resolve it, treat as protected (safe default)
    # Exact-match protection: refuse to delete the dir itself, but allow children
    for prot in PROTECTED_EXACT:
        try:
            prot_resolved = prot.resolve()
        except (OSError, RuntimeError):
            continue
        if resolved == prot_resolved:
            return True
    # Descendant protection: refuse to delete the dir OR anything under it
    for prot in PROTECTED_DESCENDANTS:
        try:
            prot_resolved = prot.resolve()
        except (OSError, RuntimeError):
            continue
        if resolved == prot_resolved or prot_resolved in resolved.parents:
            return True
    return False


def _delete_dir_contents(path: Path) -> int:
    """Delete the CONTENTS of a directory (files and subdirs inside it),
    but preserve the directory itself. This is the safe way to clean caches/logs.
    Returns count of items removed."""
    removed = 0
    try:
        for child in path.iterdir():
            # SAFETY: Always check is_symlink() FIRST and unlink it.
            # Never rmtree a symlink — rmtree follows the link and would
            # delete the target tree (e.g. a symlink to ~/Documents).
            if child.is_symlink():
                try:
                    child.unlink()
                    removed += 1
                except (OSError, PermissionError):
                    pass
                continue
            try:
                if child.is_file():
                    child.unlink()
                    removed += 1
                elif child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                    removed += 1
            except (OSError, PermissionError):
                pass
    except (OSError, PermissionError):
        pass
    return removed


def clean_items(items: list[ScanItem], progress_cb=None) -> tuple[int, int, list[str]]:
    """Delete selected items. Returns (deleted_count, failed_count, error_messages).

    SAFETY RULES:
    1. Never delete a protected path (home, Downloads, Documents, Library, etc.)
    2. For cache/log directories: delete CONTENTS, not the directory itself
    3. For files: unlink the individual file
    4. Skip virtual paths (login-item, brew-cask, etc.)
    """
    deleted = 0
    failed = 0
    errors: list[str] = []
    # Virtual paths that are display-only (no real file to delete)
    virtual_paths = {"login-item", "brew-cask", "brew-outdated",
                     "mas-outdated", "configuration-profile", "background-process"}

    for i, item in enumerate(items):
        if not item.selected or not item.removable:
            continue
        if item.path in virtual_paths:
            continue
        try:
            p = Path(item.path)
            if not p.exists():
                continue
            # SAFETY CHECK: never delete protected paths
            if _is_protected(p):
                failed += 1
                errors.append(f"Skipped (protected): {p}")
                continue
            if p.is_symlink() or p.is_file():
                p.unlink()
                deleted += 1
            elif p.is_dir():
                # Delete CONTENTS of the directory, not the directory itself.
                # This is critical for cache/log dirs that macOS/apps expect
                # to exist. The directory is preserved, contents are removed.
                _delete_dir_contents(p)
                deleted += 1
        except (OSError, PermissionError) as e:
            failed += 1
            errors.append(f"Failed: {item.path} — {e}")
        if progress_cb:
            progress_cb(i + 1, len(items))
    return deleted, failed, errors

def uninstall_app(app_path: str, progress_cb=None) -> tuple[int, list[str]]:
    """Uninstall app + leftovers. Returns (deleted_count, messages).
    SAFETY: Refuses to uninstall Apple system apps (com.apple.* bundle ID).
    Allows uninstalling individual .app bundles under /Applications while
    protecting /Applications itself from deletion. Checks _is_protected()
    on every leftover path before deletion."""
    p = Path(app_path)
    msgs = []
    deleted = 0
    # SAFETY: never delete a top-level directory (e.g. /Applications itself)
    if p.parent == Path("/") or (p.parent == Path("/Applications") and p == Path("/Applications")):
        return 0, ["Refused: will not delete a top-level directory"]
    # SAFETY: refuse Apple system apps by checking bundle ID
    info_plist = p / "Contents" / "Info.plist"
    if info_plist.exists():
        try:
            with open(info_plist, "rb") as f:
                pl = plistlib.load(f)
                bid = pl.get("CFBundleIdentifier", "")
            if bid.startswith("com.apple."):
                return 0, [f"Refused: {p.name} is an Apple system app (bundle ID: {bid})"]
        except Exception:
            pass
    # SAFETY: still check _is_protected — this protects /System, /usr, etc.
    # and prevents deleting the /Applications dir itself.
    # /System/Applications is in PROTECTED_DESCENDANTS, so all .app bundles
    # inside it are protected. Individual .app bundles under /Applications
    # are allowed (not in PROTECTED_DESCENDANTS).
    if _is_protected(p):
        return 0, [f"Refused: {p} is in a protected directory (system app?)"]
    # SAFETY: never uninstall from /System/Applications
    try:
        if p.resolve() == Path("/System/Applications").resolve() or \
           Path("/System/Applications").resolve() in p.resolve().parents:
            return 0, [f"Refused: {p.name} is in /System/Applications (protected)"]
    except (OSError, RuntimeError):
        return 0, [f"Refused: could not resolve {p}"]
    # Remove app
    if p.exists():
        try:
            # SAFETY: never rmtree a symlink — it would follow the link
            # and delete the target tree. Unlink symlinks instead.
            if p.is_symlink():
                p.unlink()
            else:
                shutil.rmtree(p, ignore_errors=True)
            deleted += 1
            msgs.append(f"Removed: {p.name}")
        except Exception as e:
            msgs.append(f"Failed to remove app: {e}")
    # Find and remove leftovers
    leftovers = find_app_leftovers(p.name)
    for lo in leftovers:
        # SAFETY: check every leftover path before deletion
        if _is_protected(lo):
            msgs.append(f"Skipped (protected): {lo}")
            continue
        try:
            # SAFETY: check is_symlink() before rmtree — never follow links
            if lo.is_symlink():
                lo.unlink()
            elif lo.is_file():
                lo.unlink()
            elif lo.is_dir():
                shutil.rmtree(lo, ignore_errors=True)
            deleted += 1
            msgs.append(f"Removed leftover: {lo}")
        except Exception as e:
            msgs.append(f"Failed leftover {lo}: {e}")
    return deleted, msgs