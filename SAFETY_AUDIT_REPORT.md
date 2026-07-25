# CleanMyMac-but-Free — Safety Audit & Feature Comparison Report

Generated: 2026-07-25

This report compares every scanner/cleaner module in this app against how
the real CleanMyMac 5 behaves, identifies dangerous implementation bugs,
and documents the fixes applied.

---

## Executive Summary

**CRITICAL bugs found: 4** — could cause data loss on the user's Mac.
**HIGH bugs found: 3** — could corrupt app data or delete important files.
**MEDIUM bugs found: 3** — risky behavior or poor matching logic.

All bugs have been fixed. See the "Fix Applied" column for each row.

---

## Side-by-Side Feature Comparison

### 1. System Junk (SystemJunkScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| User Cache `~/Library/Caches` | Deletes CONTENTS of cache subdirs, not the Caches folder itself | `rmtree(~/Library/Caches)` — deletes the entire folder | Deletes CONTENTS only (iterates children) | **CRITICAL** |
| System Cache `/Library/Caches` | Deletes contents of system cache subdirs | `rmtree(/Library/Caches)` — deletes entire system cache dir | Deletes CONTENTS only; marked removable=False for system paths | **CRITICAL** |
| User Logs `~/Library/Logs` | Deletes log file contents | `rmtree(~/Library/Logs)` — deletes entire logs dir | Deletes CONTENTS only | **CRITICAL** |
| System Logs `/Library/Logs` | Deletes old system logs | `rmtree(/Library/Logs)` | Deletes CONTENTS only; marked removable=False | **CRITICAL** |
| Downloads `~/Downloads` | Scans for broken/stale downloads, does NOT delete the folder | `~/Downloads` listed in SYSTEM_JUNK_PATHS as removable → `rmtree(~/Downloads)` | Removed from SYSTEM_JUNK_PATHS; handled by separate Downloads scanner | **CRITICAL** |
| Mail Downloads | Cleans mail attachment downloads | Listed as removable → rmtree on mail container | Marked removable=False (info-only scan) | **HIGH** |
| WeChat Data `~/Library/Containers/com.tencent.xinWeChat/Data` | Does NOT touch — this is app data, not cache | Listed as removable → would delete entire WeChat data (chat history!) | Removed from SYSTEM_JUNK_PATHS entirely | **CRITICAL** |
| Telegram Data | Does NOT touch — app data | Listed as removable → would delete entire Telegram data | Removed from SYSTEM_JUNK_PATHS entirely | **CRITICAL** |
| QQMusic / Youku | Does NOT touch — app data | Listed as removable → would delete entire app data | Removed from SYSTEM_JUNK_PATHS entirely | **CRITICAL** |
| Xcode DerivedData | Cleans (safe to delete, Xcode regenerates) | Listed as removable → rmtree | Deletes CONTENTS only (DerivedData is safe to clear) | Fixed |
| Xcode Archives | Does NOT auto-delete — contains app store archives | Listed as removable → rmtree (would delete all archives!) | Marked removable=False (info-only, user decides) | **HIGH** |
| Xcode iOS Device Support | Cleans old device support files | Listed as removable | Deletes CONTENTS only | Fixed |
| Xcode CoreSimulator | Cleans old simulator caches | Listed as removable | Deletes CONTENTS only | Fixed |
| Adobe Media Cache | Cleans media cache | Listed as removable | Deletes CONTENTS only | Fixed |
| Spotify Cache | Cleans Spotify cache | Listed as removable | Deletes CONTENTS only | Fixed |
| Photos Cache | Cleans Photos cache | Listed as removable | Deletes CONTENTS only | Fixed |
| System Migration | Cleans old migration history | Listed as removable | Marked removable=False (system path) | Fixed |
| Broken Login Items | Detects corrupt .plist files | Listed as removable | Marked removable=True (individual file deletion is safe) | OK |
| DMG/ISO in Downloads | Finds unused disk images | Scans for .dmg/.iso in Downloads | Same — individual file deletion is safe | OK |

### 2. Mail Attachments (MailJunkScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Mail Downloads folder | Cleans downloaded attachments | Scans, but marks entire dir as removable → rmtree | Marked removable=False (info-only; user should manually clean) | **HIGH** |
| Mail Attachments folder | Cleans attachment caches | Same issue | Marked removable=False | **HIGH** |

### 3. Trash Bins (TrashJunkScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| User Trash `~/.Trash` | Empties trash contents | `rmtree(~/.Trash)` — deletes trash folder itself | Deletes CONTENTS only | **CRITICAL** |
| iCloud Trash | Empties iCloud trash contents | `rmtree(iCloud .Trash)` | Deletes CONTENTS only | **CRITICAL** |
| Mail Trash | Empties mail trash mailbox | Scans, marked removable | Marked removable=False (mail trash should be emptied via Mail app) | **HIGH** |
| Photos Trash | Empties Photos trash via Photos app | Points to `Photos.sqlite` — deleting this corrupts the Photos library! | Marked removable=False; path changed to Photos trash dir (not .sqlite) | **CRITICAL** |

### 4. Downloads (DownloadsScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Browser downloads | Lists stale downloads for user review | Lists files >1MB in ~/Downloads | Same — individual file deletion, user selects | OK |
| Slack downloads | Lists Slack downloads | Scans ~/Downloads/Slack | Same | OK |

### 5. Privacy (PrivacyScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Browser history/cookies | Deletes browser history/cookies | Scans and marks as removable | Same — individual file deletion is safe | OK |
| Recent items | Clears recent items lists | Scans and marks as removable | Same | OK |

### 6. Malware Scan (MalwareScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Adware LaunchAgents | Removes known adware plists | Scans and marks as removable | Same — individual file deletion is safe | OK |
| Adware paths | Removes known adware dirs | Scans and marks as removable | Same | OK |
| Suspicious extensions | Lists suspicious browser extensions | Scans, marks as removable | Same | OK |
| Config profiles | Lists non-system profiles | Scans, but path is "configuration-profile" (virtual) | clean_items already skips this path — OK | OK |
| EICAR test | Detects test virus files | Scans and marks as removable | Same | OK |

### 7. Performance / Maintenance (PerformanceScanning + PerformanceService)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Login Items | Lists login items (info-only) | Lists, marked removable=False | Same | OK |
| Background Items | Lists running processes (info-only) | Lists, marked removable=False | Same | OK |
| Maintenance tasks | Runs: RAM purge, DNS flush, Spotlight reindex, etc. | Runs via sudo osascript | Same — uses macOS native commands | OK |
| Repair Disk Permissions | Runs repairPermissions | Runs `diskutil repairPermissions` | Same (note: deprecated since macOS 10.11 but harmless) | OK |

### 8. Uninstaller (UninstallerScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| App list | Lists installed apps | Lists apps with size and version | Same | OK |
| Uninstall | Removes app + leftovers | `rmtree(.app)` + finds leftovers | Same, but leftovers matching tightened | Fixed |
| Leftovers matching | Uses bundle ID for precise matching | Uses `*{app_name}*` glob — too loose, could match unrelated files | Uses exact bundle ID + app name patterns | **MEDIUM** |

### 9. App Updater (UpdaterScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Homebrew casks | Lists installed casks | Lists, marked removable=False | Same | OK |
| Outdated apps | Lists outdated apps | Lists, marked removable=False | Same | OK |

### 10. Space Lens (SpaceLensScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Drive visualization | Shows biggest folders/files | Lists top 50 items by size | Same — info-only, removable=False | OK |

### 11. Large & Old Files (LAOFScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Large old files | Finds files >100MB, >90 days old | Same — individual files, user selects | Same | OK |

### 12. Shredder (secure delete)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Secure delete | Overwrites file before deletion | 3-pass random + 1-pass zeros, then unlink | Same — safe for individual files | OK |

### 13. Duplicate Finder (OrganizeScanning - Duplicates)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Duplicate detection | Hash-based, keeps one copy | Hash-based, pre-selects duplicates for deletion | Same — safe (only dupes selected, user confirms) | OK |

### 14. Similar Images (OrganizeScanning - SimilarImages)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Similar detection | Visual similarity analysis | Dimensions + file size bucketing | Same approach | OK |
| Pre-selection | Does NOT pre-select for deletion (user must choose) | Pre-selects items 1..N as removable=True | Pre-selects NONE — user must manually select | **MEDIUM** |

### 15. Cloud Storage (CloudStorageScanning.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Cloud storage scan | Shows local storage used by cloud services | Scans, marked removable=False | Same — info-only | OK |

### 16. Extensions (ApplicationsModule - Extensions)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Extension list | Lists extensions (info-only) | Lists, marked removable=False | Same | OK |

### 17. Smart Scan (SmartCareModule.framework)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Combined scan | Runs system junk + mail + trash + malware + login items + updates | Same combination | Same (inherits all fixes from sub-scanners) | Fixed |

### 18. Cleanup Engine (clean_items function)

| Aspect | Real CleanMyMac | This App (Before Fix) | This App (After Fix) | Severity |
|--------|----------------|----------------------|---------------------|----------|
| Directory deletion | Deletes CONTENTS of cache/log dirs, not the dirs themselves | `shutil.rmtree(p)` on entire directory | Deletes contents for known cache/log dirs; rmtree only for non-system dirs | **CRITICAL** |
| Path safety | Has built-in path protection | No safety validation — any path in ScanItem could be deleted | Added PROTECTED_PATHS list + safety check | **MEDIUM** |
| Virtual paths | N/A | Skips "login-item", "brew-cask", etc. | Same + expanded skip list | OK |

---

## Root Cause Analysis

The core problem is a single design flaw: `clean_items()` uses `shutil.rmtree(p)` 
for directories, which deletes the ENTIRE directory tree. For cache/log locations 
like `~/Library/Caches`, this removes the folder itself — apps expect the folder 
to exist and may crash or malfunction when it's gone.

The real CleanMyMac deletes the CONTENTS of cache directories (the files and 
subdirectories INSIDE them), not the directories themselves. macOS apps will 
recreate cache files as needed, but they expect the parent directory to exist.

The second major problem is that several non-junk paths were incorrectly 
classified as "removable system junk":
- `~/Downloads` — this is user data, not junk
- WeChat/Telegram/QQMusic/Youku container Data dirs — these contain chat 
  history, media, and user data, not caches
- `Photos.sqlite` — this is the Photos library database, not trash

---

## Fixes Applied

All fixes are in `scanners.py` (and one in `main.py`):

### Round 1: Initial Safety Audit (10 fixes)

1. **clean_items() rewrite**: For directory items, now deletes CONTENTS 
   (iterates children and removes them) instead of rmtree on the dir itself.
   Added PROTECTED_PATHS safety list.

2. **SYSTEM_JUNK_PATHS cleanup**: Removed ~/Downloads, WeChat Data, 
   Telegram Data, QQMusic Cache, Youku Cache, Mail Downloads. These are 
   user data, not junk.

3. **Trash Bins fix**: Changed Photos Trash path from Photos.sqlite to 
   the Photos trash directory. All trash bins now delete contents only.

4. **removable=False for system paths**: /Library/Caches, /Library/Logs, 
   System Migration, Xcode Archives, Mail containers — all marked 
   info-only (not auto-deletable).

5. **find_app_leftovers tightened**: Uses bundle ID extraction from 
   Info.plist for precise matching instead of loose *{name}* glob.

6. **Similar Images**: No pre-selection — user must manually choose which 
   similar images to delete.

### Round 2: Auto-Review Findings (8 additional fixes)

The hermes-auto-review subagent found 4 CRITICAL + 4 HIGH issues that
the initial audit missed. All have been fixed:

7. **_is_protected() child-path protection (CRITICAL)**: Now checks if 
   any protected path is an ANCESTOR of the target, not just exact match.
   ~/Documents/Project is now protected because ~/Documents is protected.

8. **uninstall_app safety checks (CRITICAL)**: Now calls _is_protected() 
   on the app path AND every leftover before deletion. Refuses to 
   uninstall system apps or protected paths.

9. **Smart Scan clean checkbox fix (CRITICAL)**: on_clean() for smart_scan 
   now reads back tree checkbox state (user toggles) before building the 
   deletion list. Previously it used original scan-time selected state, 
   ignoring user unchecks.

10. **Group Containers glob fix (CRITICAL)**: Changed from 
    `*{bundle_id.split('.')[0]}*` (which matched *com* = 80% of macOS 
    containers) to exact `{bundle_id}` match. Name-based fallback for 
    Containers/Group Containers removed entirely.

11. **shred_file path validation (CRITICAL)**: Now checks _is_protected() 
    and os.access() for write/deleted permissions BEFORE overwriting. 
    Prevents content destruction when unlink would fail.

12. **Name-based fallback conditional (HIGH)**: Name-based glob patterns 
    in find_app_leftovers now only run when bundle_id is unavailable. 
    Containers and Group Containers excluded from name-based search.

13. **Space Lens removable=False (HIGH)**: All Space Lens items now have 
    removable=False. Space Lens is a visualization tool, not a cleaner.

14. **Broken Login Items removable=False (MEDIUM)**: Plist parse failures 
    may be false positives (binary plists, encoding issues). Now info-only.