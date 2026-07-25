# Functional Quality Comparison: CleanMyMac-but-Free vs Real CleanMyMac

Generated: 2026-07-25
Source for real CMM: macpaw.com/support/cleanmymac/knowledgebase/missing-features (official feature matrix, updated April 2026)

This report compares the FUNCTIONAL QUALITY of each module — not just whether
a feature exists, but how well it works compared to the real CleanMyMac.

Rating scale:
  MATCH    = Functionally equivalent (different impl, same result)
  PARTIAL  = Core feature works, but missing capabilities or lower quality
  MISSING  = Feature does not exist in this app
  WEAK     = Implemented but significantly lower quality / accuracy

---

## 1. Smart Care (Smart Scan)

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| One-click combined scan | Runs Cleanup + Protection + Performance + Apps + My Clutter | Runs System Junk + Mail + Trash + Malware + Login Items + Updates | PARTIAL |
| Cleanup in Smart Scan | System Junk, Mail Attachments, Trash Bins | Same | MATCH |
| Protection in Smart Scan | Malware Removal | Malware scan (rule-based) | PARTIAL |
| Performance in Smart Scan | Login Items, Background Items, Maintenance | Login Items only | PARTIAL |
| Applications in Smart Scan | Updater (outdated apps) | App Updates (brew + mas) | PARTIAL |
| My Clutter in Smart Scan | Duplicates, Similar Images, Large & Old, Downloads | NOT included in Smart Scan | MISSING |
| Smart Scan result display | Grouped by module with expand/collapse, visual icons, size summary | Grouped by module (header rows in tree), text-only | PARTIAL |
| One-click clean after scan | Clean button cleans all selected across modules | Same (after checkbox fix) | MATCH |

Quality gap: Real CMM's Smart Scan is more comprehensive — it includes My Clutter
(Duplicates, Similar, LAOF, Downloads) which this app doesn't combine into the
smart scan. The real CMM also has a much richer UI with visual progress, circular
progress indicators, and animated results.

---

## 2. Cleanup — System Junk

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| User Cache Files | Cleans contents of ~/Library/Caches | Same (via _delete_dir_contents) | MATCH |
| System Cache Files | Cleans /Library/Caches (requires sudo) | Scans but removable=False (info-only) | PARTIAL |
| User Log Files | Cleans ~/Library/Logs | Same | MATCH |
| System Log Files | Cleans /Library/Logs (requires sudo) | Scans but removable=False | PARTIAL |
| Broken Login Items | Detects broken LaunchAgents | Detects unparseable plists, removable=False | MATCH |
| Broken Preferences | Detects corrupt preference plists | NOT implemented | MISSING |
| Document Versions | Cleans old document version snapshots | NOT implemented | MISSING |
| iOS Device Backups | Finds old iOS backups | NOT implemented | MISSING |
| Language Files | Removes unused language packs (.lproj) | NOT implemented | MISSING |
| Universal Binaries | Strips architecture slices (ARM/x86) | NOT implemented | MISSING |
| Xcode Junk | DerivedData, Archives, Simulator, Device Support | Same (DerivedData, Archives, DeviceSupport, CoreSimulator, Device Logs) | MATCH |
| Adobe Media Cache | Not explicitly listed but cleaned as cache | Scans and cleans | MATCH |
| Spotify Cache | Not explicitly listed but cleaned as cache | Scans and cleans | MATCH |
| Photos Cache | Not explicitly listed but cleaned as cache | Scans and cleans | MATCH |

Quality gap: Missing 5 system junk categories (Broken Preferences, Document
Versions, iOS Backups, Language Files, Universal Binaries). System cache/logs
are info-only because the app uses osascript for sudo — real CMM has native
privilege escalation. Language Files and Universal Binaries are significant
space savers (often 1-5 GB).

---

## 3. Cleanup — Mail Attachments

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Mail attachment scan | Scans Mail downloads + attachments | Same paths | MATCH |
| Mail attachment clean | Deletes individual attachment files, preserves Mail data | removable=False (info-only) | PARTIAL |
| Mail attachment preview | Shows which attachments, sortable by size | Shows path + size, no preview | PARTIAL |

Quality gap: Real CMM can safely clean individual mail attachment files without
touching Mail's database. This app marks them info-only because deleting entire
mail container directories would destroy Mail data. A proper implementation
would walk the Mail Downloads directory and list individual files for deletion.

---

## 4. Cleanup — Trash Bins

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Startup Drive Trash | Empties ~/.Trash contents | Same (via _delete_dir_contents) | MATCH |
| External Drive Trash | Empties .Trashes on mounted volumes | NOT implemented | MISSING |
| Local Mail Trash | Empties Mail trash mailbox | Scans, removable=False | PARTIAL |
| Photos Trash | Empties Photos "Recently Deleted" | Scans Photos dir, removable=False | PARTIAL |

Quality gap: Missing external drive trash scanning (.Trashes on /Volumes/*).
Mail and Photos trash are info-only because proper emptying requires AppleScript
integration with Mail.app and Photos.app, not file deletion.

---

## 5. Cleanup — Downloads

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Safari Downloads | Lists files in ~/Downloads with age/size | Same | MATCH |
| Chrome Downloads | Lists files in ~/Downloads | Same (same dir, duplicate detection) | PARTIAL |
| Slack Downloads | Lists files in ~/Downloads/Slack | Same | MATCH |
| Duplicate Downloads | Detects duplicate files in Downloads | NOT in Downloads scanner (in Duplicate Finder only) | MISSING |
| Browser download history | Reads actual browser download databases | Just lists files in ~/Downloads | PARTIAL |

Quality gap: Real CMM reads browser download history databases to identify
which files were actually downloaded (vs user-created files). This app just
lists all files >1MB in ~/Downloads, which includes user-created files.

---

## 6. Cleanup — Unused Disk Images

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Find .dmg files | Scans ~/Downloads, ~/Desktop, ~/Documents | Same | MATCH |
| Find .iso/.img files | Same | Same (.dmg, .iso, .img, .smi, .sparseimage) | MATCH |
| Check if mounted | Excludes currently mounted DMGs | NOT implemented — lists all DMGs including mounted ones | PARTIAL |
| File age awareness | Shows age, prioritizes old DMGs | Shows name + size, no age | PARTIAL |

Quality gap: This app doesn't check if a DMG is currently mounted, so a user
could accidentally delete a mounted disk image. Also no file age display.

---

## 7. Protection — Malware

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Malware detection engine | Cloud-based signature database, updated daily, real-time monitoring | Static rule-based: known adware bundle IDs + paths | WEAK |
| Real-time protection | Background monitor, alerts on suspicious activity | NOT implemented | MISSING |
| Adware detection | Comprehensive, updated regularly | ~30 hardcoded adware bundle IDs + ~20 paths | WEAK |
| Browser extension scan | Checks for suspicious extensions | Checks Chrome extensions for permission combinations | PARTIAL |
| Config profile scan | Detects suspicious MDM profiles | Same (via `profiles -C`) | MATCH |
| EICAR test detection | Detects EICAR test file | Same (glob *eicar*) | MATCH |
| Quarantine | Quarantines threats before deletion | NOT implemented — direct deletion | MISSING |
| Malware database updates | Daily automatic updates | Static list, no updates | MISSING |

Quality gap: This is the weakest module. Real CMM has a cloud-backed malware
database with daily updates and real-time monitoring. This app has a static
hardcoded list of ~30 known adware bundle IDs that will become stale. No
real-time protection, no quarantine, no database updates.

---

## 8. Protection — Privacy

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Safari: History, Cookies, Downloads, Top Sites, Last Session | Cleans all | Same paths | MATCH |
| Chrome: History, Cookies, Cache | Cleans all | Same paths | MATCH |
| Firefox: History, Cookies, Cache | Cleans all (glob patterns) | Same | MATCH |
| Recent Items Lists | Cleans recent apps/docs/servers | Same | MATCH |
| Wi-Fi Networks | Forgets saved Wi-Fi networks | NOT implemented | MISSING |
| Application Permissions | Shows and resets app permissions | NOT implemented | MISSING |

Quality gap: Missing Wi-Fi network management and application permissions
(contacts, location, camera, microphone access review).

---

## 9. Performance — Maintenance

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Free up RAM | `sudo purge` | Same | MATCH |
| Flush DNS Cache | `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder` | Same | MATCH |
| Reindex Spotlight | `sudo mdutil -E /` | Same | MATCH |
| Repair Disk Permissions | `sudo diskutil repairPermissions /` | Same (deprecated since 10.11) | MATCH |
| Run Maintenance Scripts | `sudo periodic daily weekly monthly` | Same | MATCH |
| Free Up Purgeable Space | `sudo purge` | Same (duplicate of Free up RAM) | PARTIAL |
| Speed Up Mail | VACUUM Mail envelope index | Same (but no Mail running check) | PARTIAL |
| Thin Time Machine Snapshots | `tmutil thinLocalsnapshots` | Same | MATCH |

Quality gap: "Free Up Purgeable Space" and "Free up RAM" are identical (`sudo purge`)
— real CMM likely uses different mechanisms. Speed Up Mail doesn't check if Mail
is running (could corrupt index). Repair Disk Permissions is deprecated on APFS.

---

## 10. Performance — Login Items / Background Items

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| List login items | Via System Events osascript | Same | MATCH |
| List Launch Agents | ~/Library/LaunchAgents | Same | MATCH |
| List Launch Daemons | /Library/LaunchDaemons (non-Apple) | Same | MATCH |
| Enable/disable login items | Toggle items on/off without removing | NOT implemented | MISSING |
| Background items | Lists running processes | Same (via `ps aux`) | MATCH |
| Kill background processes | Can stop running processes | NOT implemented (info-only) | MISSING |

Quality gap: Real CMM can toggle login items on/off and kill background
processes. This app is display-only for both.

---

## 11. Applications — Uninstaller

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| List installed apps | All .app bundles with size + version | Same (/Applications, /System/Applications, ~/Applications) | MATCH |
| Uninstall app | Removes .app bundle + all leftovers | Same (rmtree + find_app_leftovers) | MATCH |
| Leftover detection | Uses bundle ID for precise matching | Bundle ID from Info.plist + name fallback | MATCH |
| Leftover categories | Caches, prefs, logs, containers, support, saved state, cookies, launch agents | Same categories | MATCH |
| Safety checks | Prevents uninstalling system apps | _is_protected() check | MATCH |
| Preview before uninstall | Shows what will be removed before executing | NOT implemented (deletes immediately) | MISSING |
| Leftovers scan (standalone) | Scan for remnants of already-removed apps | NOT implemented as standalone tool | MISSING |

Quality gap: No preview before uninstall — user can't see what will be deleted
before committing. No standalone leftovers scanner for already-removed apps.

---

## 12. Applications — Updater

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| App Store updates | Checks Mac App Store for updates | Same (via `mas outdated`) | MATCH |
| Homebrew updates | Checks Homebrew casks | Same (via `brew outdated --cask`) | MATCH |
| Sparkle updates | Checks apps using Sparkle framework | NOT implemented | MISSING |
| Custom updates | Checks vendor-specific update mechanisms | NOT implemented | MISSING |
| macOS updates | Checks for macOS system updates | NOT implemented | MISSING |
| Auto-update | Can update apps automatically | NOT implemented (info-only) | MISSING |

Quality gap: Missing Sparkle framework updates (used by most non-App-Store
Mac apps), macOS system update checking, and auto-update capability. This app
can only detect outdated apps via brew and mas — it cannot update them.

---

## 13. Applications — Extensions

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Safari Extensions | Lists installed Safari extensions | Same | MATCH |
| Internet Plugins | Lists ~/Library/Internet Plug-Ins | Same | MATCH |
| Input Methods | Lists ~/Library/Input Methods | Same | MATCH |
| Audio Plugins | Lists ~/Library/Audio/Plug-Ins | Same | MATCH |
| Spotlight Plugins | Lists ~/Library/Spotlight | Same | MATCH |
| Screen Savers | Lists ~/Library/Screen Savers | Same | MATCH |
| Remove extensions | Can remove extensions | NOT implemented (removable=False) | MISSING |

Quality gap: All extensions are info-only. Real CMM can remove extensions.

---

## 14. Organize — Space Lens

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Interactive sunburst visualization | Radial tree map, click to drill into folders | Flat list of top 50 items by size | WEAK |
| Folder size calculation | Recursive, all folders | Same (file_size on each entry) | MATCH |
| Drill-down navigation | Click folder to see its contents | NOT implemented | MISSING |
| Delete from visualization | Can delete folders/files from the visualization | removable=False (visualization-only) | PARTIAL |
| Depth | Unlimited depth, interactive | depth=2, flat top-level only | WEAK |

Quality gap: Space Lens is the most visually distinctive feature of real CMM —
an interactive sunburst/radial tree map. This app is just a sorted flat list.
No drill-down, no visualization, no interactive exploration.

---

## 15. Organize — Large & Old Files

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Find large old files | >100MB, >90 days old | Same thresholds | MATCH |
| Search locations | Documents, Downloads, Desktop, Movies, Music | Same | MATCH |
| File age display | Shows last access date | Same (days old) | MATCH |
| Sort by size/age | Sortable columns | Fixed sort (scan order) | PARTIAL |
| File preview | Quick Look preview | NOT implemented | MISSING |
| Move to trash (not delete) | Moves to Trash, not permanent delete | Direct delete (clean_items) | PARTIAL |

Quality gap: No Quick Look preview, no sort by columns, and deletion is
permanent (no Trash safety net). Real CMM moves files to Trash so users can
recover if they make a mistake.

---

## 16. Organize — Duplicate Finder

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Hash-based detection | Full file hash comparison | SHA-256 hash | MATCH |
| Size pre-filtering | Group by size before hashing | Same | MATCH |
| Keep one copy | Auto-selects duplicates, keeps original | Same (selected=True for i>0) | MATCH |
| Min size filter | Configurable minimum | 1MB default | MATCH |
| File preview | Quick Look preview | NOT implemented | MISSING |
| Smart selection | Can choose which to keep (newest, largest, etc.) | Keeps first found, no smart selection | PARTIAL |

Quality gap: No preview, no smart selection strategy (keep newest, keep largest,
keep in specific folder). User must manually decide which duplicates to keep.

---

## 17. Organize — Similar Images

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Visual similarity | perceptual hash / image analysis | Dimensions + file size bucketing (±10%) | WEAK |
| Image format support | All common formats | .jpg, .jpeg, .png, .heic, .tiff, .bmp, .gif, .webp | MATCH |
| Group similar images | Groups by visual similarity | Groups by same dimensions + similar size | PARTIAL |
| No pre-selection | User chooses which to delete | Same (selected=False) | MATCH |
| Quick Look preview | Preview before deleting | NOT implemented | MISSING |

Quality gap: This app uses file dimensions + size bucketing as a proxy for
visual similarity — it will group images that happen to have the same
dimensions and similar file size, even if they look completely different.
Real CMM uses perceptual hashing or ML-based image analysis.

---

## 18. Organize — Shredder

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Secure delete | Overwrite + unlink | 3-pass random + 1-pass zeros + unlink | MATCH |
| File picker | File dialog to select files | Same (askopenfilenames) | MATCH |
| Path validation | Prevents shredding system files | _is_protected() check | MATCH |
| Permission check | Checks writability before overwrite | os.access() check | MATCH |
| Folder shredding | Can shred folders | NOT implemented (files only) | MISSING |
| DoD/Gutmann standards | Multiple shredding algorithms | Single algorithm (random + zeros) | PARTIAL |

Quality gap: Cannot shred directories, and only one shredding algorithm.
Real CMM likely offers DoD 5220.22-M or Gutmann methods.

---

## 19. Cloud Cleanup

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| iCloud Drive | Shows local storage used | Same | MATCH |
| iCloud Desktop | Shows Desktop sync storage | Same | MATCH |
| iCloud Documents | Shows Documents sync storage | Same | MATCH |
| Dropbox | Shows Dropbox local storage | Same | MATCH |
| Google Drive | Shows Google Drive local storage | Same | MATCH |
| OneDrive | Shows OneDrive local storage | Same | MATCH |
| Clean cloud files | Can delete specific cloud-cached files | removable=False (info-only) | PARTIAL |
| iCloud Photos | Shows iCloud Photos storage | Points to CloudDocs (wrong path) | PARTIAL |

Quality gap: All cloud storage items are info-only — cannot clean individual
cached files. iCloud Photos path is wrong (points to CloudDocs, not Photos
library).

---

## 20. The Menu (Menu Bar Monitor)

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Menu bar app | Always-available menu bar icon with dropdown | NOT implemented | MISSING |
| Battery Monitor | Battery status in menu bar | NOT implemented | MISSING |
| CPU Monitor | CPU usage in menu bar | NOT implemented | MISSING |
| RAM Monitor | Memory usage in menu bar | NOT implemented | MISSING |
| Network Monitor | Network activity in menu bar | NOT implemented | MISSING |
| Storage Monitor | Disk usage in menu bar | NOT implemented | MISSING |
| Mac Health | Overall health score | NOT implemented | MISSING |
| Alerts | Low space, heavy RAM, hung apps, malware | NOT implemented | MISSING |
| Recommendations | Proactive suggestions | NOT implemented | MISSING |

Quality gap: The entire menu bar monitoring system is missing. This is a
major feature of real CMM that provides always-on system monitoring.

---

## 21. My Activity

| Capability | Real CleanMyMac | This App | Rating |
|-----------|----------------|----------|--------|
| Mac Health | Overall health score over time | NOT implemented | MISSING |
| Recommendations | Proactive maintenance suggestions | NOT implemented | MISSING |
| Usage statistics | Cleaning history + space saved | NOT implemented | MISSING |

---

## Summary Scorecard

| Module | Features in CMM | Features Matched | Partial | Missing | Weak |
|--------|----------------|-----------------|---------|---------|------|
| Smart Care | 8 | 3 | 4 | 1 | 0 |
| System Junk | 13 | 7 | 2 | 4 | 0 |
| Mail Attachments | 3 | 1 | 2 | 0 | 0 |
| Trash Bins | 4 | 1 | 2 | 1 | 0 |
| Downloads | 5 | 2 | 2 | 1 | 0 |
| Disk Images | 4 | 2 | 2 | 0 | 0 |
| Malware | 8 | 2 | 1 | 3 | 2 |
| Privacy | 6 | 4 | 0 | 2 | 0 |
| Maintenance | 8 | 6 | 2 | 0 | 0 |
| Login/Background | 6 | 3 | 0 | 3 | 0 |
| Uninstaller | 7 | 5 | 0 | 2 | 0 |
| Updater | 6 | 2 | 0 | 4 | 0 |
| Extensions | 7 | 6 | 0 | 1 | 0 |
| Space Lens | 5 | 1 | 1 | 1 | 2 |
| Large & Old Files | 6 | 3 | 2 | 1 | 0 |
| Duplicate Finder | 6 | 4 | 1 | 1 | 0 |
| Similar Images | 5 | 2 | 1 | 1 | 1 |
| Shredder | 6 | 4 | 1 | 1 | 0 |
| Cloud Cleanup | 8 | 5 | 2 | 0 | 1 |
| Menu Bar Monitor | 9 | 0 | 0 | 9 | 0 |
| My Activity | 3 | 0 | 0 | 3 | 0 |
| TOTAL | 137 | 63 (46%) | 27 (20%) | 39 (28%) | 6 (4%) |

Overall: 46% full match, 20% partial, 28% missing, 4% weak.

---

## Biggest Quality Gaps (ranked by impact)

1. **Menu Bar Monitor** (9 features missing) — The entire always-on monitoring
   system. This is a core differentiator for real CMM.

2. **Malware Engine** (2 weak, 3 missing) — Static hardcoded list vs cloud-based
   daily-updated database with real-time monitoring. The most dangerous gap
   because it gives users false confidence in malware protection.

3. **Space Lens** (2 weak, 1 missing) — Flat list vs interactive sunburst
   visualization. This is the most visually distinctive CMM feature.

4. **System Junk** (4 missing) — Language Files, Universal Binaries, iOS
   Backups, Document Versions. These can reclaim significant space (1-5 GB).

5. **Updater** (4 missing) — No Sparkle, no macOS updates, no auto-update.
   Can detect outdated apps but cannot update them.

6. **Similar Images** (1 weak) — Dimensions+size vs perceptual hashing.
   Will produce false positives (same-size, same-dimension but different photos).

7. **My Activity** (3 missing) — No cleaning history, no health score, no
   recommendations.

8. **Login/Background Items** (3 missing) — Cannot toggle login items or
   kill background processes.

---

## What This App Does Well

- **Safety**: After the audit fixes, the protection system (PROTECTED_PATHS,
  _is_protected with child-path protection, _delete_dir_contents) is actually
  MORE conservative than real CMM — it refuses to touch system cache/logs,
  mail containers, and app data directories that real CMM will clean.

- **System Junk coverage**: User cache, user logs, Xcode junk, and app-specific
  caches (Adobe, Spotify, Photos) are well-covered.

- **Maintenance tasks**: All 8 maintenance commands match real CMM.

- **Privacy**: Browser history/cookies/cache cleaning matches for all 3 browsers.

- **Uninstaller**: Bundle ID-based leftover detection is precise and safe.

- **Duplicate Finder**: SHA-256 hash-based detection is reliable.

- **Shredder**: 3-pass + zeros with path validation and permission checks.