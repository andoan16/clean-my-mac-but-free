# CleanMyMac-but-Free

An open-source clone of CleanMyMac, built with Python + tkinter.

## What it does

Reverse-engineered from CleanMyMac 5.5.7 (com.macpaw.CleanMyMac-mas). All 7 modules
with 20+ individual tools, matching the original's feature set:

1. **Smart Care** -- one-click scan combining junk + malware + performance + apps
2. **Cleanup** -- System Junk, Mail Attachments, Trash Bins, Downloads, Unused Disk Images
3. **Protection** -- Malware scan (YARA-style rules), Privacy (browser history/cookies/recent items)
4. **Performance** -- Login Items, Background Items, Maintenance (RAM, DNS, Spotlight, permissions, TM snapshots)
5. **Applications** -- Uninstaller (+ leftovers), App Updater, Extensions manager
6. **Organize** -- Space Lens (drive visualizer), Large & Old Files, Shredder (secure delete), Duplicate Finder, Similar Images
7. **Cloud Cleanup** -- iCloud / Dropbox / Google Drive storage management

## Requirements

- macOS 11.0+
- Python 3.9+
- No third-party dependencies (stdlib only)

## Run

```bash
python3 main.py
```

Some maintenance/malware/shredder operations require sudo and will prompt via
osascript. The app never deletes without showing you what it found first.

## License

MIT