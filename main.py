"""
main.py -- CleanMyMac-but-Free
Open-source clone of CleanMyMac 5, built with Python + tkinter.

Architecture maps to CleanMyMac's framework structure:
  SmartCareModule → Smart Care tab
  JunkCleanupModule → Cleanup tab (System Junk, Mail, Trash, Downloads, Disk Images)
  ProtectionModule → Protection tab (Malware, Privacy)
  PerformanceModule → Performance tab (Login Items, Background, Maintenance)
  ApplicationsModule → Applications tab (Uninstaller, Updater, Extensions)
  OrganizeModule → Organize tab (Space Lens, LAOF, Duplicates, Similar, Shredder)
  CloudStorageModule → Cloud tab
"""
import os
import sys
import json
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime
import shutil

# Ensure local imports work
sys.path.insert(0, str(Path(__file__).parent))

from scanners import (
    ScanItem, ScanResult,
    scan_system_junk, scan_mail_attachments, scan_trash_bins,
    scan_downloads, scan_unused_disk_images,
    scan_privacy, scan_malware,
    scan_login_items, scan_background_items, run_maintenance_task,
    scan_installed_apps, find_app_leftovers, uninstall_app,
    scan_app_updates, scan_space_lens,
    scan_large_old_files, scan_duplicates, scan_similar_images,
    scan_cloud_storage, scan_extensions,
    smart_scan, clean_items, shred_file,
    add_exclusion, load_exclusions,
)
from utils import human_size, expand
from scheduler import INTERVALS, get_schedule, create_schedule, remove_schedule

# ─── Colors (refined dark theme — muted, professional) ───
# Backgrounds: warm-tinted dark neutrals (not pure navy)
BG = "#1c1c1e"        # main content area
BG2 = "#242426"       # sidebar / status bar
BG3 = "#2c2c2e"       # active / header surfaces
# Borders / dividers
BORDER = "#3a3a3c"    # subtle separator
BORDER_SOFT = "#2e2e30"
# Text
FG = "#e5e5e7"        # primary text (slightly warm white)
FG2 = "#8e8e93"       # secondary / muted text
# Accents — desaturated for a calmer, intentional feel
ACCENT = "#34c759"    # primary action (Scan) — system green, not neon teal
ACCENT2 = "#ff3b30"   # destructive action (Clean) — system red
ACCENT_DIM = "#2d5a3d"  # accent-tinted surface for active sidebar item
WARN = "#ff9500"       # warnings
# Surfaces
CARD = "#2c2c2e"
ENTRY_BG = "#1c1c1e"   # table / log background (slightly darker than sidebar)


class LabelButton(tk.Label):
    """A Label that behaves like a Button — needed because tk.Button on macOS
    ignores custom bg colors. Label honors bg, so we use it + click binding.
    Supports: hover colors, disabled state, command callback."""
    def __init__(self, parent, text="", command=None, bg=None, fg=None,
                 hover_bg=None, hover_fg=None, disabled_fg=None,
                 font=None, padx=10, pady=5, cursor="hand2", anchor="center",
                 **kwargs):
        self._cmd = command
        self._bg = bg or parent.cget("bg")
        self._fg = fg
        self._hover_bg = hover_bg
        self._hover_fg = hover_fg
        self._disabled_fg = disabled_fg or fg
        self._enabled = True
        super().__init__(parent, text=text, bg=self._bg, fg=self._fg,
                        font=font, padx=padx, pady=pady, cursor=cursor,
                        anchor=anchor, **kwargs)
        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_click(self, event):
        if self._enabled and self._cmd:
            self._cmd()

    def _on_enter(self, event):
        if self._enabled and self._hover_bg:
            self.configure(bg=self._hover_bg)
        if self._enabled and self._hover_fg:
            self.configure(fg=self._hover_fg)

    def _on_leave(self, event):
        if self._enabled:
            self.configure(bg=self._bg, fg=self._fg)

    def config(self, **kwargs):
        # Map state-related config to our properties
        if "state" in kwargs:
            state = kwargs.pop("state")
            self._enabled = state == "normal"
            super().configure(fg=self._fg if self._enabled else self._disabled_fg)
            super().configure(cursor="hand2" if self._enabled else "arrow")
        if "bg" in kwargs:
            self._bg = kwargs.pop("bg")
            super().configure(bg=self._bg)
        if "fg" in kwargs:
            self._fg = kwargs.pop("fg")
            if self._enabled:
                super().configure(fg=self._fg)
        if "hover_bg" in kwargs:
            self._hover_bg = kwargs.pop("hover_bg")
        if "hover_fg" in kwargs:
            self._hover_fg = kwargs.pop("hover_fg")
        if "disabled_fg" in kwargs:
            self._disabled_fg = kwargs.pop("disabled_fg")
        if "text" in kwargs:
            super().configure(text=kwargs.pop("text"))
        if "command" in kwargs:
            self._cmd = kwargs.pop("command")
        # Pass remaining to Label
        if kwargs:
            super().configure(**kwargs)

    def configure(self, **kwargs):
        self.config(**kwargs)


MODULES = [
    ("Smart Care",       "smart",     "🧹"),
    ("Cleanup",          "cleanup",   "🗑"),
    ("Protection",       "protection","🛡"),
    ("Performance",      "perf",      "⚡"),
    ("Applications",     "apps",      "📦"),
    ("Organize",         "organize",  "🗂"),
    ("Cloud Cleanup",    "cloud",     "☁"),
]

# Sub-modules per tab
SUBMODULES = {
    "smart":     [("Smart Scan", "smart_scan")],
    "cleanup":   [("System Junk", "system_junk"), ("Mail Attachments", "mail"),
                   ("Trash Bins", "trash"), ("Downloads", "downloads"),
                   ("Unused Disk Images", "disk_images")],
    "protection":[("Malware Scan", "malware"), ("Privacy", "privacy")],
    "perf":      [("Login Items", "login_items"), ("Background Items", "background"),
                   ("Maintenance", "maintenance")],
    "apps":      [("Uninstaller", "uninstaller"), ("App Updater", "updater"),
                   ("Extensions", "extensions")],
    "organize":  [("Space Lens", "space_lens"), ("Large & Old Files", "laof"),
                   ("Duplicate Finder", "duplicates"), ("Similar Images", "similar"),
                   ("Shredder", "shredder")],
    "cloud":     [("Cloud Storage", "cloud")],
}

# Maintenance task list
MAINTENANCE_TASKS = [
    "Free up RAM",
    "Flush DNS Cache",
    "Reindex Spotlight",
    "Repair Disk Permissions",
    "Run Maintenance Scripts",
    "Free Up Purgeable Space",
    "Speed Up Mail",
    "Thin Time Machine Snapshots",
]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CleanMyMac-but-Free")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(bg=BG)

        self.current_module = "smart"
        self.current_submodule = "smart_scan"
        self.scan_results: dict[str, ScanResult] = {}
        self.smart_results: dict[str, ScanResult] = {}
        self.scanning = False
        self._cancel_scan = False
        self.maint_vars = {}

        self._build_ui()
        self.log("Ready. Select a module and click Scan.")

    def _build_ui(self):
        # ─── Top bar ───
        top = tk.Frame(self, bg=BG2, height=46)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)

        tk.Label(top, text="  CleanMyMac-but-Free", fg=FG, bg=BG2,
                 font=("SF Pro Display", 14)).pack(side="left", padx=(8, 0))

        # Disk usage gauge
        self.disk_frame = tk.Frame(top, bg=BG2)
        self.disk_frame.pack(side="left", padx=(20, 0), pady=8)
        self.disk_label = tk.Label(self.disk_frame, text="", fg=FG2, bg=BG2,
                                   font=("SF Pro", 9), anchor="w")
        self.disk_label.pack(side="left", padx=(0, 8))
        self.disk_bar = ttk.Progressbar(self.disk_frame, orient="horizontal",
                                        length=120, mode="determinate")
        self.disk_bar.pack(side="left")
        self._update_disk_usage()

        self.scan_btn = LabelButton(top, text="Scan", command=self.on_scan,
                                    bg=ACCENT, fg="#ffffff", font=("SF Pro", 12),
                                    padx=22, pady=7, hover_bg="#2db84e",
                                    hover_fg="#ffffff")
        self.scan_btn.pack(side="right", padx=(0, 12), pady=8)

        self.cancel_btn = LabelButton(top, text="Cancel", command=self.on_cancel_scan,
                                      bg=ACCENT2, fg="#ffffff", font=("SF Pro", 12),
                                      padx=16, pady=7, hover_bg="#cc2f26",
                                      hover_fg="#ffffff", disabled_fg="#666666")
        self.cancel_btn.config(state="disabled")
        self.cancel_btn.pack(side="right", padx=5, pady=8)

        self.clean_btn = LabelButton(top, text="Clean", command=self.on_clean,
                                     bg=BG3, fg=FG2, font=("SF Pro", 12),
                                     padx=22, pady=7, hover_bg=BG3, hover_fg=ACCENT2,
                                     disabled_fg=FG2)
        self.clean_btn.config(state="disabled")
        self.clean_btn.pack(side="right", padx=5, pady=8)

        # Schedule button (gear icon)
        self.schedule_btn = LabelButton(top, text="⏰", command=self.show_schedule_dialog,
                                        bg=BG3, fg=FG2, font=("SF Pro", 14),
                                        padx=10, pady=7, hover_bg=BORDER, hover_fg=ACCENT)
        self.schedule_btn.pack(side="right", padx=5, pady=8)

        # Subtle border under top bar
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", side="top")

        # ─── Main area: sidebar + content ───
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True)

        # Sidebar
        sidebar = tk.Frame(main, bg=BG2, width=210)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="", bg=BG2).pack(pady=4)
        for name, key, icon in MODULES:
            btn = LabelButton(sidebar, text=f"  {icon}  {name}", anchor="w",
                          bg=BG2, fg=FG2, font=("SF Pro", 11),
                          padx=15, pady=9, width=18,
                          hover_bg=BG3, hover_fg=FG,
                          command=lambda k=key: self.select_module(k))
            btn.pack(fill="x", padx=4, pady=3)
            setattr(self, f"btn_{key}", btn)
        self._highlight_sidebar()

        # Subtle border between sidebar and content
        tk.Frame(main, bg=BORDER, width=1).pack(side="left", fill="y")

        # Content area
        content = tk.Frame(main, bg=BG)
        content.pack(side="left", fill="both", expand=True)

        # Sub-module tabs
        self.subtab_frame = tk.Frame(content, bg=BG, height=38)
        self.subtab_frame.pack(fill="x", padx=10, pady=(4, 0))
        self._build_subtabs()

        # Separator under sub-tabs
        tk.Frame(content, bg=BORDER, height=1).pack(fill="x", padx=10)

        # Search/filter toolbar
        search_frame = tk.Frame(content, bg=BG)
        search_frame.pack(fill="x", padx=10, pady=(2, 0))
        tk.Label(search_frame, text="🔍", fg=FG2, bg=BG, font=("SF Pro", 10)).pack(side="left", padx=(2, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._filter_tree())
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                                     bg=ENTRY_BG, fg=FG, font=("SF Pro", 10),
                                     relief="flat", borderwidth=0,
                                     highlightthickness=1,
                                     highlightbackground=BORDER,
                                     highlightcolor=ACCENT)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 4), ipady=3)
        self._tree_data_cache = []  # cache all rows for filtering

        # Results table
        table_frame = tk.Frame(content, bg=BG)
        table_frame.pack(fill="both", expand=True, padx=10, pady=(6, 4))

        cols = ("sel", "path", "size", "category", "detail")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("sel", text="✓")
        self.tree.heading("path", text="Path / Name", command=lambda: self._sort_tree("path"))
        self.tree.heading("size", text="Size", command=lambda: self._sort_tree("size"))
        self.tree.heading("category", text="Type", command=lambda: self._sort_tree("category"))
        self.tree.heading("detail", text="Details", command=lambda: self._sort_tree("detail"))
        self.tree.column("sel", width=36, stretch=False, anchor="center")
        self.tree.column("path", width=340)
        self.tree.column("size", width=80, anchor="e")
        self.tree.column("category", width=110)
        self.tree.column("detail", width=280)
        self._sort_col = None
        self._sort_reverse = False

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=ENTRY_BG, fieldbackground=ENTRY_BG,
                        foreground=FG, rowheight=26, font=("SF Pro", 11),
                        borderwidth=0)
        style.configure("Treeview.Heading", background=BG3, foreground=FG2,
                        font=("SF Pro", 10), relief="flat", borderwidth=0)
        style.map("Treeview", background=[("selected", ACCENT_DIM)],
                  foreground=[("selected", FG)])
        style.map("Treeview.Heading", background=[("active", BG3)])

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<Button-2>", self.on_tree_right_click)
        self.tree.bind("<Button-3>", self.on_tree_right_click)  # some macOS setups use Button-3

        # Status bar
        tk.Frame(content, bg=BORDER, height=1).pack(fill="x", side="bottom")
        status = tk.Frame(content, bg=BG2, height=28)
        status.pack(fill="x", side="bottom")
        status.pack_propagate(False)
        self.status_label = tk.Label(status, text="  No scan results", fg=FG2, bg=BG2,
                                      font=("SF Pro", 10), anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True)
        self.scan_progress = ttk.Progressbar(status, orient="horizontal",
                                               length=120, mode="determinate")
        self.scan_progress.pack(side="right", padx=(0, 8))
        self.dry_run_var = tk.BooleanVar(value=False)
        self.dry_run_cb = tk.Checkbutton(status, text="Preview", variable=self.dry_run_var,
                                          bg=BG2, fg=FG2, selectcolor=BG3,
                                          activebackground=BG2, activeforeground=FG,
                                          font=("SF Pro", 9), highlightthickness=0)
        self.dry_run_cb.pack(side="right", padx=(0, 8))

        # Log area (collapsible)
        self.log_frame = tk.Frame(content, bg=BG, height=110)
        self.log_frame.pack(fill="x", side="bottom", padx=10, pady=(0, 4))
        self.log_frame.pack_propagate(False)

        tk.Label(self.log_frame, text=" Log", fg=FG2, bg=BG, font=("SF Pro", 9)).pack(anchor="w")
        self.log_text = tk.Text(self.log_frame, bg=ENTRY_BG, fg=FG2, font=("Menlo", 9),
                                height=5, relief="flat", wrap="word",
                                borderwidth=0, highlightthickness=0)
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")

        # Maintenance panel (hidden by default)
        self.maint_panel = None

    def _highlight_sidebar(self):
        for _, key, _ in MODULES:
            btn = getattr(self, f"btn_{key}", None)
            if btn:
                btn.config(bg=BG2, fg=FG2, hover_bg=BG3, hover_fg=FG)
        btn = getattr(self, f"btn_{self.current_module}", None)
        if btn:
            btn.config(bg=ACCENT_DIM, fg=ACCENT, hover_bg=ACCENT_DIM, hover_fg=ACCENT)

    def _build_subtabs(self):
        for w in self.subtab_frame.winfo_children():
            w.destroy()
        subs = SUBMODULES.get(self.current_module, [])
        for name, key in subs:
            is_active = key == self.current_submodule
            btn = LabelButton(self.subtab_frame, text=name,
                          bg=BG, fg=ACCENT if is_active else FG2,
                          font=("SF Pro", 10, "normal" if not is_active else "bold"),
                          padx=14, pady=7,
                          hover_bg=BG, hover_fg=ACCENT if not is_active else None,
                          command=lambda k=key, n=name: self.select_submodule(k, n))
            btn.pack(side="left", padx=2, pady=5)

        # Select All / Deselect All buttons (right side of subtabs)
        btn_frame = tk.Frame(self.subtab_frame, bg=BG)
        btn_frame.pack(side="right", padx=(4, 0), pady=5)
        LabelButton(btn_frame, text="Select All", command=self.select_all,
                    bg=BG3, fg=FG, font=("SF Pro", 9), padx=8, pady=3,
                    hover_bg=BORDER, hover_fg=ACCENT).pack(side="left", padx=2)
        LabelButton(btn_frame, text="Deselect All", command=self.deselect_all,
                    bg=BG3, fg=FG2, font=("SF Pro", 9), padx=8, pady=3,
                    hover_bg=BORDER, hover_fg=ACCENT2).pack(side="left", padx=2)

    def select_module(self, key):
        self.current_module = key
        subs = SUBMODULES.get(key, [])
        if subs:
            self.current_submodule = subs[0][1]
        self._highlight_sidebar()
        self._build_subtabs()
        self.clear_results()
        # Show maintenance panel if maintenance
        self._toggle_maint_panel()

    def select_submodule(self, key, name):
        self.current_submodule = key
        self._build_subtabs()
        self.clear_results()
        self._toggle_maint_panel()

    def _toggle_maint_panel(self):
        if self.maint_panel:
            self.maint_panel.destroy()
            self.maint_panel = None
        if self.current_submodule == "maintenance":
            self.maint_panel = tk.Frame(self.subtab_frame, bg=BG)
            self.maint_panel.pack(fill="x", pady=(8, 4))
            tk.Label(self.maint_panel, text="Tasks:", fg=FG2, bg=BG,
                     font=("SF Pro", 10)).pack(side="left", padx=(5, 8))
            for task in MAINTENANCE_TASKS:
                var = tk.BooleanVar(value=False)
                self.maint_vars[task] = var
                cb = tk.Checkbutton(self.maint_panel, text=task, variable=var,
                                  bg=BG, fg=FG2, selectcolor=BG3, activebackground=BG,
                                  activeforeground=FG, font=("SF Pro", 10),
                                  highlightthickness=0)
                cb.pack(side="left", padx=4)
            LabelButton(self.maint_panel, text="Run Selected", bg=ACCENT, fg="#ffffff",
                      font=("SF Pro", 10), padx=12, pady=5,
                      hover_bg="#2db84e", hover_fg="#ffffff",
                      command=self.run_maintenance).pack(side="left", padx=10)

    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.scan_results.clear()
        self._tree_data_cache = []
        if hasattr(self, "search_var"):
            self.search_var.set("")
        self.status_label.config(text="  No scan results")
        self.clean_btn.config(state="disabled", bg=BG3, fg=FG2,
                              hover_bg=BG3, hover_fg=FG2)

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # ─── Disk usage + stats ───
    STATS_FILE = Path.home() / ".cleanmymac-free-stats.json"

    def _update_disk_usage(self):
        """Update disk usage gauge in the top bar."""
        try:
            usage = shutil.disk_usage("/")
            total_gb = usage.total / (1024**3)
            free_gb = usage.free / (1024**3)
            used_pct = (usage.used / usage.total) * 100
            self.disk_label.config(text=f"{free_gb:.0f} GB free of {total_gb:.0f} GB")
            self.disk_bar["maximum"] = 100
            self.disk_bar["value"] = used_pct
        except OSError:
            self.disk_label.config(text="Disk info unavailable")

    def _load_stats(self) -> dict:
        """Load cumulative cleaning stats from JSON file."""
        try:
            if self.STATS_FILE.exists():
                with open(self.STATS_FILE) as f:
                    return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
        return {"total_cleaned_bytes": 0, "total_sessions": 0}

    def _save_stats(self, stats: dict):
        """Save cumulative cleaning stats to JSON file."""
        try:
            with open(self.STATS_FILE, "w") as f:
                json.dump(stats, f, indent=2)
        except OSError:
            pass

    def on_cancel_scan(self):
        if self.scanning:
            self._cancel_scan = True
            self.log("Cancelling scan...")

    def on_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self._cancel_scan = False
        self.scan_btn.config(text="Scanning...", state="disabled")
        self.cancel_btn.config(state="normal")
        self.scan_progress["value"] = 0
        self.clear_results()
        self.log(f"Scanning: {self.current_submodule}")

        def cancel_check():
            return self._cancel_scan

        def worker():
            try:
                if self.current_submodule == "smart_scan":
                    # Progress: 6 modules — update bar per module
                    self.scan_progress["maximum"] = 6
                    results = smart_scan(cancel_check)
                    self.smart_results = results
                    total = sum(r.total_size for r in results.values())
                    total_items = sum(len(r.items) for r in results.values())
                    self.scan_progress["value"] = 6
                    if self._cancel_scan:
                        self.log("Scan cancelled.")
                    else:
                        self.log(f"Smart Scan complete: {total_items} items, {human_size(total)}")
                    self._display_smart_results(results)
                else:
                    # Single scanner: indeterminate bar starts, set to 50% while running
                    self.scan_progress["maximum"] = 100
                    self.scan_progress["value"] = 10
                    result = self._run_scanner(self.current_submodule, cancel_check)
                    if result:
                        self.scan_progress["value"] = 100
                        self.scan_results[self.current_submodule] = result
                        self._display_result(result)
                        if self._cancel_scan:
                            self.log(f"Scan cancelled. Found {len(result.items)} items so far.")
                        else:
                            self.log(f"Found {len(result.items)} items ({human_size(result.total_size)})")
                    else:
                        self.scan_progress["value"] = 0
                        if self._cancel_scan:
                            self.log("Scan cancelled.")
                        else:
                            self.log("No scanner for this submodule or no results.")
            except Exception as e:
                self.log(f"Error: {e}")
            finally:
                self.scanning = False
                self.scan_btn.config(text="Scan", state="normal")
                self.cancel_btn.config(state="disabled")
                self.scan_progress["value"] = 0

        threading.Thread(target=worker, daemon=True).start()

    def _run_scanner(self, key, cancel_check=None):
        """Run scanner by sub-module key. Returns ScanResult or None."""
        scanners = {
            "system_junk": scan_system_junk,
            "mail": scan_mail_attachments,
            "trash": scan_trash_bins,
            "downloads": scan_downloads,
            "disk_images": scan_unused_disk_images,
            "privacy": scan_privacy,
            "malware": scan_malware,
            "login_items": scan_login_items,
            "background": scan_background_items,
            "uninstaller": scan_installed_apps,
            "updater": scan_app_updates,
            "extensions": scan_extensions,
            "space_lens": lambda: scan_space_lens("~", cancel_check=cancel_check),
            "laof": lambda: scan_large_old_files(cancel_check=cancel_check),
            "duplicates": lambda: scan_duplicates("~", min_size_mb=1, cancel_check=cancel_check),
            "similar": lambda: scan_similar_images("~", cancel_check=cancel_check),
            "cloud": scan_cloud_storage,
        }
        fn = scanners.get(key)
        if fn:
            # Pass cancel_check to scanners that accept it
            import inspect
            try:
                sig = inspect.signature(fn)
                if "cancel_check" in sig.parameters:
                    return fn(cancel_check=cancel_check)
            except (ValueError, TypeError):
                pass
            return fn()
        return None

    def _display_result(self, result: ScanResult):
        self.tree.delete(*self.tree.get_children())
        self.search_var.set("")
        self._tree_data_cache = []
        for item in result.items:
            sel = "✓" if item.selected else ""
            sz = human_size(item.size) if item.size > 0 else "—"
            vals = (sel, item.path, sz, item.category, item.detail)
            tags = ("removable" if item.removable else "info",)
            self.tree.insert("", "end", values=vals, tags=tags)
            self._tree_data_cache.append((vals, tags))
        self.tree.tag_configure("removable", foreground=FG)
        self.tree.tag_configure("info", foreground=FG2)
        if result.items:
            self.status_label.config(text=f"  {len(result.items)} items found — {human_size(result.total_size)}")
            self.clean_btn.config(state="normal", bg=BG3, fg=ACCENT2,
                                  hover_bg=BG3, hover_fg="#ff6961")
        else:
            self.status_label.config(text="  Nothing found. Your Mac is clean!")
            self.clean_btn.config(state="disabled", bg=BG3, fg=FG2,
                                  hover_bg=BG3, hover_fg=FG2)

    def _display_smart_results(self, results: dict[str, ScanResult]):
        self.tree.delete(*self.tree.get_children())
        self.search_var.set("")
        self._tree_data_cache = []
        total_items = 0
        total_size = 0
        for mod_name, result in results.items():
            if not result.items:
                continue
            # Module header row
            hdr_vals = ("", f"── {mod_name} ──", "", "", "")
            hdr_tags = ("header",)
            self.tree.insert("", "end", values=hdr_vals, tags=hdr_tags)
            self._tree_data_cache.append((hdr_vals, hdr_tags))
            for item in result.items:
                sel = "✓" if item.selected else ""
                sz = human_size(item.size) if item.size > 0 else "—"
                vals = (sel, item.path, sz, item.category, item.detail)
                tags = ("removable" if item.removable else "info",)
                self.tree.insert("", "end", values=vals, tags=tags)
                self._tree_data_cache.append((vals, tags))
                total_items += 1
                total_size += item.size
        self.tree.tag_configure("header", foreground=ACCENT, background=BG3)
        self.tree.tag_configure("removable", foreground=FG)
        self.tree.tag_configure("info", foreground=FG2)
        if total_items:
            self.status_label.config(text=f"  Smart Scan: {total_items} items — {human_size(total_size)}")
            self.clean_btn.config(state="normal", bg=BG3, fg=ACCENT2,
                                  hover_bg=BG3, hover_fg="#ff6961")
        else:
            self.status_label.config(text="  Your Mac is clean!")
            self.clean_btn.config(state="disabled", bg=BG3, fg=FG2,
                                  hover_bg=BG3, hover_fg=FG2)

    def on_tree_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        col = self.tree.identify_column(event.x)
        if col != "#1":  # Only toggle on checkbox column
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        vals = self.tree.item(item, "values")
        tags = self.tree.item(item, "tags")
        if "header" in tags or "info" in tags:
            return
        current = vals[0] == "✓"
        new_val = "" if current else "✓"
        self.tree.item(item, values=(new_val, vals[1], vals[2], vals[3], vals[4]))

    def on_tree_right_click(self, event):
        """Show context menu on right-click."""
        item = self.tree.identify_row(event.y)
        if not item:
            return
        # Select the row under cursor
        self.tree.selection_set(item)
        vals = self.tree.item(item, "values")
        tags = self.tree.item(item, "tags")
        if "header" in tags:
            return
        path_str = vals[1] if len(vals) > 1 else ""
        # Skip virtual paths
        is_virtual = path_str in {"login-item", "brew-cask", "brew-outdated",
                                  "mas-outdated", "configuration-profile", "background-process"}
        is_real_path = path_str.startswith("/") or path_str.startswith("~")

        menu = tk.Menu(self, tearoff=0, bg=BG3, fg=FG, activebackground=ACCENT_DIM,
                       activeforeground=FG, borderwidth=0, relief="flat")
        menu.add_command(label="Reveal in Finder", command=lambda: self._reveal_in_finder(path_str))
        menu.add_command(label="Copy Path", command=lambda: self._copy_path(path_str))
        if is_real_path and not is_virtual:
            menu.add_separator()
            menu.add_command(label="Move to Trash", command=lambda: self._move_to_trash(path_str))
            menu.add_command(label="Exclude from Scans", command=lambda: self._exclude_path(path_str))
        menu.tk_popup(event.x_root, event.y_root)

    def _reveal_in_finder(self, path_str):
        """Reveal a file/folder in Finder."""
        p = Path(path_str).expanduser()
        if not p.exists():
            self.log(f"Path not found: {path_str}")
            return
        subprocess.Popen(["open", "-R", str(p)])
        self.log(f"Revealed in Finder: {p.name}")

    def _copy_path(self, path_str):
        """Copy path to clipboard."""
        self.clipboard_clear()
        self.clipboard_append(path_str)
        self.update()  # keep clipboard after window closes
        self.log(f"Copied: {path_str}")

    def _move_to_trash(self, path_str):
        """Move a file/folder to Trash instead of deleting immediately."""
        from scanners import _is_protected
        p = Path(path_str).expanduser()
        if not p.exists():
            self.log(f"Path not found: {path_str}")
            return
        # SAFETY: refuse to move symlinks. _is_protected() resolves symlinks
        # (checks the target), so a symlink inside a protected dir would pass
        # the check based on its target rather than its own location. Moving
        # the symlink itself doesn't destroy target data, but the protection
        # semantics are wrong for symlinks — refuse and direct user to Finder.
        if p.is_symlink():
            self.log(f"Refused: {p} is a symlink — use Finder to move to Trash")
            return
        if _is_protected(p):
            self.log(f"Refused: {p} is protected")
            return
        trash = Path.home() / ".Trash"
        # SAFETY helper for name-collision-safe destination selection.
        def _trash_dest(name: str) -> Path:
            d = trash / name
            if d.exists():
                d = trash / f"{name}_{datetime.now().strftime('%H%M%S')}"
            return d
        try:
            if p.is_dir() and not p.is_symlink():
                # Move entire dir to trash.
                # SAFETY: Do NOT use shutil.move() for directories — on a
                # cross-filesystem move it internally falls back to
                # shutil.copytree(symlinks=True) + shutil.rmtree(src). On
                # Python <3.12, rmtree FOLLOWS symlinks inside the source
                # directory and would delete the target's contents (e.g. a
                # symlink inside the dir pointing to ~/Documents). That
                # bypasses every _delete_dir_contents() safety check the
                # project established to prevent exactly this. Instead:
                #   1. Try os.rename for a same-filesystem atomic move.
                #   2. On cross-filesystem (OSError EXDEV/ENODEV), copy the
                #      tree preserving symlinks (symlinks=True so the link
                #      itself is copied, not its target), then remove the
                #      source via _delete_dir_contents() + rmdir() which
                #      checks is_symlink() and _is_protected() on every
                #      nested entry — never following a symlink.
                dest = _trash_dest(p.name)
                try:
                    os.rename(str(p), str(dest))
                except OSError:
                    # Cross-filesystem (EXDEV) or other rename failure —
                    # copy then safe-remove source.
                    from scanners import _delete_dir_contents
                    shutil.copytree(str(p), str(dest), symlinks=True)
                    removed, errors = _delete_dir_contents(p)
                    try:
                        p.rmdir()  # remove now-empty source dir shell
                    except OSError:
                        pass
                    if errors:
                        self.log(f"  ⚠ {len(errors)} errors clearing source: {errors[0]}")
            else:
                # File (symlinks already refused above).
                dest = _trash_dest(p.name)
                # os.rename is atomic on same filesystem; shutil.move handles
                # cross-filesystem for single files without rmtree, so it is
                # safe here (rmtree only happens for directory moves).
                try:
                    os.rename(str(p), str(dest))
                except OSError:
                    shutil.move(str(p), str(dest))
            self.log(f"Moved to Trash: {p.name}")
            # Re-scan to update results
            self.on_scan()
        except (OSError, shutil.Error) as e:
            self.log(f"Failed to move to Trash: {e}")

    def _exclude_path(self, path_str):
        """Add a path to the exclusion list so it's skipped in future scans."""
        add_exclusion(path_str)
        self.log(f"Excluded from future scans: {path_str}")
        # Remove from current tree view
        for item in self.tree.get_children():
            vals = self.tree.item(item, "values")
            tags = self.tree.item(item, "tags")
            if "header" in tags:
                continue
            if vals[1] == path_str:
                self.tree.delete(item)
                break
        # Update cache too
        self._tree_data_cache = [(v, t) for v, t in self._tree_data_cache if v[1] != path_str]

    def _show_exclusions(self):
        """Show current exclusion list."""
        exclusions = load_exclusions()
        if not exclusions:
            self.log("No exclusions configured.")
            return
        self.log(f"Exclusion list ({len(exclusions)} items):")
        for ex in exclusions:
            self.log(f"  • {ex}")

    def select_all(self):
        """Check all removable items in the tree."""
        for item in self.tree.get_children():
            tags = self.tree.item(item, "tags")
            if "header" in tags:
                continue
            vals = self.tree.item(item, "values")
            if "info" in tags:
                continue
            # Only select removable items
            self.tree.item(item, values=("✓", vals[1], vals[2], vals[3], vals[4]))
        self.log("Selected all removable items.")

    def deselect_all(self):
        """Uncheck all items in the tree."""
        for item in self.tree.get_children():
            tags = self.tree.item(item, "tags")
            if "header" in tags:
                continue
            vals = self.tree.item(item, "values")
            self.tree.item(item, values=("", vals[1], vals[2], vals[3], vals[4]))
        self.log("Deselected all items.")

    def _filter_tree(self):
        """Filter tree rows by search text. Matches path, category, detail."""
        query = self.search_var.get().lower().strip()
        self.tree.delete(*self.tree.get_children())
        if not query:
            # No filter — restore all
            for vals, tags in self._tree_data_cache:
                self.tree.insert("", "end", values=vals, tags=tags)
        else:
            # Filter: keep headers + matching rows
            for vals, tags in self._tree_data_cache:
                if "header" in tags:
                    continue  # skip headers during filtered view
                # Search in path (vals[1]), category (vals[3]), detail (vals[4])
                searchable = f"{vals[1]} {vals[3]} {vals[4]}".lower()
                if query in searchable:
                    self.tree.insert("", "end", values=vals, tags=tags)
            # Update count in status
            shown = len(self.tree.get_children())
            self.status_label.config(text=f"  {shown} matching items (filtered)")
        self.tree.tag_configure("header", foreground=ACCENT, background=BG3)
        self.tree.tag_configure("removable", foreground=FG)
        self.tree.tag_configure("info", foreground=FG2)

    def _sort_tree(self, col):
        """Sort tree by column. Toggle ascending/descending on repeated clicks."""
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False

        items = list(self.tree.get_children())
        # Separate header rows from data rows; save values+tags before delete
        headers = []
        data = []
        for item in items:
            tags = self.tree.item(item, "tags")
            vals = self.tree.item(item, "values")
            if "header" in tags:
                headers.append((vals, tags))
            else:
                data.append((vals, tags))

        # Sort key: for "size" column, parse the human_size string back to bytes
        if col == "size":
            def sort_key(entry):
                vals = entry[0]
                sz_str = vals[2] if len(vals) > 2 else "0"
                if sz_str == "—" or not sz_str:
                    return 0
                try:
                    parts = sz_str.split()
                    num = float(parts[0])
                    unit = parts[1] if len(parts) > 1 else "B"
                    multipliers = {"B": 1, "KB": 1024, "MB": 1024**2,
                                   "GB": 1024**3, "TB": 1024**4, "PB": 1024**5}
                    return num * multipliers.get(unit, 1)
                except (ValueError, IndexError):
                    return 0
        else:
            col_idx = {"path": 1, "category": 3, "detail": 4}.get(col, 1)
            def sort_key(entry):
                vals = entry[0]
                return str(vals[col_idx]).lower() if len(vals) > col_idx else ""

        data.sort(key=sort_key, reverse=self._sort_reverse)

        self.tree.delete(*self.tree.get_children())
        if not headers:
            for vals, tags in data:
                self.tree.insert("", "end", values=vals, tags=tags)
        else:
            # Smart scan: reinsert headers + sorted data (mixed but functional)
            for vals, tags in data:
                self.tree.insert("", "end", values=vals, tags=tags)

    def on_clean(self):
        if self.current_submodule == "smart_scan":
            items_to_clean = []
            # Read checkbox state from tree (user may have unchecked items)
            tree_children = self.tree.get_children()
            for result in self.smart_results.values():
                for item in result.items:
                    if not item.removable:
                        continue
                    # SAFETY: Default to deselected. Only select if the tree
                    # row is found AND its checkbox is checked. Never carry
                    # over the original ScanResult.selected value — the user
                    # may have unchecked items in the UI.
                    item.selected = False
                    for child in tree_children:
                        vals = self.tree.item(child, "values")
                        tags = self.tree.item(child, "tags")
                        if "header" in tags:
                            continue
                        if vals[1] == item.path:
                            item.selected = vals[0] == "✓"
                            break
                    if item.selected:
                        items_to_clean.append(item)
        elif self.current_submodule == "shredder":
            # File picker for shredder
            files = filedialog.askopenfilenames(title="Select files to shred")
            if not files:
                return
            self.log(f"Shredding {len(files)} file(s)...")
            for f in files:
                ok, msg = shred_file(f)
                self.log(msg)
            return
        elif self.current_submodule == "uninstaller":
            sel = self.tree.selection()
            if not sel:
                return
            items = [self.tree.item(s, "values") for s in sel]
            for vals in items:
                app_path = vals[1]
                if app_path.endswith(".app"):
                    self.log(f"Uninstalling {Path(app_path).name}...")
                    count, msgs = uninstall_app(app_path)
                    for m in msgs:
                        self.log(m)
                    self.log(f"Done. Removed {count} items.")
            self.clear_results()
            return
        else:
            result = self.scan_results.get(self.current_submodule)
            if not result:
                return
            # Read checkbox state from tree
            items_to_clean = []
            for item in result.items:
                # SAFETY: Default to deselected. Only select if the tree
                # row is found AND its checkbox is checked. Never carry
                # over the original ScanResult.selected value — the user
                # may have unchecked items in the UI. This matches the
                # smart_scan path's behavior.
                item.selected = False
                # Find corresponding tree row
                for child in self.tree.get_children():
                    vals = self.tree.item(child, "values")
                    if vals[1] == item.path:
                        item.selected = vals[0] == "✓"
                        break
                if item.selected and item.removable:
                    items_to_clean.append(item)

        if not items_to_clean:
            self.log("Nothing selected for removal.")
            return

        # Dry-run / Preview mode: log what would be deleted, don't actually delete
        if self.dry_run_var.get():
            total_bytes = sum(item.size for item in items_to_clean)
            self.log(f"📋 PREVIEW (dry-run) — {len(items_to_clean)} items, {human_size(total_bytes)} would be freed:")
            for item in items_to_clean:
                sz = human_size(item.size) if item.size > 0 else "—"
                self.log(f"  [{item.category}] {item.path} ({sz})")
            self.log("Uncheck 'Preview' and click Clean again to actually delete.")
            return

        self.log(f"Cleaning {len(items_to_clean)} items...")
        self.clean_btn.config(state="disabled", bg=BG3, fg=FG2,
                              hover_bg=BG3, hover_fg=FG2)

        def worker():
            deleted, failed, errors = clean_items(items_to_clean, progress_cb=lambda d, t: self.log(f"  {d}/{t}..."))
            self.log(f"Cleanup complete: {deleted} removed, {failed} failed")
            for err in errors:
                self.log(f"  ⚠ {err}")
            # Update cumulative stats
            cleaned_bytes = sum(item.size for item in items_to_clean)
            stats = self._load_stats()
            stats["total_cleaned_bytes"] = stats.get("total_cleaned_bytes", 0) + cleaned_bytes
            stats["total_sessions"] = stats.get("total_sessions", 0) + 1
            self._save_stats(stats)
            total_cleaned = stats["total_cleaned_bytes"]
            self.log(f"📊 Total freed across all sessions: {human_size(total_cleaned)}")
            # Refresh disk gauge + re-scan
            self._update_disk_usage()
            self.on_scan()

        threading.Thread(target=worker, daemon=True).start()

    def show_schedule_dialog(self):
        """Show schedule configuration dialog."""
        dialog = tk.Toplevel(self)
        dialog.title("Schedule Auto-Scan")
        dialog.geometry("400x300")
        dialog.configure(bg=BG)
        dialog.transient(self)
        dialog.grab_set()

        tk.Label(dialog, text="Scheduled Auto-Scan", fg=FG, bg=BG,
                 font=("SF Pro Display", 14)).pack(pady=(16, 8))

        # Current schedule status
        current = get_schedule()
        status_text = "No schedule active" if not current.get("installed") else \
                      f"Active: {current.get('label', 'Unknown')} (every {current.get('schedule', '?')})"
        self._schedule_status = tk.Label(dialog, text=status_text, fg=FG2, bg=BG,
                                          font=("SF Pro", 10))
        self._schedule_status.pack(pady=(4, 12))

        # Interval selection
        tk.Label(dialog, text="Choose interval:", fg=FG2, bg=BG,
                 font=("SF Pro", 10)).pack(pady=(4, 4))
        btn_frame = tk.Frame(dialog, bg=BG)
        btn_frame.pack(pady=8)
        for key, info in INTERVALS.items():
            LabelButton(btn_frame, text=info["label"],
                        bg=BG3, fg=FG, font=("SF Pro", 11), padx=16, pady=6,
                        hover_bg=ACCENT_DIM, hover_fg=ACCENT,
                        command=lambda k=key: self._set_schedule(k, dialog)).pack(side="left", padx=6)

        # Remove schedule button
        LabelButton(dialog, text="Remove Schedule", bg=ACCENT2, fg="#ffffff",
                    font=("SF Pro", 10), padx=14, pady=5,
                    hover_bg="#cc2f26", hover_fg="#ffffff",
                    command=lambda: self._remove_schedule(dialog)).pack(pady=(16, 8))

        # Close button
        LabelButton(dialog, text="Close", bg=BG3, fg=FG2, font=("SF Pro", 10),
                    padx=14, pady=5, hover_bg=BORDER, hover_fg=FG,
                    command=dialog.destroy).pack(pady=(4, 8))

    def _set_schedule(self, interval_key, dialog):
        ok, msg = create_schedule(interval_key)
        self.log(f"⏰ {msg}")
        # Update status label
        current = get_schedule()
        status_text = "No schedule active" if not current.get("installed") else \
                      f"Active: {current.get('label', 'Unknown')} (every {current.get('schedule', '?')})"
        self._schedule_status.config(text=status_text)

    def _remove_schedule(self, dialog):
        ok, msg = remove_schedule()
        self.log(f"⏰ {msg}")
        self._schedule_status.config(text="No schedule active")

    def run_maintenance(self):
        selected = [task for task, var in self.maint_vars.items() if var.get()]
        if not selected:
            self.log("No maintenance tasks selected.")
            return
        self.log(f"Running {len(selected)} maintenance task(s)...")

        def worker():
            for task in selected:
                self.log(f"  Running: {task}...")
                ok, msg = run_maintenance_task(task)
                self.log(f"  {'✓' if ok else '✗'} {msg}")
        threading.Thread(target=worker, daemon=True).start()


def run_headless(args):
    """Run scan/clean without GUI. Used by scheduled tasks.

    SAFETY: Headless mode auto-cleans with no UI confirmation gate, so we add
    defense-in-depth checks independent of the scanner's removable flags:
      1. Log every path that will be deleted BEFORE clean_items runs.
      2. Explicitly refuse any item whose path resolves under a PROTECTED
         path, even if the scanner marked it removable=True. This catches a
         future scanner change that mistakenly flags user data as junk.
    """
    from scanners import clean_items, ScanItem, _is_protected
    print(f"[{datetime.now()}] Headless mode started")
    if args.clean_system_junk:
        print("Scanning system junk...")
        result = scan_system_junk()
        items = [item for item in result.items if item.removable]
        # Defense-in-depth: refuse to headlessly delete any protected path.
        safe_items = []
        for item in items:
            try:
                if _is_protected(Path(item.path)):
                    print(f"  REFUSED (protected): {item.path}")
                    continue
            except (OSError, RuntimeError) as e:
                print(f"  SKIP (unresolvable path: {e}): {item.path}")
                continue
            print(f"Will delete: {item.path}")
            item.selected = True
            safe_items.append(item)
        print(f"Found {len(items)} removable items ({human_size(result.total_size)}); "
              f"{len(safe_items)} passed protection check")
        if safe_items:
            deleted, failed, errors = clean_items(safe_items)
            print(f"Cleaned {deleted} items, {failed} failed")
            for err in errors:
                print(f"  ⚠ {err}")
    print(f"[{datetime.now()}] Headless mode complete")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CleanMyMac-but-Free")
    parser.add_argument("--headless", action="store_true", help="Run without GUI (for scheduled tasks)")
    parser.add_argument("--clean-system-junk", action="store_true", help="Scan and clean system junk (headless mode)")
    args = parser.parse_args()

    if args.headless:
        run_headless(args)
    else:
        app = App()
        app.mainloop()