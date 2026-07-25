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
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime

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
)
from utils import human_size, expand

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

        self.scan_btn = LabelButton(top, text="Scan", command=self.on_scan,
                                    bg=ACCENT, fg="#ffffff", font=("SF Pro", 12),
                                    padx=22, pady=7, hover_bg="#2db84e",
                                    hover_fg="#ffffff")
        self.scan_btn.pack(side="right", padx=(0, 12), pady=8)

        self.clean_btn = LabelButton(top, text="Clean", command=self.on_clean,
                                     bg=BG3, fg=FG2, font=("SF Pro", 12),
                                     padx=22, pady=7, hover_bg=BG3, hover_fg=ACCENT2,
                                     disabled_fg=FG2)
        self.clean_btn.config(state="disabled")
        self.clean_btn.pack(side="right", padx=5, pady=8)

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

        # Results table
        table_frame = tk.Frame(content, bg=BG)
        table_frame.pack(fill="both", expand=True, padx=10, pady=(6, 4))

        cols = ("sel", "path", "size", "category", "detail")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("sel", text="✓")
        self.tree.heading("path", text="Path / Name")
        self.tree.heading("size", text="Size")
        self.tree.heading("category", text="Type")
        self.tree.heading("detail", text="Details")
        self.tree.column("sel", width=36, stretch=False, anchor="center")
        self.tree.column("path", width=340)
        self.tree.column("size", width=80, anchor="e")
        self.tree.column("category", width=110)
        self.tree.column("detail", width=280)

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

        # Status bar
        tk.Frame(content, bg=BORDER, height=1).pack(fill="x", side="bottom")
        status = tk.Frame(content, bg=BG2, height=28)
        status.pack(fill="x", side="bottom")
        status.pack_propagate(False)
        self.status_label = tk.Label(status, text="  No scan results", fg=FG2, bg=BG2,
                                      font=("SF Pro", 10), anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True)

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
        self.status_label.config(text="  No scan results")
        self.clean_btn.config(state="disabled", bg=BG3, fg=FG2,
                              hover_bg=BG3, hover_fg=FG2)

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def on_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.config(text="Scanning...", state="disabled")
        self.clear_results()
        self.log(f"Scanning: {self.current_submodule}")

        def worker():
            try:
                if self.current_submodule == "smart_scan":
                    results = smart_scan()
                    self.smart_results = results
                    total = sum(r.total_size for r in results.values())
                    total_items = sum(len(r.items) for r in results.values())
                    self.log(f"Smart Scan complete: {total_items} items, {human_size(total)}")
                    self._display_smart_results(results)
                else:
                    result = self._run_scanner(self.current_submodule)
                    if result:
                        self.scan_results[self.current_submodule] = result
                        self._display_result(result)
                        self.log(f"Found {len(result.items)} items ({human_size(result.total_size)})")
                    else:
                        self.log("No scanner for this submodule or no results.")
            except Exception as e:
                self.log(f"Error: {e}")
            finally:
                self.scanning = False
                self.scan_btn.config(text="Scan", state="normal")

        threading.Thread(target=worker, daemon=True).start()

    def _run_scanner(self, key):
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
            "space_lens": lambda: scan_space_lens("~"),
            "laof": scan_large_old_files,
            "duplicates": lambda: scan_duplicates("~", min_size_mb=1),
            "similar": scan_similar_images,
            "cloud": scan_cloud_storage,
        }
        fn = scanners.get(key)
        if fn:
            return fn()
        return None

    def _display_result(self, result: ScanResult):
        self.tree.delete(*self.tree.get_children())
        for item in result.items:
            sel = "✓" if item.selected else ""
            sz = human_size(item.size) if item.size > 0 else "—"
            self.tree.insert("", "end", values=(sel, item.path, sz, item.category, item.detail),
                            tags=("removable" if item.removable else "info",))
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
        total_items = 0
        total_size = 0
        for mod_name, result in results.items():
            if not result.items:
                continue
            # Module header row
            self.tree.insert("", "end", values=("", f"── {mod_name} ──", "", "", ""),
                            tags=("header",))
            for item in result.items:
                sel = "✓" if item.selected else ""
                sz = human_size(item.size) if item.size > 0 else "—"
                self.tree.insert("", "end", values=(sel, item.path, sz, item.category, item.detail),
                                tags=("removable" if item.removable else "info",))
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

        self.log(f"Cleaning {len(items_to_clean)} items...")
        self.clean_btn.config(state="disabled", bg=BG3, fg=FG2,
                              hover_bg=BG3, hover_fg=FG2)

        def worker():
            deleted, failed, errors = clean_items(items_to_clean, progress_cb=lambda d, t: self.log(f"  {d}/{t}..."))
            self.log(f"Cleanup complete: {deleted} removed, {failed} failed")
            for err in errors:
                self.log(f"  ⚠ {err}")
            # Re-scan to show updated state
            self.on_scan()

        threading.Thread(target=worker, daemon=True).start()

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


if __name__ == "__main__":
    app = App()
    app.mainloop()