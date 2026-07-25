"""
utils.py -- shared helpers: file sizing, path expansion, formatting
"""
import os
import hashlib
import subprocess
import time
from pathlib import Path

def expand(path: str) -> Path:
    """Expand ~ and env vars."""
    return Path(os.path.expandvars(os.path.expanduser(path))).resolve()

def human_size(n: int) -> str:
    """Format byte count."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def file_size(path: Path) -> int:
    """Size of file or dir tree, non-following symlinks."""
    if path.is_symlink():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    if path.is_dir():
        try:
            for entry in path.rglob("*"):
                if entry.is_symlink():
                    continue
                try:
                    if entry.is_file():
                        total += entry.stat().st_size
                except OSError:
                    pass
        except (OSError, PermissionError):
            pass
    return total

def safe_remove(path: Path) -> tuple[bool, str]:
    """Delete file or dir, best-effort.
    SAFETY: Checks _is_protected() to refuse deleting protected paths.
    Checks is_symlink() before rmtree to prevent following links.
    For cache/log directories, uses _delete_dir_contents() to preserve the dir.
    Returns (success, message)."""
    # Import here to avoid circular import (scanners imports utils)
    from scanners import _is_protected, _delete_dir_contents
    if _is_protected(path):
        return False, f"Refused: {path} is protected"
    try:
        if path.is_symlink():
            path.unlink()
            return True, f"Removed symlink: {path}"
        elif path.is_file():
            path.unlink()
            return True, f"Removed file: {path}"
        elif path.is_dir():
            # SAFETY: Never rmtree cache/log directories — preserve the dir itself.
            # These are dirs macOS/apps expect to exist. Delete contents only.
            cache_log_paths = {
                Path.home() / "Library" / "Caches",
                Path.home() / "Library" / "Logs",
                Path("/Library") / "Caches",
                Path("/Library") / "Logs",
            }
            try:
                resolved = path.resolve()
                if any(resolved == p.resolve() for p in cache_log_paths):
                    removed, errors = _delete_dir_contents(path)
                    if errors:
                        return True, f"Removed {removed} items (with {len(errors)} errors): {path}"
                    return True, f"Removed {removed} items: {path}"
            except (OSError, RuntimeError):
                pass
            # SAFETY: Use _delete_dir_contents() + rmdir instead of
            # shutil.rmtree() to prevent following nested symlinks on
            # Python <3.12. rmtree would follow a symlink inside the
            # directory and delete files outside the target.
            removed, errors = _delete_dir_contents(path)
            try:
                path.rmdir()  # remove the now-empty directory shell
            except OSError:
                pass
            if errors:
                return True, f"Removed {removed} items (with {len(errors)} errors): {path}"
            return True, f"Removed {removed} items: {path}"
    except (OSError, PermissionError) as e:
        return False, f"Failed: {path} — {e}"
    return False, f"Unknown path type: {path}"

def file_hash(path: Path, algo: str = "sha256", chunk: int = 65536) -> str:
    """Hash a file for duplicate detection."""
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as f:
            while True:
                data = f.read(chunk)
                if not data:
                    break
                h.update(data)
    except (OSError, PermissionError):
        return ""
    return h.hexdigest()

def run_shell(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    """Run a shell command, return (exit_code, output)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as e:
        return 1, str(e)

def run_sudo(cmd: str, timeout: int = 120) -> tuple[int, str]:
    """Run a command with admin privileges via osascript.
    SAFETY: Escapes double quotes and backslashes to prevent AppleScript
    injection — an unescaped quote could break out of the string literal
    and execute arbitrary code with administrator privileges."""
    escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')
    apple = f'do shell script "{escaped}" with administrator privileges'
    r = run_shell(["osascript", "-e", apple], timeout=timeout)
    return r

def file_age_days(path: Path) -> int:
    """Days since last access."""
    try:
        return int((time.time() - path.stat().st_atime) / 86400)
    except OSError:
        return 0

def dir_walk(path: Path, skip_hidden: bool = False):
    """Safe directory walker.
    SAFETY: Skips symlinks to prevent following links outside the target
    directory (e.g. a symlink in ~/Documents pointing to / would cause
    walking the entire filesystem). Uses os.walk(followlinks=False) so
    symlinked directories are never recursed into, regardless of Python
    version (Path.rglob on Python <3.12 may recurse into symlinked dirs).
    Also verifies each yielded entry's resolved path stays within the
    resolved target directory as a defense-in-depth measure."""
    try:
        target_resolved = path.resolve()
    except (OSError, RuntimeError):
        return
    try:
        for root, dirs, files in os.walk(path, followlinks=False):
            root_path = Path(root)
            # Filter out hidden dirs in-place so os.walk doesn't descend into them
            if skip_hidden:
                dirs[:] = [d for d in dirs if not d.startswith(".")]
            for name in files:
                entry = root_path / name
                # Skip symlinks — never follow links outside the target tree
                if entry.is_symlink():
                    continue
                if skip_hidden and name.startswith("."):
                    continue
                # Defense-in-depth: verify resolved path is within target
                try:
                    if target_resolved not in entry.resolve().parents and \
                       entry.resolve() != target_resolved:
                        continue
                except (OSError, RuntimeError):
                    continue
                yield entry
    except (OSError, PermissionError):
        return