#!/usr/bin/env python3
"""
sysclean - a fast, simple cross-platform system cleaner.

Removes temporary and unnecessary files on Windows and Linux.

By default it runs in DRY-RUN mode: it only scans and reports how much
space could be freed. Nothing is deleted unless you pass --clean.

Examples:
  python main.py                 # scan and show what can be freed (safe)
  python main.py --clean         # delete, after a confirmation prompt
  python main.py --clean --yes   # delete without prompting
  python main.py --deep --clean  # also clean caches/update files (often needs admin/root)
  python main.py --days 7        # only consider items older than 7 days
  python main.py --list          # list available cleaning categories
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

__version__ = "1.0.0"

IS_WIN = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")


# --------------------------------------------------------------------------- #
# Target definition
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    key: str                       # cli identifier
    title: str                     # human readable name
    paths: list = field(default_factory=list)   # base directories
    mode: str = "contents"         # "contents" (children of dir) or "glob"
    patterns: tuple = ("*",)       # used when mode == "glob"
    deep: bool = False             # only included with --deep
    admin: bool = False            # typically needs admin/root
    note: str = ""                 # short caveat shown in --list


@dataclass
class Item:
    path: Path
    size: int


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def env_path(var: str, *parts: str):
    """Build a path from an environment variable, or None if it's unset/empty."""
    base = os.environ.get(var)
    if not base:
        return None
    p = Path(base)
    for part in parts:
        p = p / part
    return p


def norm(p) -> str:
    return os.path.normcase(os.path.normpath(str(p)))


def build_forbidden() -> set:
    """Paths we must never operate on directly (defense against bad env vars)."""
    s = {norm(Path.home())}
    if IS_WIN:
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        s.add(norm(sysroot))
        s.add(norm(Path(sysroot) / "System32"))
        for v in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData", "SystemDrive"):
            val = os.environ.get(v)
            if val:
                s.add(norm(val))
        s.add(norm(os.environ.get("SystemDrive", "C:") + "\\"))
        s.add(norm("C:\\"))
    else:
        for d in ("/", "/home", "/root", "/usr", "/bin", "/sbin", "/lib", "/lib64",
                  "/etc", "/boot", "/dev", "/proc", "/sys", "/opt", "/var",
                  "/srv", "/run", "/mnt", "/media"):
            s.add(norm(d))
    return s


FORBIDDEN = build_forbidden()


def is_safe_base(p: Path) -> bool:
    """A base directory is safe only if it's absolute and not a protected root."""
    if not p.is_absolute():
        return False
    if norm(p) in FORBIDDEN:
        return False
    return True


def path_size(p: Path) -> int:
    """Total size of a file or directory tree, never following symlinks."""
    try:
        if p.is_symlink():
            return 0
        if p.is_file():
            return p.stat().st_size
    except OSError:
        return 0
    total = 0
    stack = [str(p)]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def _rmtree(path: Path, errors: list) -> None:
    """Recursively delete a directory, collecting (not raising) per-file errors."""
    def on_exc(_func, p, exc):
        errors.append((str(p), exc))

    def on_err(_func, p, exc_info):
        errors.append((str(p), exc_info[1]))

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=on_exc)
    else:
        shutil.rmtree(path, onerror=on_err)


def delete_item(p: Path, errors: list) -> None:
    """Delete a single top-level item (file, symlink, dir, or special file)."""
    try:
        if p.is_symlink() or p.is_file():
            p.unlink(missing_ok=True)
        elif p.is_dir():
            _rmtree(p, errors)
        else:  # socket / fifo / etc.
            try:
                p.unlink(missing_ok=True)
            except OSError as e:
                errors.append((str(p), e))
    except OSError as e:
        errors.append((str(p), e))


def is_admin() -> bool:
    if IS_WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# --------------------------------------------------------------------------- #
# Platform targets
# --------------------------------------------------------------------------- #
def dedupe_paths(paths) -> list:
    seen, out = set(), []
    for p in paths:
        k = norm(p)
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


def windows_targets() -> list:
    sysroot = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    temp_bases = []
    for var in ("TEMP", "TMP"):
        p = env_path(var)
        if p:
            temp_bases.append(p)
    la_temp = env_path("LOCALAPPDATA", "Temp")
    if la_temp:
        temp_bases.append(la_temp)

    t = [
        Target("user-temp", "User temporary files", dedupe_paths(temp_bases),
               note="skips files currently in use"),
        Target("system-temp", "System temporary files", [sysroot / "Temp"],
               admin=True),
        Target("crash-dumps", "Application crash dumps",
               [env_path("LOCALAPPDATA", "CrashDumps")]),
        Target("error-reports", "Windows Error Reporting files",
               [env_path("LOCALAPPDATA", "Microsoft", "Windows", "WER")]),
        # deep
        Target("windows-update", "Windows Update download cache",
               [sysroot / "SoftwareDistribution" / "Download"],
               deep=True, admin=True),
        Target("prefetch", "Prefetch data", [sysroot / "Prefetch"],
               deep=True, admin=True, note="speeds app launch; regenerates"),
        Target("inet-cache", "Legacy IE/Edge internet cache",
               [env_path("LOCALAPPDATA", "Microsoft", "Windows", "INetCache")],
               deep=True),
        Target("recent", "Recent files shortcuts",
               [env_path("APPDATA", "Microsoft", "Windows", "Recent")],
               deep=True, note="clears the 'recent files' list"),
        Target("thumbnails", "Thumbnail cache",
               [env_path("LOCALAPPDATA", "Microsoft", "Windows", "Explorer")],
               mode="glob", patterns=("thumbcache_*.db",),
               deep=True, note="close Explorer first"),
    ]
    # drop targets whose paths couldn't be resolved (missing env vars)
    return [x for x in t if [p for p in x.paths if p is not None]]


def linux_targets() -> list:
    home = Path.home()
    t = [
        Target("tmp", "/tmp temporary files", [Path("/tmp")],
               note="skips files in use"),
        Target("var-tmp", "/var/tmp temporary files", [Path("/var/tmp")],
               admin=True),
        Target("user-cache", "User cache (~/.cache)", [home / ".cache"],
               note="apps will regenerate as needed"),
        Target("trash", "Trash bin", [home / ".local" / "share" / "Trash"]),
        # deep
        Target("apt-cache", "APT package cache",
               [Path("/var/cache/apt/archives")],
               mode="glob", patterns=("*.deb",), deep=True, admin=True),
        Target("old-logs", "Rotated system logs", [Path("/var/log")],
               mode="glob", patterns=("*.gz", "*.old", "*.[0-9]"),
               deep=True, admin=True, note="compressed/rotated logs only"),
    ]
    return t


def get_targets() -> list:
    if IS_WIN:
        return windows_targets()
    if IS_LINUX:
        return linux_targets()
    return []


# --------------------------------------------------------------------------- #
# Scan / clean
# --------------------------------------------------------------------------- #
def collect_items(t: Target):
    """Yield the top-level candidate paths for a target."""
    for base in t.paths:
        if base is None or not is_safe_base(base):
            continue
        if base.is_symlink() or not base.exists():
            continue
        try:
            if t.mode == "contents":
                if not base.is_dir():
                    continue
                with os.scandir(base) as it:
                    for e in it:
                        yield Path(e.path)
            else:  # glob
                for pat in t.patterns:
                    yield from base.glob(pat)
        except OSError:
            continue


def scan(targets, min_age_days: float):
    """Return list of (target, [Item], total_size). Dedupes paths globally."""
    seen = set()
    cutoff = time.time() - min_age_days * 86400 if min_age_days > 0 else None
    results = []
    for t in targets:
        items, total = [], 0
        for p in collect_items(t):
            key = norm(p)
            if key in seen:
                continue
            if cutoff is not None:
                try:
                    if p.lstat().st_mtime > cutoff:
                        continue
                except OSError:
                    continue
            seen.add(key)
            sz = path_size(p)
            items.append(Item(p, sz))
            total += sz
        results.append((t, items, total))
    return results


def clean(results, color):
    grand_freed, grand_errors = 0, 0
    for t, items, _ in results:
        if not items:
            continue
        freed, errors = 0, []
        for it in items:
            before = len(errors)
            delete_item(it.path, errors)
            if len(errors) == before:
                freed += it.size
        grand_freed += freed
        grand_errors += len(errors)
        suffix = ""
        if errors:
            suffix = color.dim(f"  ({len(errors)} skipped/in use)")
        print(f"  {color.green('cleaned')} {t.title:<32} {human(freed):>10}{suffix}")
    return grand_freed, grand_errors


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
class Color:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.enabled else s

    def bold(self, s):   return self._wrap("1", s)
    def dim(self, s):    return self._wrap("2", s)
    def green(self, s):  return self._wrap("32", s)
    def yellow(self, s): return self._wrap("33", s)
    def red(self, s):    return self._wrap("31", s)
    def cyan(self, s):   return self._wrap("36", s)


def supports_color(no_color_flag: bool) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if IS_WIN:
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if not k.GetConsoleMode(h, ctypes.byref(mode)):
                return False
            k.SetConsoleMode(h, mode.value | 0x0004)  # enable VT processing
            return True
        except Exception:
            return False
    return True


def print_report(results, color):
    found = [(t, items, total) for (t, items, total) in results if items]
    if not found:
        print(color.yellow("  Nothing to clean - your system is already tidy."))
        return 0, 0
    total_items = total_size = 0
    for t, items, total in found:
        total_items += len(items)
        total_size += total
        print(f"  {t.title:<34} {len(items):>6} items   {human(total):>10}")
    print("  " + "-" * 60)
    print(color.bold(f"  {'TOTAL':<34} {total_items:>6} items   {human(total_size):>10}"))
    return total_items, total_size


def print_list(targets, color):
    print(color.bold("Available cleaning categories:\n"))
    for t in targets:
        tags = []
        if t.deep:
            tags.append("deep")
        if t.admin:
            tags.append("needs admin/root")
        tag = color.dim("  [" + ", ".join(tags) + "]") if tags else ""
        print(f"  {color.cyan(t.key):<28} {t.title}{tag}")
        if t.note:
            print(f"      {color.dim(t.note)}")
    print()
    print(color.dim("Use --include / --exclude with these keys. 'deep' ones need --deep."))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Fast, simple system cleaner for Windows and Linux. "
                    "Runs as a safe dry-run unless --clean is given.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:")[-1].rstrip() if "Examples:" in __doc__ else None,
    )
    p.add_argument("--clean", action="store_true",
                   help="actually delete the files (default is a dry run)")
    p.add_argument("--yes", "-y", action="store_true",
                   help="skip the confirmation prompt (use with --clean)")
    p.add_argument("--deep", action="store_true",
                   help="include aggressive categories (caches, update files, logs)")
    p.add_argument("--days", type=float, default=0, metavar="N",
                   help="only consider items older than N days")
    p.add_argument("--include", nargs="+", metavar="CAT", default=None,
                   help="only clean these category keys (see --list)")
    p.add_argument("--exclude", nargs="+", metavar="CAT", default=None,
                   help="skip these category keys")
    p.add_argument("--list", action="store_true",
                   help="list available categories and exit")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--version", action="version", version=f"sysclean {__version__}")
    return p.parse_args(argv)


def select_targets(targets, args):
    keys = {t.key for t in targets}
    for opt in (args.include, args.exclude):
        for k in (opt or []):
            if k not in keys:
                print(f"warning: unknown category '{k}' (see --list)", file=sys.stderr)

    if args.include:
        chosen = [t for t in targets if t.key in set(args.include)]  # explicit, overrides --deep gate
    else:
        chosen = [t for t in targets if args.deep or not t.deep]
    if args.exclude:
        ex = set(args.exclude)
        chosen = [t for t in chosen if t.key not in ex]
    return chosen


def main(argv=None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    color = Color(supports_color(args.no_color))

    if not (IS_WIN or IS_LINUX):
        print("sysclean supports Windows and Linux only.", file=sys.stderr)
        return 1

    all_targets = get_targets()
    if args.list:
        print_list(all_targets, color)
        return 0

    targets = select_targets(all_targets, args)

    plat = "Windows" if IS_WIN else "Linux"
    print(color.bold(f"sysclean {__version__}  -  {plat}"))
    mode = color.red("CLEAN (files will be deleted)") if args.clean else \
        color.green("dry run (nothing will be deleted)")
    print(f"Mode: {mode}")
    if args.days > 0:
        print(color.dim(f"Filter: only items older than {args.days:g} day(s)"))
    print(color.dim("Scanning...\n"))

    results = scan(targets, args.days)
    total_items, total_size = print_report(results, color)

    # Hint if some privileged locations were likely inaccessible.
    if not is_admin() and any(t.admin for t in targets):
        print(color.dim("\nTip: some locations need administrator/root; "
                         "re-run elevated to include them."))

    if total_items == 0:
        return 0

    if not args.clean:
        print(color.dim("\nThis was a dry run. Re-run with --clean to free this space."))
        return 0

    if not args.yes:
        print()
        try:
            ans = input(f"Delete {total_items} item(s) (~{human(total_size)})? [y/N] ")
        except EOFError:
            ans = ""
        if ans.strip().lower() not in ("y", "yes"):
            print("Aborted. Nothing was deleted.")
            return 0

    print(color.bold("\nCleaning...\n"))
    freed, errors = clean(results, color)
    print("  " + "-" * 60)
    print(color.bold(f"  Freed {human(freed)}") +
          (color.dim(f"   ({errors} item(s) could not be removed)") if errors else ""))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
