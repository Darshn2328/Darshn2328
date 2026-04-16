import hashlib
import json
import os
import sys
from datetime import datetime

MONITOR_DIR = "D.txt"
BASELINE_FILE = "hash_files.json"
HASH_ALGO = "sha256"
RECURSIVE = True

def compute_hash(filepath: str, algo: str = HASH_ALGO) -> str:
    """Return the hex-digest hash of a file."""
    h = hashlib.new(algo)
    try:
        with open(filepath, "rb") as f:
           for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError) as err:
        print(f"  [!] Cannot read '{filepath}': {err}")
        return ""


def scan_directory(directory: str, recursive: bool = RECURSIVE) -> dict:
    """
    Walk the directory and return a dict:
        { relative_path_string : hex_hash_string }
    """
    hashes = {}
    directory = os.path.abspath(directory)

    if recursive:
        for root, _, files in os.walk(directory):
            for name in files:
                full_path = os.path.join(root, name)
                rel_path  = os.path.relpath(full_path, directory)
                digest    = compute_hash(full_path)
                if digest:
                    hashes[rel_path] = digest
    else:
        for name in os.listdir(directory):
            full_path = os.path.join(directory, name)
            if os.path.isfile(full_path):
                digest = compute_hash(full_path)
                if digest:
                    hashes[name] = digest

    return hashes


def save_baseline(hashes: dict, baseline_path: str) -> None:
    """Save the hash dict to a JSON file with metadata."""
    data = {
        "created_at"  : datetime.now().isoformat(timespec="seconds"),
        "algorithm"   : HASH_ALGO,
        "file_count"  : len(hashes),
        "hashes"      : hashes,
    }
    with open(baseline_path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n  ✔  Baseline saved → '{baseline_path}'")
    print(f"     Files recorded : {len(hashes)}")


def load_baseline(baseline_path: str) -> dict:
    """Load and return the hashes dict from a JSON baseline file."""
    with open(baseline_path, "r") as f:
        data = json.load(f)
    print(f"  ℹ  Baseline loaded (created {data.get('created_at', '?')},"
          f" algo={data.get('algorithm', '?')})")
    return data.get("hashes", {})


def compare_hashes(baseline: dict, current: dict) -> dict:
    """
    Compare two hash dicts and return a report dict with:
        changed  – files that exist in both but have different hashes
        added    – files present now but not in baseline
        deleted  – files in baseline but missing now
        unchanged– files identical in both
    """
    baseline_keys = set(baseline.keys())
    current_keys  = set(current.keys())

    changed   = [f for f in baseline_keys & current_keys
                 if baseline[f] != current[f]]
    added     = list(current_keys  - baseline_keys)
    deleted   = list(baseline_keys - current_keys)
    unchanged = [f for f in baseline_keys & current_keys
                 if baseline[f] == current[f]]

    return {
        "changed"  : sorted(changed),
        "added"    : sorted(added),
        "deleted"  : sorted(deleted),
        "unchanged": sorted(unchanged),
    }


def print_report(report: dict) -> None:
    """Pretty-print the integrity check report to the console."""
    sep = "─" * 55

    print(f"\n{'═'*55}")
    print("  FILE INTEGRITY REPORT")
    print(f"  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")
    print(f"{'═'*55}")

    # ── CHANGED ──
    print(f"\n  🔴  MODIFIED  ({len(report['changed'])} file(s))")
    print(f"  {sep}")
    if report["changed"]:
        for f in report["changed"]:
            print(f"       ✗  {f}")
    else:
        print("       (none)")

    # ── ADDED ──
    print(f"\n  🟡  NEW / ADDED  ({len(report['added'])} file(s))")
    print(f"  {sep}")
    if report["added"]:
        for f in report["added"]:
            print(f"       +  {f}")
    else:
        print("       (none)")

    # ── DELETED ──
    print(f"\n  ⚫  DELETED  ({len(report['deleted'])} file(s))")
    print(f"  {sep}")
    if report["deleted"]:
        for f in report["deleted"]:
            print(f"       –  {f}")
    else:
        print("       (none)")

    # ── UNCHANGED ──
    print(f"\n  🟢  UNCHANGED  ({len(report['unchanged'])} file(s))")
    print(f"  {sep}")
    if report["unchanged"]:
        for f in report["unchanged"]:
            print(f"       ✓  {f}")
    else:
        print("       (none)")

    # ── SUMMARY ──
    total_issues = (len(report["changed"])
                    + len(report["added"])
                    + len(report["deleted"]))
    print(f"\n{'═'*55}")
    if total_issues == 0:
        print("  ✅  All files are INTACT.  No changes detected.")
    else:
        print(f"  ⚠️   {total_issues} integrity issue(s) detected!")
    print(f"{'═'*55}\n")


# ──────────────────────────────────────────────
#  MENU / MAIN LOGIC
# ──────────────────────────────────────────────

def menu() -> str:
    """Show a simple text menu and return the user's choice."""
    print("\n" + "═"*55)
    print("  CODTECH  |  File Integrity Checker")
    print("═"*55)
    print("  [1]  Create / refresh baseline  (first-time setup)")
    print("  [2]  Check integrity            (compare vs baseline)")
    print("  [3]  Show current file hashes   (no comparison)")
    print("  [4]  Exit")
    print("─"*55)
    return input("  Enter choice [1-4]: ").strip()


def resolve_paths():
    """Return absolute paths for monitor dir and baseline file."""
    script_dir   = os.path.dirname(os.path.abspath(__file__))
    monitor_abs  = os.path.join(script_dir, MONITOR_DIR)
    baseline_abs = os.path.join(script_dir, BASELINE_FILE)
    return monitor_abs, baseline_abs


def ensure_monitor_dir(monitor_abs: str) -> bool:
    """Create the monitor directory if missing. Return True if ok."""
    if not os.path.exists(monitor_abs):
        os.makedirs(monitor_abs)
        print(f"\n  [+] Created monitor folder: '{monitor_abs}'")
        print("      Drop files into that folder, then re-run option [1].")
        return False          # folder was just created – probably empty
    return True


def main():
    monitor_abs, baseline_abs = resolve_paths()
    print(f"\n  Monitor dir  : {monitor_abs}")
    print(f"  Baseline file: {baseline_abs}")
    print(f"  Algorithm    : {HASH_ALGO.upper()}")

    while True:
        choice = menu()

        # ── 1: Create / refresh baseline ──────────────────────
        if choice == "1":
            ensure_monitor_dir(monitor_abs)
            print(f"\n  Scanning '{monitor_abs}' ...")
            current = scan_directory(monitor_abs)
            if not current:
                print("  [!] No files found in the monitor directory.")
                print("      Add some files and try again.")
            else:
                save_baseline(current, baseline_abs)

        # ── 2: Check integrity ─────────────────────────────────
        elif choice == "2":
            if not os.path.exists(baseline_abs):
                print("\n  [!] No baseline found.  Run option [1] first.")
                continue
            ensure_monitor_dir(monitor_abs)
            print(f"\n  Scanning '{monitor_abs}' ...")
            current  = scan_directory(monitor_abs)
            baseline = load_baseline(baseline_abs)
            report   = compare_hashes(baseline, current)
            print_report(report)

        # ── 3: Show current hashes ─────────────────────────────
        elif choice == "3":
            ensure_monitor_dir(monitor_abs)
            print(f"\n  Scanning '{monitor_abs}' ...\n")
            current = scan_directory(monitor_abs)
            if not current:
                print("  [!] No files found.")
            else:
                print(f"  {'FILE':<40}  {'HASH':>64}")
                print("  " + "─"*106)
                for path, digest in sorted(current.items()):
                    print(f"  {path:<40}  {digest}")
                print(f"\n  Total: {len(current)} file(s)\n")

        # ── 4: Exit ────────────────────────────────────────────
        elif choice == "4":
            print("\n  Goodbye!\n")
            sys.exit(0)

        else:
            print("\n  [!] Invalid choice. Enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()