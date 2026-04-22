"""
Sync the clean main_runtime source bundle from login-credential-checker/src.

Usage:
    python sync_bundle.py
"""

from __future__ import annotations

import shutil
from pathlib import Path


def main() -> None:
    bundle_root = Path(__file__).resolve().parent
    source_root = (bundle_root.parent / "login-credential-checker" / "src").resolve()
    target_root = (bundle_root / "src").resolve()

    required_files = [
        "main.py",
        "checker.py",
        "parser.py",
        "proxy_manager.py",
        "page_analyzer.py",
        "form_cache.py",
        "advanced_checker.py",
        "credential_filter.py",
        "__init__.py",
        "gui/app.py",
        "gui/styles.py",
        "gui/__init__.py",
    ]
    required_set = {Path(p).as_posix() for p in required_files}

    if not source_root.exists():
        raise SystemExit(f"Source root not found: {source_root}")

    target_root.mkdir(parents=True, exist_ok=True)
    (target_root / "gui").mkdir(parents=True, exist_ok=True)

    # Copy/update required files from source when they exist there.
    copied = 0
    for rel in required_files:
        src = source_root / rel
        dst = target_root / rel

        if rel in ("__init__.py", "gui/__init__.py"):
            if not dst.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(
                    '"""main_runtime package marker."""\n'
                    if rel == "__init__.py"
                    else '"""main_runtime.gui package marker."""\n',
                    encoding="utf-8",
                )
            continue

        if not src.exists():
            print(f"[SKIP] Missing in source: {src}")
            continue

        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied += 1
        print(f"[COPY] {src} -> {dst}")

    # Remove stale .py files from target/src not in required set.
    removed = 0
    for py_file in target_root.rglob("*.py"):
        rel = py_file.relative_to(target_root).as_posix()
        if rel not in required_set:
            py_file.unlink(missing_ok=True)
            removed += 1
            print(f"[REMOVE] stale file: {py_file}")

    # Remove all __pycache__ directories.
    cache_dirs = list(target_root.rglob("__pycache__"))
    for cache_dir in cache_dirs:
        shutil.rmtree(cache_dir, ignore_errors=True)
        print(f"[CLEAN] {cache_dir}")

    print(
        f"\nDone. copied={copied}, removed_stale_py={removed}, "
        f"removed_pycache={len(cache_dirs)}"
    )


if __name__ == "__main__":
    main()
