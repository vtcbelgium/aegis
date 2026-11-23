"""Build distributable release artifacts for Aegis (extension zip, wheel/sdist, checksums).

Usage:
    python scripts/build_release.py                  # extension zip + python wheel/sdist (if `build` installed)
    python scripts/build_release.py --extension-only # build browser extension zip only
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from aegis import __version__  # noqa: E402

EXTENSION_FILES = (
    "manifest.json",
    "background.js",
    "content.js",
    "popup.html",
    "popup.js",
    "rules.json",
    "icons/icon16.png",
    "icons/icon48.png",
    "icons/icon128.png",
)


def build_extension_zip(out_dir: Path) -> Path:
    ext_root = REPO_ROOT / "browser-extension"
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"aegis-ai-shield-extension-{__version__}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in EXTENSION_FILES:
            src = ext_root / rel
            if not src.is_file():
                raise FileNotFoundError(f"Missing required extension file: {src}")
            zf.write(src, arcname=rel)
    return zip_path


def build_python_dists(out_dir: Path) -> bool:
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(out_dir)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return True
    # Fallback: build a wheel via pip if `build` module is not installed
    fallback = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(out_dir), str(REPO_ROOT)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    if fallback.returncode == 0:
        return True
    sys.stderr.write("Note: neither `python -m build` nor `pip wheel` succeeded; skipped Python dists.\n")
    return False


def write_checksums(out_dir: Path) -> Path:
    sums_path = out_dir / "SHA256SUMS.txt"
    lines = []
    for item in sorted(out_dir.iterdir()):
        if not item.is_file() or item.name == "SHA256SUMS.txt":
            continue
        digest = hashlib.sha256(item.read_bytes()).hexdigest()
        lines.append(f"{digest}  {item.name}")
    sums_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return sums_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Aegis free public release packages")
    parser.add_argument("--out-dir", default=str(REPO_ROOT / "dist"))
    parser.add_argument("--extension-only", action="store_true")
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    ext_zip = build_extension_zip(out_dir)
    print(f"Built browser extension package: {ext_zip}")

    if not args.extension_only:
        if build_python_dists(out_dir):
            print(f"Built Python distribution package(s) in: {out_dir}")

    sums = write_checksums(out_dir)
    print(f"Wrote SHA-256 checksums: {sums}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
