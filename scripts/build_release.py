"""Build twice, compare bytes, then publish checksummed release artifacts locally.

Requires Python 3.12, uv and Node 22/npm. Run from a clean committed checkout.
This script never uploads artifacts or publishes to a package registry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*command: str, cwd: Path = ROOT, env: dict[str, str] | None = None) -> str:
    return subprocess.check_output(command, cwd=cwd, env=env, text=True).strip()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(source: Path, destination: Path, env: dict[str, str]) -> dict[str, str]:
    destination.mkdir()
    run("uv", "build", "--python", "3.12", "--build-constraints",
        str(source / "scripts/build-constraints.txt"), "--out-dir", str(destination),
        cwd=source, env=env)
    run("npm", "pack", "--pack-destination", str(destination),
        cwd=source / "integrations/deepseek", env=env)
    # uv creates an output-directory .gitignore alongside the distributions.
    files = sorted(path for path in destination.iterdir() if path.name != ".gitignore")
    if len(files) != 3 or {p.suffix for p in files} != {".whl", ".gz", ".tgz"}:
        raise RuntimeError("Expected exactly one wheel, sdist and npm package")
    return {path.name: digest(path) for path in files}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/release")
    parser.add_argument("--tag", help="Require this tag to match the package version")
    args = parser.parse_args()
    version_match = re.search(r'^version = "([^"]+)"$',
                              (ROOT / "pyproject.toml").read_text(), re.M)
    if version_match is None:
        raise RuntimeError("Missing project version")
    version = version_match.group(1)
    if args.tag and args.tag != f"v{version}":
        raise ValueError("Release tag must match the Python package version")
    if run("git", "status", "--porcelain", "--untracked-files=normal"):
        raise RuntimeError("Release builds require a clean committed checkout")
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory must be empty to avoid mixing releases")
    env = {**os.environ, "SOURCE_DATE_EPOCH": run("git", "show", "-s", "--format=%ct", "HEAD")}
    with tempfile.TemporaryDirectory(prefix="ragguard-release-") as directory:
        temporary = Path(directory)
        archive = temporary / "source.tar"
        run("git", "archive", "--format=tar", "--output", str(archive), "HEAD")
        sources = [temporary / "source-first", temporary / "source-second"]
        for source in sources:
            source.mkdir()
            with tarfile.open(archive) as bundle:
                bundle.extractall(source, filter="data")
            run("npm", "ci", "--ignore-scripts", cwd=source / "integrations/deepseek", env=env)
        first, second = temporary / "first", temporary / "second"
        hashes = build(sources[0], first, env)
        if hashes != build(sources[1], second, env):
            raise RuntimeError("Repeated builds differed; refusing to release")
        output.mkdir(parents=True, exist_ok=True)
        for filename in hashes:
            shutil.copy2(first / filename, output / filename)
    metadata = {
        "commit": run("git", "rev-parse", "HEAD"), "version": version,
        "source_date_epoch": int(env["SOURCE_DATE_EPOCH"]),
        "uv": run("uv", "--version"), "node": run("node", "--version"),
        "npm": run("npm", "--version"), "artifacts": hashes,
        "verification": "two builds in the same environment produced identical SHA-256 hashes",
    }
    (output / "build-info.json").write_text(json.dumps(metadata, indent=2) + "\n")
    hashes["build-info.json"] = digest(output / "build-info.json")
    (output / "SHA256SUMS").write_text("".join(
        f"{value}  {name}\n" for name, value in sorted(hashes.items())
    ))
    print(f"Verified release artifacts: {output}")


if __name__ == "__main__":
    main()
