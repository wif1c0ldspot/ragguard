# Releases and installation

The project is alpha. Python 3.10, 3.11 and 3.12 are tested; the DeepSeek bundle
targets Node 22 and the exact harness peer versions in its package manifest.
Semantic detector adapters are application-owned and require separate evaluation.

## Install a versioned snapshot

Download the wheel, npm tarball, `build-info.json` and `SHA256SUMS` from the
[GitHub releases page](https://github.com/wif1c0ldspot/ragguard/releases).
Download all listed files into one directory, then verify:

```bash
sha256sum -c SHA256SUMS       # macOS: shasum -a 256 -c SHA256SUMS
python -m pip install ./ragguard-0.3.0-py3-none-any.whl
# Optional vector checks:
python -m pip install './ragguard-0.3.0-py3-none-any.whl[vector]'
```

The Python base package has no runtime dependencies. The optional vector extra
adds numpy. The npm tarball is a separate DeepSeek Harness integration; install
it in the harness environment following its README. Neither artifact is published
to PyPI or npm by this workflow. Checksums detect file changes; a checksum file
downloaded from the same release is not an independent signature.

## Maintainer procedure

1. Update Python versions in `pyproject.toml` and `ragguard/__init__.py`, and run
   `uv lock`. Update the npm manifest and lockfile when its behavior changes.
2. Update the changelog, compatibility documentation and `docs/releases/vVERSION.md`.
   Preserve historical metrics; evaluate dev and frozen holdout separately.
3. Merge only after the Python matrix and DeepSeek checks pass.
4. From the clean committed checkout, run:

   ```bash
   uv run --no-project --python 3.12 python scripts/build_release.py --tag v0.3.0
   ```

   This exports the committed tree into two fresh directories, excluding ignored
   local build outputs. It uses pinned build dependencies, `npm ci`, the commit
   timestamp and two builds. It refuses mismatched bytes and emits wheel, sdist, npm tarball,
   environment metadata and SHA-256 checksums. This verifies reproducibility
   within one environment, not across arbitrary operating systems or toolchains.
5. Create and push the matching tag. The release workflow reruns the complete CI
   suite, checks that the commit belongs to main, rebuilds twice and publishes
   the artifacts as a GitHub prerelease. Do not move published tags or replace
   release assets; issue a new patch release instead.

Build dependencies are pinned in `scripts/build-constraints.txt`; review them
deliberately. CI actions are pinned by commit, with Dependabot proposing updates.
Node/npm/uv versions are recorded with each release for reproduction.
