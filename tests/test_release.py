"""Release smoke orchestration; final builds also execute the actual artifact checks."""

import io
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts import build_release


def artifact_fixture(tmp_path):
    source = tmp_path / "source"
    scripts = source / "integrations/deepseek/tests"
    scripts.mkdir(parents=True)
    (scripts / "package-smoke.mjs").write_text("// locked smoke script\n")
    (source / "integrations/deepseek/node_modules").mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "ragguard.whl").write_bytes(b"exact wheel")
    with tarfile.open(artifacts / "plugin.tgz", "w:gz") as bundle:
        content = b'{"name":"dsh-ragguard"}'
        info = tarfile.TarInfo("package/package.json")
        info.size = len(content)
        bundle.addfile(info, io.BytesIO(content))
    return source, artifacts


def test_smoke_uses_exact_artifacts_offline_outside_source(tmp_path, monkeypatch):
    source, artifacts = artifact_fixture(tmp_path)
    calls = []

    def run(*command, cwd, env, timeout):
        calls.append(command)
        assert cwd != source and not cwd.is_relative_to(source)
        assert not {"PYTHONPATH", "PYTHONHOME", "NODE_PATH", "NODE_OPTIONS"} & env.keys()
        assert timeout > 0
        if command[0] == "node":
            assert Path(command[1]).read_text() == "// locked smoke script\n"
            assert (Path(command[2]) / "package.json").is_file()
            assert (cwd / "node_modules").resolve() == (
                source / "integrations/deepseek/node_modules"
            )
            assert env["RAGGUARD_TEST_PYTHON"] == calls[2][0]
        return ""

    monkeypatch.setattr(build_release, "run", run)
    build_release.smoke_artifacts(source, artifacts, "1.2.3", {
        "PATH": "/bin", "PYTHONPATH": "bad", "PYTHONHOME": "bad",
        "NODE_PATH": "bad", "NODE_OPTIONS": "bad",
    })
    assert len(calls) == 4
    assert "--offline" in calls[0]
    assert "--offline" in calls[1] and "--no-deps" in calls[1]
    assert calls[1][-1] == str(artifacts / "ragguard.whl")
    assert calls[2][1:3] == ("-I", "-c")
    assert calls[2][-1] == "1.2.3"


def test_failed_wheel_smoke_prevents_javascript_smoke(tmp_path, monkeypatch):
    source, artifacts = artifact_fixture(tmp_path)
    calls = []

    def run(*command, **kwargs):
        calls.append(command)
        if "-c" in command:
            raise subprocess.CalledProcessError(1, command)
        return ""

    monkeypatch.setattr(build_release, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        build_release.smoke_artifacts(source, artifacts, "1.2.3", {})
    assert len(calls) == 3
    assert not any(command[0] == "node" for command in calls)


def test_release_does_not_copy_artifacts_when_smoke_fails(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "pyproject.toml").write_text('version = "1.2.3"\n')
    output = tmp_path / "release"
    monkeypatch.setattr(build_release, "ROOT", checkout)
    monkeypatch.setattr("sys.argv", ["build_release.py", "--output", str(output)])

    def run(*command, **kwargs):
        if command[:2] == ("git", "archive"):
            with tarfile.open(command[command.index("--output") + 1], "w"):
                pass
        if command[:2] == ("git", "show"):
            return "123"
        return ""

    def build(source, destination, env):
        destination.mkdir()
        (destination / "exact.whl").write_bytes(b"identical")
        return {"exact.whl": "same digest"}

    def smoke(source, artifacts, version, env):
        assert (artifacts / "exact.whl").read_bytes() == b"identical"
        raise RuntimeError("Artifact smoke failed")

    monkeypatch.setattr(build_release, "run", run)
    monkeypatch.setattr(build_release, "build", build)
    monkeypatch.setattr(build_release, "smoke_artifacts", smoke)
    with pytest.raises(RuntimeError, match="Artifact smoke failed"):
        build_release.main()
    assert not output.exists()
