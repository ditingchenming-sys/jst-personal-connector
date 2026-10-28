"""只构建临时包及解析安装脚本，不执行安装、登录或部署。"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("jst_distribution", ROOT / "scripts" / "build_bundle.py")
distribution = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(distribution)


def wheel_content(extra=None, missing=None):
    files = {
        **{"jst_connector/" + module: "# 离线完整包结构测试\n" for module in distribution.MODULES},
        "jst_connector/__init__.py": '__version__ = "0.1.0"\n',
        "jst_connector/__main__.py": "# 离线打包用例\n",
        "jst_connector/management.html": "<!doctype html><html lang=zh-CN></html>\n",
        "jst_personal_connector-0.1.0.dist-info/METADATA": "Metadata-Version: 2.4\nName: jst-personal-connector\nVersion: 0.1.0\nRequires-Python: >=3.11\nLicense-Expression: MIT\nLicense-File: LICENSE\n",
        "jst_personal_connector-0.1.0.dist-info/licenses/LICENSE": (ROOT / "LICENSE").read_bytes(),
        "jst_personal_connector-0.1.0.dist-info/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        "jst_personal_connector-0.1.0.dist-info/RECORD": "",
        "jst_personal_connector-0.1.0.dist-info/entry_points.txt": "[console_scripts]\njst-connector = jst_connector.cli:main\n",
    }
    files.update(extra or {})
    if missing:
        files.pop(missing)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as wheel:
        for name, content in files.items():
            wheel.writestr(name, content)
    return output.getvalue()


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "项目"
    root.mkdir()
    for relative in distribution.FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("安全分发测试资料\n", encoding="utf-8")
    (root / "LICENSE").write_bytes((ROOT / "LICENSE").read_bytes())
    wheel = root / "dist" / "jst_personal_connector-0.1.0-py3-none-any.whl"
    wheel.parent.mkdir()
    wheel.write_bytes(wheel_content())
    return root


def test_bundle_only_contains_explicit_files_hashes_and_matching_metadata(project, tmp_path):
    for relative in (".env", "runtime/vault.enc", "data/ledger.sqlite", "credentials/master.key",
                     "browser_data/cookies.json", ".venv/secret", ".git/config", "unapproved.md"):
        path = project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("DUMMY_NOT_A_REAL_SECRET", encoding="utf-8")
    output = tmp_path / "bundle.zip"
    result = distribution.build_bundle(project, output)
    assert result["version"] == "0.1.0"
    assert result["sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        expected = set(distribution.FILES) | {"bundle.json", distribution.MANIFEST,
                                              "wheels/jst_personal_connector-0.1.0-py3-none-any.whl"}
        assert names == expected
        manifest = json.loads(archive.read(distribution.MANIFEST))
        assert manifest["algorithm"] == "sha256"
        assert set(manifest["files"]) == names - {distribution.MANIFEST}
        for name, record in manifest["files"].items():
            content = archive.read(name)
            assert record == {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
            assert b"DUMMY_NOT_A_REAL_SECRET" not in content
        metadata = json.loads(archive.read("bundle.json"))
        assert metadata["requires_python"] == ">=3.11"
        assert metadata["real_business_verified"] is False
        extracted = tmp_path / "extracted"
        archive.extractall(extracted)
    assert distribution.verify_directory(extracted)["ok"]
    (extracted / "INSTALL.md").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="校验失败"):
        distribution.verify_directory(extracted)


def test_existing_distribution_target_is_never_overwritten(project, tmp_path):
    output = tmp_path / "existing.zip"
    output.write_bytes(b"keep-existing")
    with pytest.raises(FileExistsError, match="拒绝覆盖"):
        distribution.build_bundle(project, output)
    assert output.read_bytes() == b"keep-existing"


@pytest.mark.parametrize("name", ["jst_connector/.env", "jst_connector/state/vault.enc",
                                  "jst_connector/cookies.json", "jst_connector/browser_data/state.json",
                                  "../credentials.txt", "/tmp/file", "jst_connector/__pycache__/x.pyc",
                                  "jst_connector/unknown.py", "jst_personal_connector-0.1.0.dist-info/licenses/private.key",
                                  "jst_personal_connector-0.1.0.dist-info/licenses/nested/LICENSE"])
def test_wheel_runtime_credentials_and_unapproved_files_are_rejected(project, tmp_path, name):
    wheel = project / "dist" / "jst_personal_connector-0.1.0-py3-none-any.whl"
    wheel.write_bytes(wheel_content({name: "DUMMY_NOT_A_REAL_SECRET"}))
    with pytest.raises(ValueError):
        distribution.build_bundle(project, tmp_path / "unsafe.zip")
    assert not (tmp_path / "unsafe.zip").exists()


def test_missing_wheel_and_required_file_fail_before_output(project, tmp_path):
    wheel = project / "dist" / "jst_personal_connector-0.1.0-py3-none-any.whl"
    wheel.unlink()
    with pytest.raises(ValueError, match="先 uv build"):
        distribution.build_bundle(project, tmp_path / "missing-wheel.zip")
    wheel.write_bytes(wheel_content())
    (project / "requirements.lock.txt").unlink()
    with pytest.raises(ValueError, match="必需文件缺失"):
        distribution.build_bundle(project, tmp_path / "missing-lock.zip")


@pytest.mark.parametrize("missing", [
    "jst_connector/browser.py",
    "jst_connector/management.html",
    "jst_personal_connector-0.1.0.dist-info/entry_points.txt",
    "jst_personal_connector-0.1.0.dist-info/licenses/LICENSE",
])
def test_incomplete_wheel_is_rejected_before_bundle_creation(project, tmp_path, missing):
    wheel = project / "dist" / "jst_personal_connector-0.1.0-py3-none-any.whl"
    wheel.write_bytes(wheel_content(missing=missing))
    output = tmp_path / "incomplete.zip"
    with pytest.raises(ValueError, match="缺少运行模块"):
        distribution.build_bundle(project, output)
    assert not output.exists()


def test_mismatched_license_text_is_rejected(project, tmp_path):
    wheel = project / "dist" / "jst_personal_connector-0.1.0-py3-none-any.whl"
    wheel.write_bytes(wheel_content({"jst_personal_connector-0.1.0.dist-info/licenses/LICENSE": "changed"}))
    with pytest.raises(ValueError, match="许可证全文"):
        distribution.build_bundle(project, tmp_path / "wrong-license.zip")


def test_missing_license_expression_is_rejected(project, tmp_path):
    wheel = project / "dist" / "jst_personal_connector-0.1.0-py3-none-any.whl"
    wheel.write_bytes(wheel_content({"jst_personal_connector-0.1.0.dist-info/METADATA":
        "Metadata-Version: 2.4\nName: jst-personal-connector\nVersion: 0.1.0\n"}))
    with pytest.raises(ValueError, match="许可证声明"):
        distribution.build_bundle(project, tmp_path / "missing-license-expression.zip")


def test_wrong_console_entrypoint_is_rejected(project, tmp_path):
    wheel = project / "dist" / "jst_personal_connector-0.1.0-py3-none-any.whl"
    wheel.write_bytes(wheel_content({
        "jst_personal_connector-0.1.0.dist-info/entry_points.txt": "[console_scripts]\njst-connector = wrong.module:main\n"}))
    with pytest.raises(ValueError, match="命令入口"):
        distribution.build_bundle(project, tmp_path / "wrong-entrypoint.zip")


def test_symlinked_document_cannot_smuggle_an_external_file(project, tmp_path):
    document = project / "README.md"
    document.unlink()
    outside = tmp_path / "outside.txt"
    outside.write_text("DUMMY_NOT_A_REAL_SECRET", encoding="utf-8")
    try:
        document.symlink_to(outside)
    except OSError:
        pytest.skip("当前Windows账号不允许创建符号链接，未执行此平台用例。")
    with pytest.raises(ValueError, match="普通文件"):
        distribution.build_bundle(project, tmp_path / "symlink.zip")


def test_manifest_traversal_and_metadata_mismatch_are_rejected(project, tmp_path):
    output = tmp_path / "bundle.zip"
    distribution.build_bundle(project, output)
    extracted = tmp_path / "unpacked"
    with zipfile.ZipFile(output) as archive:
        archive.extractall(extracted)
    manifest = json.loads((extracted / distribution.MANIFEST).read_bytes())
    manifest["files"]["../private"] = {"size": 1, "sha256": "bad"}
    (extracted / distribution.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="不安全"):
        distribution.verify_directory(extracted)


def test_powershell_installer_parses_without_execution():
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        pytest.skip("当前环境没有PowerShell，仅能在Windows补脚本语法验证。")
    environment = dict(os.environ, JST_TEST_SCRIPT=str(ROOT / "scripts" / "install.ps1"))
    command = "$tokens=$null; $parseErrors=$null; [System.Management.Automation.Language.Parser]::ParseFile($env:JST_TEST_SCRIPT,[ref]$tokens,[ref]$parseErrors) | Out-Null; if ($parseErrors.Count) { $parseErrors | ForEach-Object { $_.Message }; exit 1 }"
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, env=environment, timeout=20, check=False)
    assert result.returncode == 0, result.stdout.decode("utf-8", errors="replace")


def test_powershell5_executes_actual_python_probes_in_chinese_space_venv_path(tmp_path):
    powershell = shutil.which("powershell")
    if os.name != "nt" or not powershell:
        pytest.skip("该原生参数回归仅适用于Windows PowerShell 5。")
    environment_directory = tmp_path / "中文 空格 安装目录" / ".venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(environment_directory)],
                   capture_output=True, timeout=30, check=True)
    environment_python = environment_directory / "Scripts" / "python.exe"
    text = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8-sig")
    codes = re.findall(r"Invoke-Checked \$(?:Python|EnvironmentPython) @\('-c', '([^']+)'\)", text)
    assert len(codes) == 2 and all('"' not in code for code in codes)
    # Load only the real helper definition; do not execute the installer body.
    command = "$tokens=$null; $errors=$null; $ast=[System.Management.Automation.Language.Parser]::ParseFile($env:JST_TEST_SCRIPT,[ref]$tokens,[ref]$errors); $helper=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Checked'},$true); . ([scriptblock]::Create($helper.Extent.Text)); try { Invoke-Checked $env:JST_PROBE_PYTHON @('-c',$env:JST_PROBE_CODE); exit 0 } catch { exit 1 }"
    for code in codes:
        environment = dict(os.environ, JST_TEST_SCRIPT=str(ROOT / "scripts" / "install.ps1"),
                           JST_PROBE_PYTHON=str(environment_python), JST_PROBE_CODE=code)
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, env=environment, timeout=20, check=False)
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


def test_shell_installer_syntax_without_execution():
    candidates = [shutil.which("sh"), shutil.which("bash")]
    if os.name == "nt":
        candidates += [str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe")]
    for shell in candidates:
        if not shell or not Path(shell).is_file():
            continue
        probe = subprocess.run([shell, "--version"], capture_output=True, timeout=10, check=False)
        if probe.returncode != 0:
            continue
        result = subprocess.run([shell, "-n", (ROOT / "scripts" / "install.sh").as_posix()],
                                capture_output=True, timeout=10, check=False)
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
        return
    pytest.skip("未发现可用的sh/bash（Windows的WSL启动器不是可用Linux shell）；Linux安装执行仍待目标环境验收。")


def test_installers_have_locked_venv_installation_and_no_automatic_login():
    for name in ("install.ps1", "install.sh"):
        text = (ROOT / "scripts" / name).read_text(encoding="utf-8-sig")
        assert "--require-hashes" in text and "--no-deps" in text and "venv" in text
        assert "doctor" in text and "client-configs" in text
        assert "JST_CONNECTOR_MASTER_KEY=" not in text
        assert "-m jst_connector open" not in text
        assert "schtasks" not in text.lower() and "systemctl" not in text.lower()
