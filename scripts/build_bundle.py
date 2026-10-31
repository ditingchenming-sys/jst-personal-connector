"""白名单构建可分发 ZIP；不遍历和打包工作区运行资料。"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import zipfile
from configparser import ConfigParser
from configparser import Error as ConfigError
from email.parser import Parser
from pathlib import Path, PurePosixPath

PROJECT_NAME = "jst-personal-connector"
MANIFEST = "manifest.sha256.json"
FILES = ('README.md', 'INSTALL.md', 'AI接入说明.md', 'LICENSE', 'pyproject.toml', 'uv.lock', 'requirements.lock.txt', 'docs/通用探索与接口复用.md', 'scripts/install.ps1', 'scripts/install.sh', 'scripts/build_bundle.py', 'examples/system_integration.py')
MODULES = {
    "__init__.py", "__main__.py", "agent.py", "bridge.py", "browser.py", "cli.py", "client.py", "login_flow.py", "identity_probe.py", "auth_receipt.py",
    "config.py", "erp.py", "errors.py", "identity.py", "discovery_browser.py", "interface_registry.py",
    "ledger.py", "mcp_server.py", "service.py", "system_sdk.py",
    "system_runner.py", "vault.py", "management.html", "adapters/__init__.py", "adapters/login.py",
    "adapters/SOURCES.md",
}
DIST_INFO_FILES = {"METADATA", "WHEEL", "RECORD", "entry_points.txt"}


def _json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _path(name):
    if not isinstance(name, str) or not name or any(part in ("", ".", "..") for part in name.split("/")):
        raise ValueError("分发文件包含不安全的路径。")
    path = PurePosixPath(name)
    if ("\\" in name or path.is_absolute() or ":" in name
            or any(part in ("", ".", "..") or part.startswith(".") for part in path.parts)):
        raise ValueError("分发文件包含不安全的路径。")
    return path


def _wheel_metadata(content):
    with zipfile.ZipFile(io.BytesIO(content)) as wheel:
        names = wheel.namelist()
        if len(names) != len(set(names)):
            raise ValueError("wheel 包含重复路径。")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ValueError("wheel 缺少唯一的包元数据。")
        info_directory = str(_path(metadata_names[0]).parent)
        for item in wheel.infolist():
            path = _path(item.filename)
            if stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError("wheel 不允许包含符号链接。")
            if str(path).startswith("jst_connector/"):
                allowed = str(path)[len("jst_connector/"):] in MODULES
            else:
                allowed = ((str(path.parent) == info_directory and path.name in DIST_INFO_FILES)
                           or str(path) == f"{info_directory}/licenses/LICENSE")
            if not allowed:
                raise ValueError("wheel 包含源码白名单之外的文件，已拒绝分发。")
        metadata = Parser().parsestr(wheel.read(metadata_names[0]).decode("utf-8"))
        version = metadata.get("Version", "")
        if metadata.get("Name") != PROJECT_NAME or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:[A-Za-z0-9.+-]*)", version):
            raise ValueError("wheel 的项目名称或版本无效。")
        if info_directory != f"jst_personal_connector-{version}.dist-info":
            raise ValueError("wheel 元数据目录与版本不一致。")
        if metadata.get("License-Expression") != "MIT" or metadata.get_all("License-File") != ["LICENSE"]:
            raise ValueError("wheel 缺少明确的MIT许可证声明。")
        required = {"jst_connector/" + module for module in MODULES
                    if module.endswith(".py") or module == "management.html"}
        required.update(f"{info_directory}/{name}" for name in DIST_INFO_FILES)
        required.add(f"{info_directory}/licenses/LICENSE")
        if not required <= set(names):
            raise ValueError("wheel 缺少运行模块、管理页面、入口或必要元数据。")
        entry_points = ConfigParser(interpolation=None)
        try:
            entry_points.read_string(wheel.read(f"{info_directory}/entry_points.txt").decode("utf-8"))
            entry_point = entry_points.get("console_scripts", "jst-connector", fallback=None)
        except ConfigError:
            raise ValueError("wheel 的命令入口配置无效。") from None
        if entry_point != "jst_connector.cli:main":
            raise ValueError("wheel 缺少已核实的 jst-connector 命令入口。")
        if "Tag: py3-none-any" not in wheel.read(f"{info_directory}/WHEEL").decode("utf-8"):
            raise ValueError("当前分发仅接受独立于操作系统的纯 Python wheel。")
        return {"name": PROJECT_NAME, "version": version, "requires_python": metadata.get("Requires-Python")}


def _read(root, relative):
    path = root / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise ValueError(f"分发必需文件缺失或不是仓库内的普通文件：{relative}")
    return path.read_bytes()


def build_bundle(root: Path, output: Path, wheel: Path | None = None):
    root, output = root.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError("分发目标已存在，拒绝覆盖；请指定新文件名。")
    if wheel is None:
        candidates = list((root / "dist").glob("jst_personal_connector-*.whl"))
        if len(candidates) != 1:
            raise ValueError("需要唯一的本项目 wheel，请先 uv build --wheel 或显式指定 --wheel。")
        wheel = candidates[0]
    if wheel.is_symlink() or not wheel.is_file() or not re.fullmatch(r"jst_personal_connector-.+\.whl", wheel.name):
        raise ValueError("指定文件不是本项目的普通 wheel 文件。")
    wheel_content = wheel.read_bytes()
    metadata = _wheel_metadata(wheel_content)
    expected = f"jst_personal_connector-{metadata['version']}-py3-none-any.whl"
    if wheel.name != expected:
        raise ValueError("wheel 文件名与已审查的包版本或平台不一致。")
    payload = {relative: _read(root, relative) for relative in FILES}
    with zipfile.ZipFile(io.BytesIO(wheel_content)) as archive:
        if archive.read(f"jst_personal_connector-{metadata['version']}.dist-info/licenses/LICENSE") != payload["LICENSE"]:
            raise ValueError("wheel 的许可证全文与源码LICENSE不一致。")
    payload["wheels/" + wheel.name] = wheel_content
    metadata.update(schema_version=1, wheel="wheels/" + wheel.name,
                    contents_policy="显式白名单；不包含本机运行资料或凭据", real_business_verified=False)
    payload["bundle.json"] = _json(metadata)
    manifest = {"schema_version": 1, "algorithm": "sha256", "files": {
        name: {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        for name, content in payload.items()}}
    payload[MANIFEST] = _json(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(payload.items()):
            archive.writestr(name, content)
    return {"path": str(output), "files": len(payload), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "name": metadata["name"], "version": metadata["version"]}


def verify_directory(root: Path):
    root = root.resolve()
    manifest = json.loads(_read(root, MANIFEST))
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != 1
            or manifest.get("algorithm") != "sha256" or not isinstance(manifest.get("files"), dict)):
        raise ValueError("分发哈希清单格式无效。")
    files = manifest["files"]
    for name, expected in files.items():
        _path(name)
        if not isinstance(expected, dict):
            raise TypeError("分发哈希记录格式无效。")
        if name not in {*FILES, "bundle.json"} and not re.fullmatch(r"wheels/jst_personal_connector-[A-Za-z0-9_.+-]+\.whl", name):
            raise ValueError("哈希清单包含白名单之外的文件。")
        content = _read(root, name)
        if len(content) != expected.get("size") or hashlib.sha256(content).hexdigest() != expected.get("sha256"):
            raise ValueError(f"分发文件校验失败：{name}")
    metadata = json.loads(_read(root, "bundle.json"))
    if not isinstance(metadata, dict):
        raise TypeError("分发元数据格式无效。")
    wheel_name = metadata.get("wheel")
    if not {*FILES, "bundle.json", wheel_name} == set(files):
        raise ValueError("分发哈希清单缺少必要文件或存在额外文件。")
    _path(wheel_name)
    actual_metadata = _wheel_metadata(_read(root, wheel_name))
    with zipfile.ZipFile(io.BytesIO(_read(root, wheel_name))) as archive:
        if archive.read(f"jst_personal_connector-{actual_metadata['version']}.dist-info/licenses/LICENSE") != _read(root, "LICENSE"):
            raise ValueError("wheel 的许可证全文与源码LICENSE不一致。")
    if any(actual_metadata[key] != metadata.get(key) for key in ("name", "version", "requires_python")):
        raise ValueError("分发元数据与 wheel 不一致。")
    return {"ok": True, "files_verified": len(files), "version": metadata["version"]}


def main():
    parser = argparse.ArgumentParser(description="白名单构建或校验聚水潭连接器分发包")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--verify-directory", type=Path)
    args = parser.parse_args()
    try:
        if args.verify_directory:
            result = verify_directory(args.verify_directory)
        else:
            if args.output is None:
                parser.error("构建时必须提供 --output，已有目标不会覆盖。")
            result = build_bundle(args.root, args.output, args.wheel)
    except (OSError, TypeError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, "分发处理失败：" + str(error) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
