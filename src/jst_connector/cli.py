"""组件安装、诊断、MCP 与本机服务命令。"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from importlib.metadata import version
from pathlib import Path

from . import __version__
from .config import data_directory, profile_name
from .errors import ConnectorError


def _client_argument(value):
    try:
        return profile_name(value)
    except ConnectorError as error:
        raise argparse.ArgumentTypeError(error.message) from None


def _write_config(root: Path, client: str, kind: str, remote_url: str | None = None) -> str:
    args = ["-m", "jst_connector", "mcp", "--client", client, "--data-dir", str(root)]
    if remote_url:
        from .remote_client import public_origin
        args.extend(["--remote-url", public_origin(remote_url)])
    if kind == "codex":
        # JSON quoted basic strings are also valid TOML basic strings.
        return "[mcp_servers.jushuitan]\ncommand = " + json.dumps(sys.executable, ensure_ascii=False) + "\nargs = " + json.dumps(args, ensure_ascii=False) + "\nstartup_timeout_sec = 30\ntool_timeout_sec = 120\n"
    return json.dumps({"mcpServers": {"jushuitan": {"type": "stdio", "command": sys.executable,
                                                     "args": args, "timeout": 120000}}}, ensure_ascii=False, indent=2) + "\n"


def _store_employee_credential(destination: Path, issue):
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            def sink(value):
                stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            # EmployeeStore runs sink inside its transaction. File failure rolls back
            # account creation/rotation; a failed commit removes the unusable new file.
            return issue(sink)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="聚水潭个人连接器")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("init", "serve", "mcp", "open", "status", "catalog", "config", "doctor",
                    "serve-remote", "employee-add", "employee-token", "employee-disable"):
        part = sub.add_parser(command)
        part.add_argument("--data-dir", type=Path)
        if command in ("init", "mcp", "open", "status", "catalog", "config"):
            part.add_argument("--client", default="codex", type=_client_argument)
        if command == "serve":
            part.add_argument("--port", type=int, default=0)
        if command == "serve-remote":
            part.add_argument("--public-url", required=True, help="HTTPS 反向代理对外域名，如 https://jst.example.com")
            part.add_argument("--port", type=int, default=8765)
        if command in ("employee-add", "employee-token", "employee-disable"):
            part.add_argument("--username", required=True)
        if command in ("employee-add", "employee-token"):
            part.add_argument("--client", default="workbench", type=_client_argument)
            part.add_argument("--token-output", required=True, type=Path, help="员工调用凭证文件；须安全保管，不放入源码或安装包")
        if command == "employee-add":
            part.add_argument("--password-file", type=Path, help="可选：仅当前用户可读的员工密码文件；省略时隐藏输入")
        if command in ("mcp", "open", "status", "catalog", "config"):
            part.add_argument("--remote-url", help="远程组件 HTTPS 域名；访问凭证由 JST_CONNECTOR_ACCESS_TOKEN 提供")
        if command == "config":
            part.add_argument("--format", choices=("codex", "workbuddy", "generic"), required=True)
            part.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    root = data_directory(args.data_dir)
    try:
        if args.command in ("employee-add", "employee-token", "employee-disable"):
            from .remote import EmployeeStore
            from .vault import Vault
            store = EmployeeStore(root, Vault(root))
            if args.command == "employee-disable":
                store.disable(args.username)
                print(json.dumps({"ok": True, "message": "员工账号已禁用，调用授权及页面会话已撤销。"}, ensure_ascii=False))
                return
            destination = args.token_output.expanduser().resolve()
            if destination.exists():
                raise FileExistsError
            if destination.is_relative_to(Path(__file__).resolve().parents[2]):
                raise ConnectorError("unsafe_secret_destination", "员工调用凭证须保存到源码或安装目录之外。")
            if args.command == "employee-add":
                if args.password_file:
                    password_path = args.password_file.expanduser().resolve()
                    if os.name != "nt" and password_path.stat().st_mode & 0o077:
                        raise ConnectorError("unsafe_password_file", "员工密码文件须仅当前用户可读（chmod 600）。")
                    password = password_path.read_text(encoding="utf-8").rstrip("\r\n")
                else:
                    password = getpass.getpass("新员工登录密码（至少12位）：")
                    if password != getpass.getpass("再次输入员工登录密码："):
                        raise ConnectorError("password_mismatch", "两次密码不一致，未创建员工。")
                issued = _store_employee_credential(destination, lambda sink: store.create_employee(
                    args.username, password, args.client, issue_sink=sink))
            else:
                issued = _store_employee_credential(destination, lambda sink: store.issue_token(
                    args.username, args.client, issue_sink=sink))
            print(json.dumps({"ok": True, "username": issued["username"], "client": issued["client"],
                              "token_file": str(destination), "message": "员工调用凭证已写入指定文件，未在终端输出。"}, ensure_ascii=False))
            return
        if args.command == "serve-remote":
            from .remote import serve_remote
            serve_remote(root, origin=args.public_url, port=args.port)
            return
        if args.command == "doctor":
            from cryptography.fernet import Fernet
            from playwright.sync_api import sync_playwright

            from .vault import Vault, _dpapi
            key_error = None
            try:
                external_key = os.environ.get("JST_CONNECTOR_MASTER_KEY")
                if external_key:
                    Fernet(external_key.encode("ascii"))
                elif os.name == "nt":
                    probe = b"jst-local-diagnostic"
                    if _dpapi(_dpapi(probe), decrypt=True) != probe:
                        raise ConnectorError("key_protection_failed", "当前用户的密钥保护检查未通过。")
                else:
                    raise ConnectorError("master_key_required", "需要由运行环境提供独立主密钥。")
                if (root / "vault.enc").exists():
                    Vault(root)
            except (ConnectorError, ValueError, UnicodeError):
                key_error = "本组件的主密钥或加密资料检查未通过，请检查配置与资料完整性。"
            with sync_playwright() as playwright:
                browser_ready = Path(playwright.chromium.executable_path).is_file()
            ready = key_error is None and browser_ready
            info = {"ok": ready, "version": __version__, "python": sys.version.split()[0],
                    "platform": sys.platform, "data_dir": str(root),
                    "master_key_source": "environment" if os.environ.get("JST_CONNECTOR_MASTER_KEY") else "Windows DPAPI" if os.name == "nt" else "not_configured",
                    "checks": {"key": {"ready": key_error is None, "message": key_error or "密钥保护检查通过，未输出任何密钥或登录资料。"},
                               "chromium": {"ready": browser_ready, "message": "浏览器已安装。" if browser_ready else "请运行 python -m playwright install chromium。"}},
                    "business_ready": False,
                    "dependencies": {name: version(name) for name in ("mcp", "playwright", "cryptography", "fastapi")},
                    "notice": "诊断只检查本组件环境，不读取旧项目凭据、不发业务请求；环境就绪不代表真实业务已验收。"}
            print(json.dumps(info, ensure_ascii=False, indent=2))
            if not ready:
                raise SystemExit(1)
            return
        if args.command == "config":
            content = _write_config(root, args.client, args.format, args.remote_url)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                # 不覆盖用户已有配置，安装者按说明合并到对应客户端。
                with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(content)
                print(json.dumps({"ok": True, "path": str(args.output.resolve())}, ensure_ascii=False))
            else:
                print(content, end="")
            return
        if args.command == "serve":
            from .agent import serve
            serve(root, port=args.port)
            return
        if args.command == "mcp":
            from .mcp_server import create_server
            from .remote_client import RemoteAgentClient
            remote = RemoteAgentClient(args.remote_url) if args.remote_url else None
            create_server(root, args.client, client=remote).run(transport="stdio")
            return
        from .client import AgentClient
        if getattr(args, "remote_url", None):
            from .remote_client import RemoteAgentClient
            client = RemoteAgentClient(args.remote_url)
        else:
            client = AgentClient(root, args.client)
        if args.command == "init":
            result = {"ok": True, "client": args.client, "data_dir": str(root),
                      "message": "已初始化独立调用端；尚未登录聚水潭。"}
        else:
            action = {"open": "open-manager", "status": "status", "catalog": "catalog"}[args.command]
            result = client.call(action)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except ConnectorError as error:
        print(json.dumps(error.as_dict(), ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1) from None
    except FileExistsError:
        print(json.dumps({"ok": False, "error": {"code": "file_exists", "message": "目标配置已存在，未覆盖。"}}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1) from None
    except OSError:
        print(json.dumps({"ok": False, "error": {"code": "local_file_error", "message": "本地文件无法读取或写入，请检查指定路径和访问权限。"}}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1) from None

