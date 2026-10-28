"""本地组件客户端，供 stdio MCP 使用；组件可独立于 AI 进程保留。"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from filelock import FileLock

from .config import profile_name
from .errors import ConnectorError
from .vault import Vault


def validate_agent_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port
                 and not parsed.username and not parsed.password and parsed.path in ("", "/")
                 and not parsed.query and not parsed.fragment)
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ConnectorError("invalid_agent_address", "组件地址必须是本机回环地址。")
    return url.rstrip("/")


class AgentClient:
    def __init__(self, root: Path, profile: str, *, auto_start=True):
        self.root = Path(root)
        self.profile = profile_name(profile)
        self.vault = Vault(self.root)
        self.token = self.vault.ensure_client(self.profile)
        self.auto_start = auto_start

    def _running_url(self) -> str | None:
        state = self.root / "agent.json"
        if not state.exists():
            return None
        try:
            url = validate_agent_url(json.loads(state.read_text(encoding="utf-8"))["url"])
            response = httpx.get(url + "/health", timeout=1, trust_env=False, follow_redirects=False)
            if response.status_code == 200 and response.json().get("ok") is True:
                return url
        except (OSError, ValueError, KeyError, httpx.HTTPError, ConnectorError):
            pass
        return None

    def ensure_running(self) -> str:
        with FileLock(str(self.root / ".agent-start.lock"), timeout=30, mode=0o600):
            url = self._running_url()
            if url:
                return url
            if not self.auto_start:
                raise ConnectorError("agent_offline", "员工组件当前未运行。")
            kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
            else:
                kwargs["start_new_session"] = True
            subprocess.Popen([sys.executable, "-m", "jst_connector", "serve", "--data-dir", str(self.root)], **kwargs)
            for _ in range(100):
                time.sleep(0.1)
                url = self._running_url()
                if url:
                    return url
        raise ConnectorError("agent_start_failed", "组件未能启动，请运行 jst-connector doctor 检查依赖和密钥。")

    def call(self, action: str, body: dict | None = None) -> dict:
        url = self.ensure_running()
        try:
            response = httpx.post(url + "/api/" + action, json=body or {},
                                  headers={"Authorization": "Bearer " + self.token}, timeout=90,
                                  trust_env=False, follow_redirects=False)
            result = response.json()
            if not isinstance(result, dict):
                raise TypeError("组件响应必须是 JSON 对象")
            if response.status_code >= 400:
                error = result.get("error", {})
                raise ConnectorError(error.get("code", "agent_error"), error.get("message", "组件调用失败。"),
                                     details=error.get("details", {}))
            return result
        except (httpx.HTTPError, ValueError, TypeError):
            raise ConnectorError("agent_unreachable", "无法取得组件响应；写入任务须先查询原任务状态，不要重新提交。") from None

