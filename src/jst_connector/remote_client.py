"""通过员工专属调用授权访问远程组件；不在员工电脑创建或复制 ERP 会话。"""
from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

import httpx

from .errors import ConnectorError


def public_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.hostname and parsed.port in (None, 443)
                 and not parsed.username and not parsed.password and parsed.path in ("", "/")
                 and not parsed.query and not parsed.fragment and "\\" not in value
                 and not any(c.isspace() or ord(c) < 32 for c in value))
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ConnectorError("invalid_remote_origin", "远程地址须为独立 HTTPS 域名，不带路径、账号、查询串或片段。")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ConnectorError("invalid_remote_origin", "远程服务域名格式无效。") from None
    return "https://" + ("[" + host + "]" if ":" in host else host)


class RemoteAgentClient:
    def __init__(self, url: str, token: str | None = None, *, transport=None):
        self.url = public_origin(url)
        self.token = token if token is not None else os.environ.get("JST_CONNECTOR_ACCESS_TOKEN", "")
        if not isinstance(self.token, str) or not re.fullmatch(r"jst_remote_[A-Za-z0-9_-]{43}", self.token):
            raise ConnectorError("remote_token_required", "请由安全环境变量 JST_CONNECTOR_ACCESS_TOKEN 提供本员工本调用端的远程授权。")
        self._transport = transport

    def call(self, action: str, body: dict | None = None) -> dict:
        if not isinstance(action, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", action):
            raise ConnectorError("unsupported_action", "远程组件动作无效。")
        try:
            with httpx.Client(transport=self._transport, timeout=120, trust_env=False,
                              follow_redirects=False) as client:
                response = client.post(self.url + "/api/" + action, json=body or {},
                                       headers={"Authorization": "Bearer " + self.token})
            if 300 <= response.status_code < 400:
                raise ConnectorError("remote_redirect_rejected", "远程组件返回重定向，已停止；请核实配置地址和任务结果。")
            result = response.json()
            if not isinstance(result, dict):
                raise TypeError("invalid response")
            if response.status_code >= 400:
                error = result.get("error", {})
                raise ConnectorError(error.get("code", "remote_error"),
                                     error.get("message", "远程组件调用失败。"), details=error.get("details", {}))
            return result
        except (httpx.HTTPError, ValueError, TypeError):
            raise ConnectorError("remote_unreachable", "无法取得远程组件结果；写入须先核对原预览状态，不能重复提交。") from None
