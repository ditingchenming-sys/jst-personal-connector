"""组件配置；不读取旧项目、当前目录 .env 或浏览器资料。"""
from __future__ import annotations

import os
import re
from pathlib import Path

from .errors import ConnectorError


def data_directory(value: str | Path | None = None) -> Path:
    if value is not None:
        return Path(value).expanduser().resolve()
    configured = os.environ.get("JST_CONNECTOR_DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "jst-personal-connector"


def profile_name(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", value):
        raise ConnectorError("invalid_profile", "调用端标识须以小写字母开头，仅含字母、数字、点、下划线或连字符，最长64位。")
    return value

