"""组件配置；不读取旧项目、当前目录 .env 或浏览器资料。"""
from __future__ import annotations

import os
import re
from pathlib import Path

from .errors import ConnectorError


def platform_name(value: str) -> str:
    if not isinstance(value, str) or value not in {"erp", "drp"}:
        raise ConnectorError("invalid_platform", "平台须为 erp（聚水潭ERP）或 drp（分销平台）。")
    return value


def data_directory(value: str | Path | None = None, *, platform="erp") -> Path:
    platform = platform_name(platform)
    if value is not None:
        return Path(value).expanduser().resolve()
    configured = os.environ.get("JST_CONNECTOR_DATA_DIR")
    if configured:
        base = Path(configured).expanduser().resolve()
        return base / "drp" if platform == "drp" else base
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    root = base / "jst-personal-connector"
    return root / "drp" if platform == "drp" else root


def profile_name(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", value):
        raise ConnectorError("invalid_profile", "调用端标识须以小写字母开头，仅含字母、数字、点、下划线或连字符，最长64位。")
    return value

