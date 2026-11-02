"""启动配置固定平台；业务请求不能切换存储目录的授权域。"""
from __future__ import annotations

import json
from pathlib import Path

from filelock import FileLock

from .config import platform_name
from .errors import ConnectorError
from .vault import _atomic_write


def ensure_platform(root: Path, platform="erp") -> str:
    platform = platform_name(platform)
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = root / ".platform.json"
    with FileLock(str(root / ".platform.lock"), timeout=30, mode=0o600):
        if marker.is_symlink():
            raise ConnectorError("platform_store_invalid", "平台绑定文件无效，请核对运行目录。")
        if marker.exists():
            try:
                value = json.loads(marker.read_text(encoding="utf-8"))
            except (ValueError, UnicodeError, OSError):
                raise ConnectorError("platform_store_invalid", "运行目录的平台绑定文件无法验证。") from None
            if value != {"schema_version": 1, "platform": platform}:
                raise ConnectorError("platform_mismatch", "此运行目录已绑定其他平台，请为ERP和分销使用各自独立目录。")
        else:
            # All previously released stores are ERP. Never reinterpret their cookies as SCM.
            previous_files = ("vault.enc", "masterkey.dpapi", "agent.json", "ledger.sqlite3", "employees.sqlite3",
                              "interfaces.sqlite3", "write-interfaces.sqlite3", "sso-links.sqlite3")
            if platform != "erp" and any((root / name).exists() for name in previous_files):
                raise ConnectorError("platform_mismatch", "此目录已有历史ERP资料；分销平台须使用新的独立运行目录。")
            _atomic_write(marker, (json.dumps({"schema_version": 1, "platform": platform}) + "\n").encode())
    return platform
