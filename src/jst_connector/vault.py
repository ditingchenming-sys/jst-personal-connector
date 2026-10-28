"""个人会话与组件凭证的加密存储；不读取其他项目的任何资料。"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from filelock import FileLock

from .errors import ConnectorError

_UNSET = object()


def _json(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (ValueError, TypeError) as exc:
        raise ConnectorError("invalid_data", "资料必须是有效的 JSON 数据。") from exc


def _profile(profile: str) -> str:
    if not isinstance(profile, str) or not profile.strip() or len(profile) > 256:
        raise ConnectorError("invalid_profile", "调用端标识无效。")
    return profile


def _identity(identity: dict) -> dict:
    if not isinstance(identity, dict) or any(
        isinstance(identity.get(field), bool) or not isinstance(identity.get(field), (str, int))
        or not str(identity[field]).strip() for field in ("company_id", "user_id")
    ):
        raise ConnectorError("invalid_identity", "缺少经过验证的公司或员工身份。")
    return json.loads(_json(identity))


def _atomic_write(path: Path, content: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".secure-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _dpapi(value: bytes, *, decrypt: bool = False) -> bytes:
    """当前 Windows 用户保护；禁止机器范围解密，禁止弹出系统对话框。"""
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    function.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    source = Blob(len(value), buffer)
    output = Blob()
    if not function(ctypes.byref(source), None, None, None, None, 0x01, ctypes.byref(output)):
        raise ConnectorError("key_protection_failed", "无法使用当前 Windows 用户保护或恢复密钥。")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)


class Vault:
    def __init__(self, root: Path, key: bytes | None = None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._path = self.root / "vault.enc"
        self._lock = FileLock(str(self.root / ".vault.lock"), mode=0o600)
        with self._lock:
            if key is None:
                key = self._load_key()
            try:
                self._cipher = Fernet(key)
            except (TypeError, ValueError) as exc:
                raise ConnectorError("invalid_master_key", "主密钥格式无效，请提供 Fernet 密钥。") from exc
            if self._path.exists():
                self._read()

    def _load_key(self) -> bytes:
        external = os.environ.get("JST_CONNECTOR_MASTER_KEY")
        if external:
            try:
                return external.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ConnectorError("invalid_master_key", "主密钥格式无效。") from exc
        if os.name != "nt":
            raise ConnectorError("master_key_required", "此环境必须提供独立主密钥 JST_CONNECTOR_MASTER_KEY。")
        path = self.root / "masterkey.dpapi"
        if path.exists():
            return _dpapi(path.read_bytes(), decrypt=True)
        if self._path.exists():
            raise ConnectorError("master_key_missing", "加密资料的主密钥缺失，不能生成替代密钥。")
        key = Fernet.generate_key()
        _atomic_write(path, _dpapi(key))
        return key

    def seal(self, value: Any) -> str:
        return self._cipher.encrypt(_json(value)).decode("ascii")

    def unseal(self, value: str) -> Any:
        try:
            return json.loads(self._cipher.decrypt(value.encode("ascii")))
        except (InvalidToken, ValueError, TypeError, AttributeError, UnicodeError) as exc:
            raise ConnectorError("encrypted_data_invalid", "加密资料无法验证，请检查密钥或资料完整性。") from exc

    def _read(self) -> dict:
        if not self._path.exists():
            return {"version": 1, "sessions": {}, "clients": {}, "manager": None}
        try:
            encrypted = self._path.read_text(encoding="ascii")
        except UnicodeError as exc:
            raise ConnectorError("encrypted_data_invalid", "加密资料无法验证，请检查密钥或资料完整性。") from exc
        value = self.unseal(encrypted)
        if not isinstance(value, dict) or value.get("version") != 1 or not all(
            isinstance(value.get(field), dict) for field in ("sessions", "clients")
        ):
            raise ConnectorError("vault_invalid", "个人资料存储格式无效。")
        return value

    def _write(self, value: dict) -> None:
        _atomic_write(self._path, self.seal(value).encode("ascii"))

    def save_session(self, profile: str, state: dict, identity: dict, credentials=None,
                     *, expected_binding: Any = _UNSET) -> None:
        profile = _profile(profile)
        identity = _identity(identity)
        if not isinstance(state, dict):
            raise ConnectorError("invalid_session", "登录状态格式无效。")
        with self._lock:
            data = self._read()
            existing = data["sessions"].get(profile)
            if expected_binding is not _UNSET:
                matches = (existing is None if expected_binding is None else
                           isinstance(expected_binding, str) and existing is not None
                           and secrets.compare_digest(existing["binding"].encode(), expected_binding.encode()))
                if not matches:
                    raise ConnectorError("session_changed", "登录状态已退出或更新，不能用旧浏览器资料恢复该会话。")
            if existing and existing["identity"] != identity:
                raise ConnectorError("account_switch_requires_logout", "当前调用端已有账号，请先退出后再切换账号。")
            data["sessions"][profile] = {
                "state": state, "identity": identity, "credentials": credentials,
                "binding": existing["binding"] if existing else secrets.token_urlsafe(32),
            }
            self._write(data)

    def load_session(self, profile: str) -> dict | None:
        with self._lock:
            session = self._read()["sessions"].get(_profile(profile))
            if session is None:
                return None
            return {field: session[field] for field in ("state", "identity", "credentials")}

    def session_binding(self, profile: str) -> str | None:
        """仅组件内部使用，使退出后重新登录不能复用旧的执行授权。"""
        with self._lock:
            session = self._read()["sessions"].get(_profile(profile))
            return session["binding"] if session else None

    def clear_session(self, profile: str) -> None:
        with self._lock:
            data = self._read()
            data["sessions"].pop(_profile(profile), None)
            self._write(data)

    def ensure_client(self, profile: str) -> str:
        with self._lock:
            data = self._read()
            profile = _profile(profile)
            if profile not in data["clients"]:
                data["clients"][profile] = "client_" + secrets.token_urlsafe(32)
                self._write(data)
            return data["clients"][profile]

    def client_for_token(self, token: str) -> str | None:
        if not isinstance(token, str) or not token:
            return None
        with self._lock:
            for profile, candidate in self._read()["clients"].items():
                if secrets.compare_digest(token.encode("utf-8"), candidate.encode("utf-8")):
                    return profile
        return None

    def manager_token(self) -> str:
        with self._lock:
            data = self._read()
            if data["manager"] is None:
                data["manager"] = "manager_" + secrets.token_urlsafe(32)
                self._write(data)
            return data["manager"]

    @staticmethod
    def profile_key(profile: str) -> str:
        """供本地隔离目录使用，不把调用端输入拼接到文件路径。"""
        return hashlib.sha256(_profile(profile).encode("utf-8")).hexdigest()
