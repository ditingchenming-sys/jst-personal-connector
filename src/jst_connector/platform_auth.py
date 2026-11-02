"""可信平台后端的短时签名授权；浏览器与调用令牌不能自报员工身份。"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

from .config import profile_name
from .errors import ConnectorError
from .vault import _json

CHALLENGE_COOKIE = "__Host-jst-platform"
FLOW_TTL = 120
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{20,128}")
_BASE_CLAIMS = {"version", "issuer", "audience", "action", "tenant", "subject", "client", "request_id", "issued_at", "expires_at"}


def _fail(message="平台授权无法验证，请返回原平台重新发起。", code="platform_proof_invalid"):
    raise ConnectorError(code, message)


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _identifier(value, label, maximum=256):
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum or value != value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        _fail(label + "格式无效。")
    return value


class PlatformRegistry:
    """与 EmployeeStore 同库，proof、授权流和员工变更使用一个事务。

    成功重新登记必须换用从未登记过的新密钥。新 generation 使旧签名、
    challenge、code、浏览器会话和平台调用令牌全部失效；重新 provision
    保持原随机 profile。管理员停用的主体不会被 provision 自动复活。
    """

    def __init__(self, root, vault, *, employees=None):
        self.root, self.vault = Path(root), vault
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / "employees.sqlite3"
        self._employees = employees
        with self._connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS platform_registrations (issuer TEXT PRIMARY KEY,encrypted TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS platform_key_history (issuer TEXT NOT NULL,fingerprint TEXT NOT NULL,PRIMARY KEY(issuer,fingerprint))")
            conn.execute("CREATE TABLE IF NOT EXISTS platform_subjects (id TEXT PRIMARY KEY,encrypted TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS platform_replays (id TEXT PRIMARY KEY,expires REAL NOT NULL)")
            conn.execute("""CREATE TABLE IF NOT EXISTS platform_challenges (
                id TEXT PRIMARY KEY,issuer TEXT NOT NULL,username TEXT NOT NULL,connection_id TEXT NOT NULL,
                browser_hash TEXT NOT NULL,encrypted TEXT NOT NULL,expires REAL NOT NULL)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS platform_codes (
                id TEXT PRIMARY KEY,issuer TEXT NOT NULL,username TEXT NOT NULL,connection_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL,browser_hash TEXT NOT NULL,encrypted TEXT NOT NULL,expires REAL NOT NULL)""")
        self.path.chmod(0o600)

    @contextmanager
    def _connection(self, write=False):
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            if write:
                conn.commit()
        except BaseException:
            if write:
                conn.rollback()
            raise
        finally:
            conn.close()

    def _store(self):
        if self._employees is None:
            from .remote import EmployeeStore
            self._employees = EmployeeStore(self.root, self.vault)
        return self._employees

    def _registration(self, conn, issuer, *, require_enabled=True):
        row = conn.execute("SELECT encrypted FROM platform_registrations WHERE issuer=?", (issuer,)).fetchone()
        record = self.vault.unseal(row[0]) if row else None
        if not record or record.get("issuer") != issuer or require_enabled and record.get("enabled") is not True:
            _fail("平台尚未登记或已停用，请联系接入平台管理员。", "platform_not_registered")
        return record

    @staticmethod
    def _login_url(value):
        if not isinstance(value, str) or len(value) > 2048:
            _fail("平台登录地址须为固定HTTPS地址。")
        try:
            parts = urlsplit(value)
            if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
                    or parts.port not in (None, 443) or parts.fragment or "\\" in value
                    or any(char.isspace() or ord(char) < 32 for char in value)
                    or set(parse_qs(parts.query, keep_blank_values=True)) & {"challenge", "audience"}):
                raise ValueError
        except (ValueError, TypeError):
            _fail("平台登录地址须为固定HTTPS地址，不得含账号、片段或预置challenge/audience。")
        return value

    def _invalidate_issuer(self, conn, issuer):
        for table in ("platform_challenges", "platform_codes"):
            conn.execute(f"DELETE FROM {table} WHERE issuer=?", (issuer,))
        exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='browser_sessions'").fetchone()
        if exists:
            for row in conn.execute("SELECT id,encrypted FROM browser_sessions").fetchall():
                record = self.vault.unseal(row["encrypted"])
                if record.get("auth_method") == "platform" and record.get("issuer") == issuer:
                    conn.execute("DELETE FROM browser_sessions WHERE id=?", (row["id"],))

    def register(self, issuer, login_url, secret: bytes, tenants: list[str]):
        issuer = _identifier(issuer, "平台标识", 128)
        login_url = self._login_url(login_url)
        if not isinstance(secret, bytes) or not 32 <= len(secret) <= 4096:
            _fail("平台签名密钥须为32至4096个原始字节。")
        if not isinstance(tenants, list) or not 1 <= len(tenants) <= 1000:
            _fail("至少登记一个允许的租户，最多1000项。")
        tenants = sorted({_identifier(tenant, "平台租户") for tenant in tenants})
        fingerprint = hashlib.sha256(secret).hexdigest()
        with self._connection(True) as conn:
            if conn.execute("SELECT 1 FROM platform_key_history WHERE fingerprint=?", (fingerprint,)).fetchone():
                _fail("该平台曾使用此签名密钥，请提供全新的密钥；旧密钥不能重复启用。", "platform_key_reuse")
            record = {"issuer": issuer, "login_url": login_url, "secret_hex": secret.hex(), "tenants": tenants,
                      "generation": secrets.token_urlsafe(24), "enabled": True, "registered_at": time.time()}
            conn.execute("INSERT INTO platform_key_history VALUES (?,?)", (issuer, fingerprint))
            conn.execute("INSERT INTO platform_registrations VALUES (?,?) ON CONFLICT(issuer) DO UPDATE SET encrypted=excluded.encrypted",
                         (issuer, self.vault.seal(record)))
            self._invalidate_issuer(conn, issuer)
        return {"ok": True, "issuer": issuer, "login_url": login_url, "tenants": tenants,
                "generation": record["generation"], "message": "已登记可信平台；旧授权已失效，需由平台重新签发连接授权。"}

    def disable(self, issuer):
        issuer = _identifier(issuer, "平台标识", 128)
        with self._connection(True) as conn:
            record = self._registration(conn, issuer, require_enabled=False)
            record["enabled"] = False
            conn.execute("UPDATE platform_registrations SET encrypted=? WHERE issuer=?", (self.vault.seal(record), issuer))
            self._invalidate_issuer(conn, issuer)
        return {"ok": True, "issuer": issuer, "message": "已停用此平台的签名、调用令牌与浏览器授权；业务登录资料仍独立保留。"}

    @staticmethod
    def external_current(conn, vault, employee, connection, *, generation=None):
        """Current registry state is checked on every bearer/session/flow use."""
        external = employee.get("external", {})
        issuer = external.get("issuer")
        row = conn.execute("SELECT encrypted FROM platform_registrations WHERE issuer=?", (issuer,)).fetchone()
        registration = vault.unseal(row[0]) if row else None
        return bool(registration and registration.get("enabled") is True
                    and external.get("tenant") in registration["tenants"]
                    and connection.get("platform_generation") == registration["generation"]
                    and (generation is None or generation == registration["generation"]))

    @staticmethod
    def _namespace(issuer, tenant, subject):
        return hashlib.sha256(_json([issuer, tenant, subject])).hexdigest()

    def _subject(self, conn, issuer, tenant, subject):
        row = conn.execute("SELECT encrypted FROM platform_subjects WHERE id=?", (self._namespace(issuer, tenant, subject),)).fetchone()
        if not row:
            return None
        record = self.vault.unseal(row[0])
        if (record.get("issuer"), record.get("tenant"), record.get("subject")) != (issuer, tenant, subject):
            _fail("外部身份映射无法验证。")
        return record

    def _proof(self, conn, envelope, origin):
        if not isinstance(envelope, dict) or set(envelope) != {"claims", "signature"}:
            _fail()
        claims, signature = envelope["claims"], envelope["signature"]
        if not isinstance(claims, dict):
            _fail()
        action = claims.get("action")
        if not isinstance(action, str) or action not in {"provision", "authorize", "disable"} or set(claims) != _BASE_CLAIMS | ({"challenge"} if action == "authorize" else set()):
            _fail()
        if type(claims["version"]) is not int or claims["version"] != 1 or claims["audience"] != origin:
            _fail()
        issuer = _identifier(claims["issuer"], "平台标识", 128)
        for field in ("tenant", "subject"):
            _identifier(claims[field], "平台主体")
        profile_name(claims["client"])
        request_id = _identifier(claims["request_id"], "授权请求编号", 128)
        if len(request_id) < 16:
            _fail("授权请求编号须为至少16个字符的唯一编号。")
        issued, expires, now = claims["issued_at"], claims["expires_at"], time.time()
        if (type(issued) is not int or type(expires) is not int or not 0 < expires - issued <= FLOW_TTL
                or issued > now + 10 or expires <= now):
            _fail("平台授权已过期或时间范围无效，请重新发起。", "platform_proof_expired")
        registration = self._registration(conn, issuer)
        if claims["tenant"] not in registration["tenants"]:
            _fail("该平台租户未获此连接器授权。")
        if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
            _fail()
        expected = hmac.new(bytes.fromhex(registration["secret_hex"]), _json(claims), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            _fail()
        replay_id = hashlib.sha256(_json([issuer, registration["generation"], request_id])).hexdigest()
        conn.execute("DELETE FROM platform_replays WHERE expires < ?", (now,))
        try:
            conn.execute("INSERT INTO platform_replays VALUES (?,?)", (replay_id, now + 86400))
        except sqlite3.IntegrityError:
            _fail("此平台授权请求已经使用，不能重复提交。", "platform_replay")
        return claims, registration

    def _invalidate_connection(self, conn, username, connection_id=None):
        for table in ("platform_challenges", "platform_codes"):
            if connection_id is None:
                conn.execute(f"DELETE FROM {table} WHERE username=?", (username,))
            else:
                conn.execute(f"DELETE FROM {table} WHERE username=? AND connection_id=?", (username, connection_id))

    def integration(self, envelope, origin):
        store = self._store()
        with self._connection(True) as conn:
            claims, registration = self._proof(conn, envelope, origin)
            mapping = self._subject(conn, claims["issuer"], claims["tenant"], claims["subject"])
            employee = store._employee(conn, mapping["username"]) if mapping else None
            if employee and (employee.get("auth_method") != "platform" or employee.get("external") != {
                    field: claims[field] for field in ("issuer", "tenant", "subject")}):
                _fail("平台主体映射未通过核验，不能合并到已有员工。")
            if claims["action"] == "provision":
                if mapping and (not employee or not employee["enabled"]):
                    _fail("该平台主体已由管理员停用，不能通过重新分配连接恢复。", "platform_subject_disabled")
                if employee is None:
                    username = "external-" + secrets.token_hex(20)
                    if store._employee(conn, username) is not None:
                        _fail("无法分配独立的平台主体标识，请重新发起。")
                    external = {field: claims[field] for field in ("issuer", "tenant", "subject")}
                    employee = {"username": username, "auth_method": "platform", "display_name": "平台授权用户",
                                "external": external, "connections": [], "enabled": True}
                    mapping = {**external, "username": username}
                    conn.execute("INSERT INTO platform_subjects VALUES (?,?)",
                                 (self._namespace(*[claims[field] for field in ("issuer", "tenant", "subject")]), self.vault.seal(mapping)))
                connection = next((item for item in employee["connections"] if item["client"] == claims["client"]), None)
                if connection is None:
                    connection, token = store._connection_record(claims["client"])
                    employee["connections"].append(connection)
                else:
                    token = "jst_remote_" + secrets.token_urlsafe(32)
                    connection["token_hash"] = _hash(token)
                    store._revoke_connection_sessions(conn, employee["username"], connection["connection_id"])
                    self._invalidate_connection(conn, employee["username"], connection["connection_id"])
                connection["platform_generation"] = registration["generation"]
                store._save(conn, employee)
                return {"ok": True, **store._issued(employee, connection, token), "auth_method": "platform"}
            if not employee or not employee["enabled"] or employee.get("auth_method") != "platform":
                _fail("平台主体尚未分配连接或已停用。", "platform_subject_disabled")
            if claims["action"] == "disable":
                employee["enabled"] = False
                store._save(conn, employee)
                store._revoke_sessions(conn, employee["username"])
                self._invalidate_connection(conn, employee["username"])
                return {"ok": True, "message": "已停用此平台主体的全部连接授权。"}
            challenge = claims["challenge"]
            if not isinstance(challenge, str) or not _OPAQUE.fullmatch(challenge):
                _fail()
            row = conn.execute("SELECT encrypted,expires FROM platform_challenges WHERE id=?", (_hash(challenge),)).fetchone()
            flow = self.vault.unseal(row["encrypted"]) if row else None
            if (not flow or row["expires"] <= time.time() or flow.get("state") != "pending"
                    or any(flow[field] != claims[field] for field in ("issuer", "tenant", "subject", "client"))):
                _fail("浏览器授权请求不匹配或已过期，请从原平台重新打开。", "platform_challenge_invalid")
            connection = self._flow_connection(conn, flow, employee)
            if connection["connection_id"] != flow["connection_id"]:
                _fail()
            code = secrets.token_urlsafe(32)
            expiry = min(row["expires"], claims["expires_at"], time.time() + FLOW_TTL)
            flow["state"] = "authorized"
            conn.execute("UPDATE platform_challenges SET encrypted=? WHERE id=?", (self.vault.seal(flow), _hash(challenge)))
            conn.execute("INSERT INTO platform_codes VALUES (?,?,?,?,?,?,?,?)",
                         (_hash(code), flow["issuer"], flow["username"], flow["connection_id"], _hash(challenge),
                          flow["browser_hash"], self.vault.seal(flow), expiry))
            return {"ok": True, "redirect_url": origin + "/login#platform_code=" + code}

    def _lookup_connection(self, conn, identifier):
        if not isinstance(identifier, str) or not _OPAQUE.fullmatch(identifier):
            _fail("此连接已失效，请返回原平台重新打开。", "platform_connection_invalid")
        for row in conn.execute("SELECT encrypted FROM employees"):
            employee = self.vault.unseal(row[0])
            connection = next((item for item in employee["connections"] if item["connection_id"] == identifier), None)
            if connection:
                if not employee["enabled"]:
                    _fail("此连接已停用。", "platform_connection_invalid")
                if employee.get("auth_method") == "platform" and not self.external_current(conn, self.vault, employee, connection):
                    _fail("平台连接授权已失效，请由原平台重新分配。", "platform_connection_invalid")
                return employee, connection
        _fail("此连接不存在或已失效，请返回原平台重新打开。", "platform_connection_invalid")

    def auth_options(self, connection_id=None):
        if connection_id is None:
            return {"ok": True, "mode": "password"}
        self._store()
        with self._connection() as conn:
            employee, _ = self._lookup_connection(conn, connection_id)
            if employee.get("auth_method") != "platform":
                return {"ok": True, "mode": "password"}
            return {"ok": True, "mode": "platform", "issuer": employee["external"]["issuer"], "login_label": "返回平台继续授权"}

    @staticmethod
    def _next(value, connection_id, area):
        if value is None:
            return None
        if not isinstance(value, str) or len(value) > 1024 or "\\" in value or any(ord(char) < 32 for char in value):
            _fail("授权后的返回页面无效。")
        try:
            parts = urlsplit(value)
        except ValueError:
            _fail("授权后的返回页面无效。")
        query = parse_qs(parts.query, keep_blank_values=True)
        if (parts.scheme or parts.netloc or parts.fragment or not re.fullmatch(r"/operations/[A-Za-z0-9_-]{16,80}", parts.path)
                or set(query) - {"connection", "area"} or any(len(values) != 1 for values in query.values())
                or "connection" in query and query["connection"] != [connection_id]
                or "area" in query and (query["area"][0] not in {"erp", "drp"} or area is not None and query["area"] != [area])):
            _fail("授权后的返回页面须为本连接的操作确认页。")
        return value

    def start(self, connection_id, origin, *, peer, next_path=None, area=None, old_cookie=None):
        if area is not None and (not isinstance(area, str) or area not in {"erp", "drp"}):
            _fail("业务板块无效。")
        next_path = self._next(next_path, connection_id, area)
        store = self._store()
        with self._connection(True) as conn:
            store._limit(conn, "platform-peer:" + peer, 120, 300)
            store._limit(conn, "platform-connection:" + str(connection_id), 12, 300)
        with self._connection(True) as conn:
            employee, connection = self._lookup_connection(conn, connection_id)
            if employee.get("auth_method") != "platform":
                _fail("此连接使用原有员工登录方式。", "platform_connection_invalid")
            external = employee["external"]
            registration = self._registration(conn, external["issuer"])
            challenge, browser_cookie = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            now = time.time()
            for table in ("platform_challenges", "platform_codes"):
                conn.execute(f"DELETE FROM {table} WHERE expires < ?", (now,))
                if isinstance(old_cookie, str):
                    conn.execute(f"DELETE FROM {table} WHERE browser_hash=?", (_hash(old_cookie),))
            flow = {**external, "username": employee["username"], "client": connection["client"],
                    "connection_id": connection_id, "profile": connection["profile"],
                    "token_hash": connection["token_hash"], "generation": registration["generation"],
                    "browser_hash": _hash(browser_cookie), "audience": origin, "state": "pending",
                    "next": next_path, "area": area}
            conn.execute("INSERT INTO platform_challenges VALUES (?,?,?,?,?,?,?)",
                         (_hash(challenge), external["issuer"], employee["username"], connection_id,
                          flow["browser_hash"], self.vault.seal(flow), now + FLOW_TTL))
            parts = urlsplit(registration["login_url"])
            query = [*parse_qsl(parts.query, keep_blank_values=True), ("challenge", challenge), ("audience", origin)]
            login_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
            return {"ok": True, "login_url": login_url}, browser_cookie

    def _flow_connection(self, conn, flow, employee):
        if (employee.get("auth_method") != "platform" or not employee["enabled"]
                or employee["external"] != {field: flow[field] for field in ("issuer", "tenant", "subject")}
                or employee["username"] != flow["username"]):
            _fail("浏览器授权主体已变化，请重新发起。", "platform_challenge_invalid")
        connection = next((item for item in employee["connections"] if item["connection_id"] == flow["connection_id"]), None)
        if (connection is None or connection["profile"] != flow["profile"] or connection["client"] != flow["client"]
                or not hmac.compare_digest(connection["token_hash"], flow["token_hash"])
                or not self.external_current(conn, self.vault, employee, connection, generation=flow["generation"])):
            _fail("连接授权已更新或撤销，请从原平台重新打开。", "platform_challenge_invalid")
        return connection

    def login(self, code, browser_cookie, origin):
        if (not isinstance(code, str) or not _OPAQUE.fullmatch(code) or not isinstance(browser_cookie, str)
                or not _OPAQUE.fullmatch(browser_cookie)):
            _fail("平台回调已失效，请返回原平台重新打开连接。", "platform_code_invalid")
        store = self._store()
        with self._connection(True) as conn:
            row = conn.execute("SELECT * FROM platform_codes WHERE id=?", (_hash(code),)).fetchone()
            flow = self.vault.unseal(row["encrypted"]) if row else None
            challenge = conn.execute("SELECT encrypted,expires FROM platform_challenges WHERE id=?", (row["challenge_id"],)).fetchone() if row else None
            if (not flow or row["expires"] <= time.time() or flow["audience"] != origin
                    or not hmac.compare_digest(flow["browser_hash"], _hash(browser_cookie))
                    or not challenge or challenge["expires"] <= time.time()
                    or self.vault.unseal(challenge["encrypted"]) != flow):
                _fail("平台回调与当前浏览器不匹配或已过期，请返回原平台重新打开。", "platform_code_invalid")
            employee = store._employee(conn, flow["username"])
            if employee is None:
                _fail()
            connection = self._flow_connection(conn, flow, employee)
            token, session = store._create_browser_session(conn, employee, connection, auth_method="platform", generation=flow["generation"])
            conn.execute("DELETE FROM platform_codes WHERE id=?", (_hash(code),))
            conn.execute("DELETE FROM platform_challenges WHERE id=?", (row["challenge_id"],))
            return token, session, {key: flow[key] for key in ("next", "area") if flow[key] is not None}
