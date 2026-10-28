"""面向调用方的中文错误。"""

class ConnectorError(Exception):
    def __init__(self, code: str, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def as_dict(self) -> dict:
        return {"ok": False, "error": {"code": self.code, "message": self.message, "details": self.details}}

