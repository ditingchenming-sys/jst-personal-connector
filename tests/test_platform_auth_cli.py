"""平台信任配置只由本机管理命令完成；密钥不出现在回执或明文库。"""
import json
import os

import pytest
from cryptography.fernet import Fernet

from jst_connector.cli import main


@pytest.fixture
def registration(tmp_path, monkeypatch):
    monkeypatch.setenv("JST_CONNECTOR_MASTER_KEY", Fernet.generate_key().decode())
    secret = os.urandom(32)
    key = tmp_path / "private-platform-key"
    key.write_bytes(secret)
    key.chmod(0o600)
    root = tmp_path / "connector"
    args = ["platform-register", "--data-dir", str(root), "--issuer", "business-platform",
            "--login-url", "https://workbench.example.com/jst/authorize", "--tenant", "corp-a",
            "--secret-file", str(key)]
    return root, key, secret, args


def test_local_registration_and_disable_do_not_expose_secret(registration, capsys):
    root, _key, secret, args = registration
    main(args)
    captured = capsys.readouterr()
    assert json.loads(captured.out)["ok"] is True and not captured.err
    assert secret.hex() not in captured.out and str(secret) not in captured.out
    for path in root.glob("*.sqlite3"):
        assert secret not in path.read_bytes()
    main(["platform-disable", "--data-dir", str(root), "--issuer", "business-platform"])
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_reused_key_registration_is_rejected_without_secret_output(registration, capsys):
    _root, _key, secret, args = registration
    main(args)
    capsys.readouterr()
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 1
    captured = capsys.readouterr()
    assert not json.loads(captured.err)["ok"]
    assert secret.hex() not in captured.err and str(secret) not in captured.err


@pytest.mark.skipif(os.name == "nt", reason="POSIX密钥文件访问位检查")
def test_shared_readable_key_file_is_rejected(registration, capsys):
    _root, key, _secret, args = registration
    key.chmod(0o644)
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 1
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "unsafe_secret_file"
