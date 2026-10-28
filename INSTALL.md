# 安装与更新

需要 Python 3.11+、网络访问和支持本地 MCP stdio 的 AI 客户端。当前版本 0.2.0，实际调用在本机运行；本仓库不提供公网 MCP 服务。

## 完整分发包

打开[最新 Release](https://github.com/ditingchenming-sys/jst-personal-connector/releases/latest)，下载其中的 bundle ZIP 及 SHA256 清单，核验后解压。完整 bundle 应含 `wheels/`、`scripts/`、依赖锁文件、`LICENSE` 和 `manifest.sha256.json`；安装脚本会再次检查包内文件哈希。若尚无 Release，可按下方源码方式安装。

Windows 在解压目录运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -InstallDir C:\Tools\jst-personal-connector
```

可通过 `-Python` 指定 Python。脚本会创建独立 `.venv`、安装带哈希锁定的依赖、wheel 和 Chromium，并在安装目录的 `client-configs/` 生成 Codex、WorkBuddy 配置供合并。

Linux 先按下方方式准备密钥，然后在解压目录运行：

```sh
sh scripts/install.sh --install-dir "$HOME/.local/opt/jst-personal-connector"
```

浏览器缺系统依赖时，由管理员确认后使用安装环境的 Python 执行 `-m playwright install-deps chromium`。安装脚本不注册开机任务、不代为登录、不覆盖已有客户端配置。

## 从源码安装

克隆或下载仓库源码后，在源码目录创建隔离环境。Windows：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements.lock.txt
.\.venv\Scripts\python.exe -m pip install --no-deps .
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\python.exe -m jst_connector doctor
```

Linux：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock.txt
.venv/bin/python -m pip install --no-deps .
.venv/bin/python -m playwright install chromium
```

维护者也可用 `uv build --wheel` 构建 wheel，再执行 `python scripts/build_bundle.py --wheel dist/对应版本.whl --output dist/新包名.zip`，脚本拒绝覆盖已有目标。

## Linux 密钥

Linux 运行时必须提供 `JST_CONNECTOR_MASTER_KEY`（Fernet 格式），不能在源码、接入说明或聊天里放真实密钥。部署环境已有秘密管理时使用其注入机制。个人测试可在仓库及安装目录之外创建仅自己可读的密钥文件：

```sh
umask 077
python3 -c "from pathlib import Path; import secrets,base64,os; p=Path.home()/'.jst-connector-master.key'; fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,base64.urlsafe_b64encode(secrets.token_bytes(32))); os.close(fd)"
export JST_CONNECTOR_MASTER_KEY="$(cat "$HOME/.jst-connector-master.key")"
```

命令不会打印密钥，也不覆盖已有文件。MCP 进程需要继承该环境变量；桌面客户端由启动环境的秘密管理机制注入。保留同一密钥才能读取已有加密登录资料。

## 生成 MCP 配置

Windows 安装环境内：

```powershell
.\.venv\Scripts\python.exe -m jst_connector config --client codex --format codex --output codex-mcp.toml
.\.venv\Scripts\python.exe -m jst_connector config --client workbuddy --format workbuddy --output workbuddy-mcp.json
```

Linux 对应使用 `.venv/bin/python`。其他兼容客户端可用 `--format generic` 生成通用 JSON，并使用独立调用端名称，例如 `--client my-ai`。

将生成内容合并到目标 AI 的 MCP 配置，不覆盖其他服务；刷新或重启客户端后检查工具列表。首次使用先调用 `connector_status`，需要登录时调用 `open_connection_manager`。每个 AI 分别登录自己的账号，每个调用端仅保留一个账号，换账号先退出。

## 登录资料与更新

Windows 运行资料默认位于 `%LOCALAPPDATA%/jst-personal-connector`，密钥由当前 Windows 用户的 DPAPI 保护；Linux 默认 `~/.local/share/jst-personal-connector`。运行目录与源码、安装目录分开保存，不上传 GitHub。

程序退出保留加密登录态；主动退出账号清除对应资料。能否继续免登录取决于聚水潭有效期和风控。

更新说明立即影响下一次读取仓库的 AI；本地代码需升级。暂停当前任务并停止该安装环境的 MCP/本机组件，下载、核验新版本 bundle 后，使用安装脚本的 `-InstallDir` 或 `--install-dir` 指向原安装目录。保留运行目录及 Linux 原密钥，安装完成后重启 MCP 并调用 `connector_status`。配置中安装路径不变通常无需重新配置；切换安装目录则重新生成配置。当前不会自动执行仓库更新。
