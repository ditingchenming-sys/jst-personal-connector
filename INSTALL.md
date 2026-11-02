# 安装与更新

需要 Python 3.11+、网络访问和支持 MCP stdio 的 AI 客户端。当前版本 0.4.0，可选 ERP 或分销平台、本机组件或自己部署的 Linux 多员工 HTTPS 服务。GitHub 只分发安装包，不代管任何账号或业务服务。

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

## Linux 多员工远程部署

在服务器完成上述安装，使用独立运行目录和原密钥。下面的域名为示例，部署时换成自己的 HTTPS 域名；不把示例变成实际安装地址。

```sh
.venv/bin/python -m jst_connector serve-remote \
  --data-dir /var/lib/jst-connector \
  --public-url https://jst.example.com --port 8765
```

服务默认只监听服务器 `127.0.0.1:8765`，由 HTTPS 反向代理对外提供入口。单进程启动，勿对同一运行目录运行多个服务；安装脚本不自动注册系统服务。已有进程管理器可运行以上命令，主密钥通过秘密管理注入。

Nginx 示例（证书由部署环境提供）：

```nginx
server {
    listen 443 ssl;
    server_name jst.example.com;
    ssl_certificate /etc/ssl/jst/fullchain.pem;
    ssl_certificate_key /etc/ssl/jst/privkey.pem;
    client_max_body_size 1m;
    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host jst.example.com;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 150s;
    }
}
```

`Host` 须匹配 `--public-url`，员工浏览器使用此 HTTPS 域名。应用检查固定域名和同源请求；浏览器凭证使用 Secure、HttpOnly、SameSite cookie。反向代理不要记录 Authorization、Cookie、请求体或登录参数。运行目录由部署账号独占读写。

管理员在服务器本机创建员工账号，命令隐藏输入员工密码，调用凭证只写指定私有文件，不输出终端：

```sh
umask 077
.venv/bin/python -m jst_connector employee-add \
  --data-dir /var/lib/jst-connector --username alice --client workbuddy \
  --token-output /var/lib/jst-credentials/alice-workbuddy.json
```

`--client` 用于区分每个 AI 或接入系统。另一调用端另发令牌、另存聚水潭会话：

```sh
.venv/bin/python -m jst_connector employee-token \
  --data-dir /var/lib/jst-connector --username alice --client codex \
  --token-output /var/lib/jst-credentials/alice-codex.json
```

对已有同名调用端再次发令牌会撤销旧令牌和员工浏览器会话；凭证文件不覆盖，轮换时使用新文件名。禁用员工使用 `employee-disable --data-dir /var/lib/jst-connector --username alice`。员工账号只授权连接器访问；实际公司及聚水潭员工身份仍须本人登录后核验。

将每人每调用端对应文件中的 `access_token` 通过各自客户端的秘密环境配置注入 `JST_CONNECTOR_ACCESS_TOKEN`，不要把完整凭证交给 AI 对话、放进仓库或 URL。服务端 `JST_CONNECTOR_MASTER_KEY` 不交给员工电脑。客户端生成远程适配配置：

```sh
python -m jst_connector config --client workbuddy --format workbuddy \
  --remote-url https://jst.example.com --output workbuddy-remote.json
```

此配置运行 `mcp --remote-url` 的 stdio 适配器，继承员工自己的 `JST_CONNECTOR_ACCESS_TOKEN` 环境变量。配置中不包含令牌，AI客户端启动时须确实继承该秘密环境；不同员工或AI勿共用同一环境凭证。

首次 `open_connection_manager` 返回普通远程登录网址。员工用自己电脑浏览器打开，登录管理员创建的员工账号，再连接本人聚水潭账号并按需完成短信；连接完成可关页。有效登录态加密保存在服务器，按员工和调用端隔离，已有本机模式不会改为共享会话。

写入使用通用契约和真实预览。`request_operation_confirmation` 返回独立业务确认网址，需要本人员工浏览器会话；登录页不显示业务预览。确认后由 AI 或可信系统执行同一预览，执行结果回查并记录。只有MCP调用令牌不能自行批准。

工作台可通过每员工各自令牌调用同一 `/api/{action}`；不能用共享令牌加请求参数 `profile/employee_id` 代替身份映射。具体工作台还须接好账号分配、秘密保存和可信确认；本仓库发布不等于已改动某个外部工作台。

后端参考：[FastAPI 身份认证](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)、[Playwright 请求观察](https://playwright.dev/python/docs/network)。本实现使用服务端存储的随机会话及盐化密码摘要，接口调用与浏览器确认的权限分别校验。

## 聚水潭分销平台

官方分销统一登录：`https://account.scm121.com/user/login`；业务入口：`https://sc.scm121.com/`。使用本包的 `--platform drp`，不需要另外安装一套工作台适配器才能访问分销域。

本机生成独立连接器条目：

```sh
python -m jst_connector config --platform drp --client codex --format codex --output codex-drp.toml
python -m jst_connector config --platform drp --client workbuddy --format workbuddy --output workbuddy-drp.json
```

配置条目名 `jushuitan-drp`，保留已有 `jushuitan`。默认分销运行目录为默认 ERP 目录下的 `drp/`；若指定 `--data-dir`，须使用新的独立目录。每个目录通过 `.platform.json` 绑定平台；已有 ERP 资料不会被改为分销资料，也不复制已有 ERP Cookie。平台不能由模型工具参数切换。

首次调用分销连接器的 `open_connection_manager`，在本人授权页独立登录分销，验证码仅按原系统要求由本人完成。连接器以官方认证回执和分销当前用户接口交叉核对身份，再加密保存；之后优先恢复分销自身的有效登录态。

已有本人ERP连接时，可先配置一次来源配对，免填分销账号密码接续：

```sh
python -m jst_connector link-erp --platform drp --client codex \
  --erp-data-dir /实际ERP运行目录 --erp-client codex
```

分销若使用自定义目录，还需给此命令传入同一 `--data-dir`。随后本人打开分销授权页，点击“使用已登录的ERP接续分销”。来源必须是连接器已验证并保存的本人ERP会话，不能使用未导入或未授权的其他浏览器会话。后台固定调用ERP官方 `GetRedirectTokenV2` 换发分销授权，再核验分销身份；源身份变化、换发失败或验证失败时停止，可继续使用独立分销登录。

远程部署与员工授权同样固定为分销平台，并使用独立域名/运行目录及各自令牌：

```sh
python -m jst_connector serve-remote --platform drp --data-dir /var/lib/jst-drp \
  --public-url https://drp-connector.example.com --port 8766
python -m jst_connector employee-add --platform drp --data-dir /var/lib/jst-drp \
  --username alice --client workbench --token-output /var/lib/jst-credentials/alice-drp.json
```

员工客户端配置也加 `--platform drp --remote-url https://drp-connector.example.com`，注入该员工的分销专属 `JST_CONNECTOR_ACCESS_TOKEN`。同一市场条目可以提供 ERP 与 `jst-drp` 两个连接条目，但不能共用访问令牌或根据请求自报的员工编号切换身份。

需要远程员工ERP接续时，由服务器本机管理员核对两侧员工和调用端后配对：

```sh
python -m jst_connector link-erp --platform drp --data-dir /var/lib/jst-drp \
  --username alice --client workbench --erp-data-dir /var/lib/jst-erp \
  --erp-username alice --erp-client workbench
```

两侧目录都须是已配置、可由当前运行环境解密的独立存储，来源ERP员工须先完成本人登录。用户名相同不代表系统自动认定同一人，以上配对由管理员核对并明确配置。源或目标重新登录、退出、公司切换均受会话绑定核对；两平台的实际公司/员工编号不要求数值相同。

本版身份协议工程验收以官方 `sc` 供货侧当前用户接口为依据；其他入口或角色须按实际身份协议继续核验，不能套用供货侧字段或冒称全部角色已真实验收。查询与写入按同样的实际请求发现、预览、可信确认和回查机制使用，不设固定业务名称清单。

## 登录资料与更新

Windows 运行资料默认位于 `%LOCALAPPDATA%/jst-personal-connector`，密钥由当前 Windows 用户的 DPAPI 保护；Linux 默认 `~/.local/share/jst-personal-connector`。运行目录与源码、安装目录分开保存，不上传 GitHub。

程序退出保留加密登录态；主动退出账号清除对应资料。能否继续免登录取决于聚水潭有效期和风控。

更新说明立即影响下一次读取仓库的 AI；本地代码需升级。暂停当前任务并停止该安装环境的 MCP/本机组件，下载、核验新版本 bundle 后，使用安装脚本的 `-InstallDir` 或 `--install-dir` 指向原安装目录。保留运行目录及 Linux 原密钥，安装完成后重启 MCP 并调用 `connector_status`。配置中安装路径不变通常无需重新配置；切换安装目录则重新生成配置。当前不会自动执行仓库更新。
