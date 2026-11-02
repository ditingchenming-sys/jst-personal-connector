# 安装与更新

需要 Python 3.11+、网络访问和支持 MCP stdio 的 AI 客户端。当前版本 0.6.1，对外只有一个聚水潭连接器，默认ERP；需要分销时自动接续本人已连接的ERP。可选本机组件或自己部署的Linux多员工HTTPS服务。GitHub只分发安装包，不代管账号或业务服务。

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

### 平台已登录的身份接入

工作台通常已通过钉钉等方式登录员工。0.6.0支持直接承接平台可信后端核验的身份，不要求员工另建或再次登录连接器密码账号。平台身份用于确定操作人，本人聚水潭登录用于取得业务权限，两者仍分别验证；连接器不直接读取钉钉Cookie。

在连接器服务器本机登记可信平台的固定标识、授权入口和允许的企业。共享密钥使用独立的至少32字节原始随机文件，只保存在可信平台后端与连接器加密运行资料中；Linux权限须为600，不交给员工前端或MCP：

```sh
.venv/bin/python -m jst_connector platform-register --data-dir /var/lib/jst-connector \
  --issuer business-platform --tenant actual-corp-id \
  --login-url https://workbench.example.com/jst/authorize \
  --secret-file /run/secrets/jst-platform-key
```

`--tenant`可重复指定，只允许这些企业。登记不是钉钉应用开通；平台须已完成自己的钉钉/其他身份核验，再实现下列通用后端接入。连接器不绑定某个工作台仓库。

1. 平台后端从已验证的员工会话取得企业和用户的稳定ID，以固定调用端签名`provision`，POST到连接器的`/integration/platform`。连接器从`(issuer, tenant, subject)`隔离映射无密码内部员工，为该调用端分配连接及API令牌；后端私有保存返回的`access_token`和`connection_id`，按员工使用。重复`provision`表示显式轮换该调用端令牌，保留原profile及聚水潭资料，撤销既有页面授权；不要每次登录都重新provision。
2. 员工打开正常`/login?connection=...`。平台身份模式页面只显示继续平台授权，不显示员工账号密码框；浏览器同源POST `/portal/platform-start`，只提交连接编号和可选板块/业务确认返回路径。连接器设置浏览器绑定cookie，生成120秒内有效的challenge，返回登记的HTTPS平台授权入口，附`challenge`和`audience`查询参数。
3. 平台授权入口复用本人的钉钉/平台登录会话；无有效会话才按平台自己的流程登录。后端从该会话重新取企业、用户及固定调用端，签名`authorize`并携带challenge，通过后端POST `/integration/platform`。不要根据前端传入的企业/用户字段签名；`audience`始终使用部署配置中的连接器origin，不直接信任URL查询。
4. 连接器核对challenge对应的企业、用户、调用端、连接和当前授权版本，返回固定本站`redirect_url`。平台将本人浏览器重定向到此地址；短期一次性code在URL片段中，连接器页面立即清除片段，再同源POST `/portal/platform-login`。兑换还须原浏览器HttpOnly挑战cookie，code/challenge只能消费一次；成功后进入聚水潭登录/已连接状态。
5. 写入确认继续使用本人浏览器授权及CSRF，单点登录不会批准业务预览。确认页恢复授权只返回原有连接、板块和操作；不能用API调用令牌或平台登录证明代替本人点击确认。

后端请求使用精确的JSON包裹结构：

```python
import hashlib, hmac, json, secrets, time

def envelope(secret, *, action, tenant, subject, challenge=None):
    # tenant/subject只能来自平台后端已经验证的当前员工会话。
    now = int(time.time())
    claims = {
        "version": 1, "issuer": "business-platform",
        "audience": "https://jst.example.com", "action": action,
        "tenant": tenant, "subject": subject, "client": "workbench",
        "request_id": secrets.token_urlsafe(24), "issued_at": now, "expires_at": now + 60,
    }
    if action == "authorize":
        claims["challenge"] = challenge
    raw = json.dumps(claims, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"), allow_nan=False).encode("utf-8")
    return {"claims": claims, "signature": hmac.new(secret, raw, hashlib.sha256).hexdigest()}
```

只支持`provision`、`authorize`、`disable`三个动作。签名证明有效期不超过120秒，未来签发容忍10秒，`request_id`原子防重放；后端请求不携带浏览器`Origin`。`disable`禁用该外部身份及其调用/页面授权，管理员禁用的身份不能靠provision复活。仅支持预先登记的平台，不接受客户端自行指定验签地址、员工profile或任意回调URL。

平台密钥轮换需使用从未登记过的新密钥重新执行`platform-register`；旧代证明、挑战、code、调用令牌和页面会话失效，后端须为仍启用的员工重新provision，原聚水潭资料仍保留。整体禁用平台：

```sh
.venv/bin/python -m jst_connector platform-disable --data-dir /var/lib/jst-connector \
  --issuer business-platform
```

旧密码员工与新平台身份不按姓名、手机号或字符串ID自动合并。旧绑定保留；迁移需由对接方核对真实员工关系并切换到新平台连接，不借用旧默认账号。升级本包不会自动接通工作台的钉钉后端，需部署方完成上述受信登记和接口联调。安全设计参考[OAuth安全最佳实践关于CSRF与浏览器状态绑定](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.7)；本协议是项目自有可信平台接续协议，不宣称完整实现OAuth/OIDC授权服务器。

### 独立部署的员工密码模式

没有平台登录后端的独立部署可继续使用原方式。管理员在服务器本机创建员工账号，命令隐藏输入员工密码，调用凭证只写指定私有文件，不输出终端：

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

首次 `open_connection_manager` 返回普通远程登录网址。平台身份接入时继续平台授权后直接连接本人聚水潭；独立密码模式才登录管理员创建的员工账号。聚水潭按需完成本人短信，连接完成可关页。有效登录态加密保存在服务器，按员工和调用端隔离，已有本机模式不会改为共享会话。

写入使用通用契约和真实预览。`request_operation_confirmation` 返回独立业务确认网址，需要本人员工浏览器会话；登录页不显示业务预览。确认后由 AI 或可信系统执行同一预览，执行结果回查并记录。只有MCP调用令牌不能自行批准。

工作台可通过每员工各自令牌调用同一 `/api/{action}`；不能用共享令牌加请求参数 `profile/employee_id` 代替身份映射。平台身份方式由可信后端核验后分配令牌，无须另设员工密码。工作台仍须接好秘密保存和可信确认；本仓库发布不等于已改动某个外部工作台。

后端参考：[FastAPI 身份认证](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)、[Playwright 请求观察](https://playwright.dev/python/docs/network)。本实现使用服务端存储的随机会话及盐化密码摘要，接口调用与浏览器确认的权限分别校验。

## 聚水潭分销平台

官方分销统一登录为 `https://account.scm121.com/user/login`，业务入口为 `https://sc.scm121.com/`。0.5.0 将分销作为同一个聚水潭连接器的内部兼容板块，不再要求第二连接器、第二域名、第二个员工账号或第二份调用令牌。

使用上文正常配置即可，只生成一个 `jushuitan` 条目：

```sh
python -m jst_connector config --client codex --format codex --output codex-mcp.toml
python -m jst_connector config --client workbuddy --format workbuddy --output workbuddy-mcp.json
```

日常工具调用省略 `area` 为ERP；需要分销时，在同一套工具中指定 `area="drp"`，例如 `connector_status(area="drp")`、`open_connection_manager(area="drp")`、`start_discovery(area="drp")`。后续同一分销任务的探索、保存、预览、确认、执行与回查都使用同一 `area`。

正常使用只需连接本人ERP。业务首次请求`area="drp"`时，连接器自动核验已有分销会话或通过同一员工的ERP换发分销授权，成功后继续处理原业务，无需用户再切登录板块、点接续或填写分销密码。已登录ERP的旧连接也可直接按需补连，不要求重登ERP；普通ERP状态/目录不加载分销。

并发首用单飞，成功会话复用。换票失败不清除有效ERP、不伪报分销已连接，不自动重放任何业务写入。自动接续绑定当前ERP和分销实际会话，ERP退出或换账号后会重新核对来源；有效的独立手工分销连接不被自动覆盖。

授权页的分销入口主要用于查看状态和异常处理；没有可用ERP时仍兼容本人分销独立登录，短信仍按原系统要求由本人完成。页面只作登录授权、验证码、连接状态和退出，完成即可关闭。

远程也只运行一个服务和一个HTTPS域名：

```sh
python -m jst_connector serve-remote --data-dir /var/lib/jst-connector \
  --public-url https://jst.example.com --port 8765
python -m jst_connector employee-add --data-dir /var/lib/jst-connector \
  --username alice --client workbench --token-output /var/lib/jst-credentials/alice.json
```

客户端配置一个 `--remote-url https://jst.example.com`，由安全环境变量 `JST_CONNECTOR_ACCESS_TOKEN` 注入本员工本调用端的令牌。同一令牌在两个板块始终对应同一员工；`area`只选择本人业务板块，不能选择其他人的profile、公司、来源目录或票据。

直接API调用同样使用一个地址和同一鉴权。例如分销连接状态请求为：

```json
{"area":"drp"}
```

将其作为JSON正文发送到同一服务的 `/api/status`。其他动作沿用原路径并增加 `area`。统一入口仍使用其默认ERP传输平台；不要把HTTP平台头改成DRP来路由，板块选择由正文 `area` 承载。登录和业务批准仍只能经本人员工浏览器会话/可信系统，API令牌不能自批写入。

工作台的分销模块应直接请求上述`area="drp"`的状态或业务接口，让连接器按需准备会话；不能先查看默认ERP状态中的`modules.drp`未初始化就拦成“请另外登录分销”。`area`由接入模块按业务需要选择，业务人员只看到一个连接器。接入侧也不得捕获业务超时后自动再次提交原写请求。

连接器内部按需创建分销模块，存储位于统一运行目录的 `modules/drp/`。会话、域名策略、身份核验、保存契约和执行账本仍分开；少用分销时不会为其初始化或恢复浏览器、不会自动换票。板块选择和退出仅作用于所选板块，不混用ERP Cookie。

### 工作台统一展示与旧版兼容

任何工作台或市场都只登记一个“聚水潭个人连接器”，分销在其内部按需调用，不注册第二张分销卡片。若旧工作台已存在 `jst-drp` 条目，可作为隐藏的兼容别名保留旧绑定，逐步改用统一入口；连接器发版不会替所有工作台修改各自已存目录。

0.4 的独立 `--platform drp` 服务及 `link-erp` 管理配对命令保留兼容。旧分销目录、EmployeeStore和调用凭证不会被新统一模块自动认作同一个员工，也不会删除。旧独立实例省略area仍为分销，不能通过area转用未授权ERP；新接入不需要这些旧分离部署参数。

从旧分离部署迁移时，保留旧安装目录、数据和密钥，先更新正常ERP入口；在统一授权页按需接续/登录分销。旧条目绑定是否迁移由对接系统核对其真实员工关系，不能按相同用户名或公司编号自动合并。完成后再由部署方处理旧服务，不自动停服务或清凭据。

本版身份协议工程验收以官方 `sc` 供货侧当前用户接口为依据；其他入口或角色须按实际身份协议继续核验，不能套用供货侧字段或冒称全部角色已真实验收。查询与写入按同样的实际请求发现、预览、可信确认和回查机制使用，不设固定业务名称清单。

## 登录资料与更新

Windows 运行资料默认位于 `%LOCALAPPDATA%/jst-personal-connector`，密钥由当前 Windows 用户的 DPAPI 保护；Linux 默认 `~/.local/share/jst-personal-connector`。运行目录与源码、安装目录分开保存，不上传 GitHub。

程序退出保留加密登录态；主动退出账号清除对应资料。能否继续免登录取决于聚水潭有效期和风控。

更新说明立即影响下一次读取仓库的 AI；本地代码需升级。暂停当前任务并停止该安装环境的 MCP/本机组件，下载、核验新版本 bundle 后，使用安装脚本的 `-InstallDir` 或 `--install-dir` 指向原安装目录。保留运行目录及 Linux 原密钥，安装完成后重启 MCP 并调用 `connector_status`。配置中安装路径不变通常无需重新配置；切换安装目录则重新生成配置。当前不会自动执行仓库更新。
