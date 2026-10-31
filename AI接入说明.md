# AI 接入说明

本仓库是公开接入入口。0.3.0 提供本机和多员工 HTTPS 服务两种运行方式，均可通过 MCP stdio 适配器使用；不要把仓库 URL 或员工 HTTPS 服务地址当作远程 MCP 协议地址。

稳定入口：[仓库说明](https://github.com/ditingchenming-sys/jst-personal-connector)、[最新发布](https://github.com/ditingchenming-sys/jst-personal-connector/releases/latest)。接入时读取 `main` 上的当前说明，再选择已发布版本。

## 安装与配置

1. 读取本文件和 [INSTALL.md](INSTALL.md)，确认 Windows 或 Linux、Python 3.11+、当前 AI 的 MCP stdio 支持与配置位置。
2. 优先使用正式 Release 中的完整 bundle；校验发布方提供的 SHA256 后解压，运行对应安装脚本。若尚无 Release，可从源码构建 wheel 再安装。安装脚本需要 wheel，不能把只有 wheel 的分发目录当作源码执行 `pip install .`。
3. 每个 AI 使用独立 `--client`，例如 `codex`、`workbuddy`。用本机安装环境的 `jst-connector config` 生成配置，再合并到该 AI 的实际 MCP 配置；保留其他 MCP 设置，不复制维护者电脑的绝对路径。
4. 配置命令不登录账号、不修改 AI 全局配置。启动 MCP 后先列出工具，应有 18 个；调用 `connector_status`，已有有效会话先恢复，只有需要登录时调用 `open_connection_manager`。远程部署使用管理员分配给本人本调用端的凭证，由 `JST_CONNECTOR_ACCESS_TOKEN` 注入，配置增加 `--remote-url https://实际域名`。远程返回的普通登录链接可交本人打开。
5. 本人在连接器页面填写账号、密码、协议同意及必要验证码。不要索取、复制或输出密码、Cookie、验证码、主密钥或带授权的管理页地址。登录完成后关闭该页，继续在 AI 对话中使用。

## 按需求调用

- 先用 `search_capabilities` 查目录与保存接口，区分已适配、待验证和未适配状态。
- 明确支持的基础查询用 `query_erp`；检查 `complete/has_more/total` 和错误，不能把未适配或未完成分页当作空结果或全量结果。
- 未预置功能按 [通用探索与接口复用](docs/通用探索与接口复用.md) 使用 `start_discovery → inspect_discovery → interact_discovery → propose_read_interface → validate_read_interface → call_saved_interface`。条件不清楚时在当前对话里询问本人。
- 查询契约通过连接器校验后，在当前已授权连接的读取范围内试查，不要求本人返回登录页逐项批准。服务端身份、Cookie 和令牌由连接器提供，模型不能自报公司、员工或授权。
- 登录 Cookie 后以本人账号权限为准，预置目录不限制业务范围。写入从实际拦截请求形成 `propose_write_interface` 契约；`preview_write_interface` 读取真实数据并核对同一对象和前置条件；显示完整预览后 `request_operation_confirmation` 交本人确认，确认后 `execute_confirmed_operation` 提交并回查预期字段。已有可信业务系统可沿用签名确认链。查询或页面点击不能替代写入确认。
- 通用契约按已核对的对象和参数复用；新增参数须重新预览确认。当前通用提交路径是一对象一请求，不把这个边界叫作“已验证整批原子性”；跨对象多步骤须核实聚水潭整体提交保证。预置 W 快捷方式未适配时继续通用探索。
- 超时、回查不符或结果未知时先查 `operation_status`，可设置 `recheck=true` 只读回查：证实同一对象的预期已生效时更新原记录；不符仍未知，绝不重发。不新建预览绕过防重；同公司相同业务请求共用防重复占用，成功后的真实状态变化可重新预览确认。

## 获取更新

接入新环境时重新读取仓库当前说明，选择已发布版本。已有安装需要更新时，按 `INSTALL.md` 保留原安装目录、运行目录和密钥，安装新 wheel，并重启 MCP。当前没有自动下载和执行更新机制，不声称文档变更已经升级本地程序。

不读取其他项目的 `.env`、Cookie、浏览器目录或默认账号，不把个人运行资料提交到此仓库。系统嵌入示例只展示协议结构，仍需目标系统真实认证、身份配对和业务联调。
