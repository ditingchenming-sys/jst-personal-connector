# AI 接入说明

本仓库是公开接入入口。实际程序运行在使用者自己的环境，通过本地 MCP stdio 提供工具；不要把仓库 URL 当作远程 MCP 服务地址。

稳定入口：[仓库说明](https://github.com/ditingchenming-sys/jst-personal-connector)、[最新发布](https://github.com/ditingchenming-sys/jst-personal-connector/releases/latest)。接入时读取 `main` 上的当前说明，再选择已发布版本。

## 安装与配置

1. 读取本文件和 [INSTALL.md](INSTALL.md)，确认 Windows 或 Linux、Python 3.11+、当前 AI 的 MCP stdio 支持与配置位置。
2. 优先使用正式 Release 中的完整 bundle；校验发布方提供的 SHA256 后解压，运行对应安装脚本。若尚无 Release，可从源码构建 wheel 再安装。安装脚本需要 wheel，不能把只有 wheel 的分发目录当作源码执行 `pip install .`。
3. 每个 AI 使用独立 `--client`，例如 `codex`、`workbuddy`。用本机安装环境的 `jst-connector config` 生成配置，再合并到该 AI 的实际 MCP 配置；保留其他 MCP 设置，不复制维护者电脑的绝对路径。
4. 配置命令不登录账号、不修改 AI 全局配置。启动 MCP 后先列出工具，应有 15 个；调用 `connector_status`，已有有效会话先恢复，只有需要登录时调用 `open_connection_manager`。
5. 本人在连接器页面填写账号、密码、协议同意及必要验证码。不要索取、复制或输出密码、Cookie、验证码、主密钥或带授权的管理页地址。登录完成后关闭该页，继续在 AI 对话中使用。

## 按需求调用

- 先用 `search_capabilities` 查目录与保存接口，区分已适配、待验证和未适配状态。
- 明确支持的基础查询用 `query_erp`；检查 `complete/has_more/total` 和错误，不能把未适配或未完成分页当作空结果或全量结果。
- 查询参数的语义、字段含义、白名单范围与排查路径见 [查询使用指引](docs/查询使用指引.md)。该文档说明商品标识层级、自定义字段位各家口径不同、库存字段需另行取数、接口白名单按完整 URL 匹配，以及部分页面回调协议已下线等情况，避免误判为空数据或登录问题。
- 未预置功能按 [通用探索与接口复用](docs/通用探索与接口复用.md) 使用 `start_discovery → inspect_discovery → interact_discovery → propose_read_interface → validate_read_interface → call_saved_interface`。条件不清楚时在当前对话里询问本人。
- 查询契约通过连接器校验后，在当前已授权连接的读取范围内试查，不要求本人返回登录页逐项批准。服务端身份、Cookie 和令牌由连接器提供，模型不能自报公司、员工或授权。
- 当前版本全部真实业务写入关闭。不得借查询、任意 HTTP、脚本或点击绕过制单、修改、审核和付款限制。

## 获取更新

接入新环境时重新读取仓库当前说明，选择已发布版本。已有安装需要更新时，按 `INSTALL.md` 保留原安装目录、运行目录和密钥，安装新 wheel，并重启 MCP。当前没有自动下载和执行更新机制，不声称文档变更已经升级本地程序。

不读取其他项目的 `.env`、Cookie、浏览器目录或默认账号，不把个人运行资料提交到此仓库。系统嵌入示例只展示协议结构，仍需目标系统真实认证、身份配对和业务联调。
