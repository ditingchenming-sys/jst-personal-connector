# 适配来源与边界

0.7.0新增通用业务链接、SPA哈希路由、iframe与实际来源链，以及分销只读初始化和查询复用。普通业务筛选按结构核验，不按商品、供应商等业务字段枚举；未知页面引用不自动取得登录凭据或成为业务接口目的地。

- 官方[SC应用](https://sc.scm121.com/)及[商品应用](https://goods.scm121.com/)公开HTML与其精确引用的脚本用于核对模块、接口及响应形状。[Webbox生产模块配置](https://files.erp321.com/cdn/webbox/load-config/gyl-home/url.config.js)声明商品等独立前端模块；已核公共静态根与业务请求分开处理。
- SC公开脚本的供应商价格库存页面调用`POST /api/goods/buyer/supplier/queryDisErpGoodsDataV2`，供应商选项调用`GET /api/drp/partner/channel/queryMySupplierByOptionals`；它们与自有商品管理的`/api/goods/supplier/goods/list`及`/api/goods/myself/rapidly/goods/list`分别处理，不替换业务含义。
- 官方脚本表明部分大供应商使用代码202的异步查询链；本版快捷查询对此明确返回尚需核对，不将其当空结果。分页总数未知保留null，一页返回不声明全量完成。
- 证据为匿名官方资源与隔离Chromium/HTTP契约闭环。分销探索不复制主会话的真实Cookie或页面存储，只提供无真实认证效力的页面初始化占位值；实际接口认证由服务端从本人已核主会话重建。通用链接识别不等于全部官方前端、平台角色或真实业务已逐项验收。

0.6.1按需自动接续分销：用户已实测本人ERP手工接续成功，连接器在首次分销请求前自动执行同一受信换票链；普通ERP使用不启动分销。匿名官方登录页及其JS还确认，密码登录的`/api/auth`可由`account.scm121.com`同源代理；本版仅为两个已核实origin的四个固定认证端点加入精确别名，保持一次动作一次提交和实际响应来源核验，不泛开整个认证域。官方JS回归中的加密key/认证响应均为本机合成夹具，生产认证提交0；该证据不等于真实分销密码登录验收。

0.6.0新增可信平台身份接续，复用项目既有服务端会话、HMAC签名和SQLite防重机制，不直接接收钉钉Cookie或前端自报员工。浏览器状态/一次性授权与回调绑定参考[RFC9700第4.7节](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.7)。这是项目自有平台后端接续协议，不声明已实现完整OAuth/OIDC或任意工作台已自动接通。钉钉本身的身份核验由接入平台按其官方流程完成。

0.5.0 对外统一一个连接器、一个MCP、一个HTTPS服务入口。以下ERP/分销协议与身份策略仍在各自内部模块使用，不能据此要求两张连接卡片或两套对外服务。分销按需选择 `area="drp"`，当前员工由统一入口已验证授权派生。

## 分销平台（0.4.0）

- 官方统一登录：[account.scm121.com/user/login](https://account.scm121.com/user/login)；业务应用：[sc.scm121.com](https://sc.scm121.com/)。匿名HTML及其精确引用的登录脚本用于核对独立登录表单和请求，不以业务名称建立白名单。
- 登录页面引用的[account umi.5fac74bd.js](https://assets.sursung.com/prod/account/umi.5fac74bd.js)与[Login chunk](https://assets.sursung.com/prod/account/p__Account__Login.69f4a2fc.async.js)声明 `gyl.scm121.com/api/auth` 下的账号密码与IDAAS本人短信流程。密码编码交官方表单脚本处理；不在本项目重新猜测加密算法。
- 同一官方脚本声明 `gyl.scm121.com/api/drp` 为业务前缀。供货侧当前用户为固定 `GET /user/supplier/getUserInfo?supplierType=shop&terminalName=SUPPLIER`，服务器字段 `data.coId/coName/coCompanyUser.uid/userName`；认证回执的令牌只作为比对目标，还须由此服务器接口验证当前会话。
- ERP官方[首页模块](https://src.erp321.com/epaas-container-new/p__index.fa94585c.async.js)的 `epaas.common.syncScmToken` 调用 `PtRR.c` 并读取 `code=0/act=0/data.details.access_token`；[主容器](https://src.erp321.com/epaas-container-new/umi.a6621ceb.js)的该导出对应 `POST /usercenterapi/SupplyChain/GetRedirectTokenV2`。接续仅由已配对且当前核验的ERP本人会话调用，令牌内部转给新分销上下文；不跨域复制ERP Cookie、不接受模型提供票据。
- 查询/写入、页面、匿名资产、响应来源和DNS校验均使用固定实例平台策略，认证接口不进入通用业务请求通道。SCM业务头由当前已核验会话重建，不保存模板中的Authorization。
- 取证为匿名公开HTML/JS与隔离夹具验证，不等于已通过真实员工、多角色或全部分销业务验收。当前固定身份契约以官方sc供货侧为依据，渠道/其他入口须按实际身份来源核对。

本目录为独立实现的聚水潭网页协议适配，不依赖其他项目源码、配置或默认公司。

- 页面与认证流程依据聚水潭公开页面及其引用的官方前端资源。
- 当前公司和员工通过固定的官方当前用户接口核实，不能凭页面名称、Cookie 存在或模型参数声明身份。
- 预置查询只封装已核对的请求形状。各能力当前适配与验证状态以运行时 `search_capabilities` 为准。
- 未预置查询通过隔离页面探索、实际请求观察、只读契约校验及有范围的试查接入。不能仅凭 URL 名称或 HTTP 方法认定只读。
- 此公开目录不包含个人登录态、业务取证记录、账号或本地开发历史。

官方入口：[聚水潭 ERP](https://www.erp321.com/epaas)。站点协议变化时需要重新核对适配，不承诺永久有效。
