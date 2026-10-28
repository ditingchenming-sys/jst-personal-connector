"""匿名官方页面/JS取证；仅放行本人管理登录流程。"""

import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

LOGIN_URL = "https://www.erp321.com/login.aspx"
ENTRY_URL = "https://www.erp321.com/epaas"
LOGIN_TERMS = {
    "agreement_url": "https://app.jushuitan.com/doc/regUserAgreement.html",
    "privacy_url": "https://app.jushuitan.com/doc/regPrivacy.html",
}
LOGIN_ASSETS = {
    "https://src.erp321.com/erp-login-react/jushuitan.ico",
    "https://src.erp321.com/erp-login-react/images/login/erp/login_subimg_202606081740.jpg",
    "https://src.erp321.com/erp-login-react/umi.e8703b74.css",
    "https://src.erp321.com/erp-login-react/preload_helper.61012c86.js",
    "https://src.erp321.com/erp-login-react/umi.a8efe1b1.js",
    "https://src.erp321.com/erp-login-react/p__login__index.8e85f4bd.chunk.css",
    "https://src.erp321.com/erp-login-react/122.40c8559d.async.js",
    "https://src.erp321.com/erp-login-react/391.2cf2742d.async.js",
    "https://src.erp321.com/erp-login-react/428.4d810d78.async.js",
    "https://src.erp321.com/erp-login-react/533.91fd043d.async.js",
    "https://src.erp321.com/erp-login-react/630.1d6f4af2.async.js",
    "https://src.erp321.com/erp-login-react/p__login__index.17f6e7bb.async.js",
    "https://src.erp321.com/erp-login-react/static/beian.ef881569.png",
    "https://src.erp321.com/erp-login-react/images/login/erp/logo.png",
    "https://gias.jd.com/js/td.js",
    "https://cdn.erp321.cn/cdn/expire-1-Y/fingerprintjs/3.3.3/umd/fingerprintjs.min.js",
    "https://g.alicdn.com/sj/securesdk/0.0.3/securesdk_v2.js",
    "https://g.alicdn.com/AWSC/WebUMID/1.88.4/um.js",
}
# The exact SDK source constructs these two numeric cache-busting variants.
# No other query keys, redirects, business paths, or similarly named hosts are allowed.
LOGIN_ASSET_QUERY_RULES = {
    "https://g.alicdn.com/sd/pointman/js/pt2.js": ("_", r"[0-9]{1,10}"),
    "https://g.alicdn.com/sj/securesdk/0.0.3/securesdk_v2.js": ("timestamp", r"[0-9]{13}"),
}


def is_login_asset(url: str) -> bool:
    if url in LOGIN_ASSETS:
        return True
    try:
        parts = urlsplit(url)
        base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        rule = LOGIN_ASSET_QUERY_RULES.get(base)
        if rule is None or parts.fragment:
            return False
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
        return len(pairs) == 1 and pairs[0][0] == rule[0] and re.fullmatch(rule[1], pairs[0][1]) is not None
    except (TypeError, ValueError):
        return False


# Public login JS sets baseURL='//api.erp321.com' for this host, withCredentials=True.
# Only login operations are listed: account switching/deletion/password reset are excluded.
AUTH_POST_URLS = {"https://api.erp321.com" + path for path in (
    "/erp/webapi/UserApi/WebLogin/Passport",
    "/usercenter/AuthApi/WebLogin/SendVerificationV2",
    "/usercenter/AuthApi/WebLogin/VerificationV2",
    "/erp/webapi/UserApi/WebLogin/AuthProtection",
    "/erp/webapi/UserApi/WebLogin/SendIdaasVerification",
    "/erp/webapi/UserApi/WebLogin/IdaasVerification",
    "/usercenter/UnionApi/SendIdaasVerification",
    "/usercenter/UnionApi/IdaasVerification",
)}
CAPTCHA_URL = "https://www.erp321.com/ValidCode.aspx"
