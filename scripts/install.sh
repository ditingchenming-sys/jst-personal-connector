#!/bin/sh
# 仅安装隔离组件；不创建主密钥，不读取旧凭据，不修改客户端全局配置。
set -eu

PACKAGE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
INSTALL_DIR=$PACKAGE_ROOT
PYTHON=python3
WHEEL=
SKIP_BROWSER=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --install-dir|--python|--wheel)
            [ "$#" -ge 2 ] || { echo '安装参数缺少值。' >&2; exit 2; }
            case "$1" in
                --install-dir) INSTALL_DIR=$2 ;;
                --python) PYTHON=$2 ;;
                --wheel) WHEEL=$2 ;;
            esac
            shift 2 ;;
        --skip-browser) SKIP_BROWSER=1; shift ;;
        --help)
            echo '用法：sh scripts/install.sh [--install-dir 目录] [--python Python路径] [--wheel 文件] [--skip-browser]'
            exit 0 ;;
        *) echo '未知安装参数。' >&2; exit 2 ;;
    esac
done

"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "需要 Python 3.11 或以上版本。")'
if [ -f "$PACKAGE_ROOT/manifest.sha256.json" ]; then
    "$PYTHON" "$PACKAGE_ROOT/scripts/build_bundle.py" --verify-directory "$PACKAGE_ROOT"
fi
if [ -z "$WHEEL" ]; then
    WHEEL_COUNT=0
    for candidate in "$PACKAGE_ROOT"/wheels/jst_personal_connector-*.whl "$PACKAGE_ROOT"/dist/jst_personal_connector-*.whl; do
        [ -f "$candidate" ] || continue
        WHEEL=$candidate
        WHEEL_COUNT=$((WHEEL_COUNT + 1))
    done
    [ "$WHEEL_COUNT" -eq 1 ] || { echo '需要唯一的本项目 wheel。请先运行 uv build --wheel，或用 --wheel 指定已构建文件。' >&2; exit 1; }
fi
case "$(basename -- "$WHEEL")" in
    jst_personal_connector-*.whl) ;;
    *) echo '指定文件不是本项目的 wheel。' >&2; exit 1 ;;
esac
[ -f "$WHEEL" ] || { echo '指定的 wheel 文件不存在。' >&2; exit 1; }
[ -f "$PACKAGE_ROOT/requirements.lock.txt" ] || { echo '缺少带哈希的依赖锁文件。' >&2; exit 1; }

mkdir -p -- "$INSTALL_DIR"
INSTALL_DIR=$(CDPATH= cd -- "$INSTALL_DIR" && pwd)
ENVIRONMENT_DIRECTORY=$INSTALL_DIR/.venv
if [ -e "$ENVIRONMENT_DIRECTORY" ] && [ ! -f "$ENVIRONMENT_DIRECTORY/pyvenv.cfg" ]; then
    echo '目标 .venv 已存在但不是可识别的虚拟环境，已停止，未删除或覆盖该目录。' >&2
    exit 1
fi
if [ ! -d "$ENVIRONMENT_DIRECTORY" ]; then
    "$PYTHON" -m venv "$ENVIRONMENT_DIRECTORY"
fi
ENVIRONMENT_PYTHON=$ENVIRONMENT_DIRECTORY/bin/python
"$ENVIRONMENT_PYTHON" -c 'import site,sys; sys.exit(0 if sys.version_info >= (3, 11) and sys.prefix != sys.base_prefix and not site.ENABLE_USER_SITE else "需要隔离的 Python 3.11+ 虚拟环境，不能借用系统包。")'
"$ENVIRONMENT_PYTHON" -m ensurepip
"$ENVIRONMENT_PYTHON" -m pip install --require-hashes --only-binary=:all: -r "$PACKAGE_ROOT/requirements.lock.txt"
"$ENVIRONMENT_PYTHON" -m pip install --no-deps --force-reinstall "$WHEEL"
if [ "$SKIP_BROWSER" -eq 0 ]; then
    "$ENVIRONMENT_PYTHON" -m playwright install chromium
fi
mkdir -p -- "$INSTALL_DIR/client-configs"
for client in workbuddy codex; do
    extension=json
    [ "$client" != codex ] || extension=toml
    destination=$INSTALL_DIR/client-configs/$client-mcp.$extension
    if [ -e "$destination" ]; then
        printf '已有配置未覆盖：%s\n' "$destination"
    else
        "$ENVIRONMENT_PYTHON" -m jst_connector config --client "$client" --format "$client" --output "$destination"
    fi
done
echo '组件及独立客户端配置已安装；请自行合并配置。未注册开机任务，未登录账号。'
if [ -z "${JST_CONNECTOR_MASTER_KEY:-}" ]; then
    echo 'Linux 尚未配置 JST_CONNECTOR_MASTER_KEY；请由运行环境的秘密管理机制注入，勿把密钥写入命令日志或安装材料。以下 doctor 将非零退出。' >&2
fi
"$ENVIRONMENT_PYTHON" -m jst_connector doctor
