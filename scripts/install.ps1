[CmdletBinding()]
param(
    [string]$InstallDir = (Split-Path -Parent $PSScriptRoot),
    [string]$Python = 'python',
    [string]$Wheel,
    [switch]$SkipBrowser
)

$ErrorActionPreference = 'Stop'
$PackageRoot = Split-Path -Parent $PSScriptRoot
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

function Invoke-Checked {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [string]$FailureMessage = '安装步骤失败，请按上方错误处理后重试。'
    )
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage 退出码：$LASTEXITCODE。"
    }
}

try {
    Invoke-Checked $Python @('-c', 'import sys; sys.exit(int(sys.version_info < (3, 11)))') -FailureMessage '需要 Python 3.11 或以上版本。'
    if (Test-Path -LiteralPath (Join-Path $PackageRoot 'manifest.sha256.json')) {
        Invoke-Checked $Python @((Join-Path $PSScriptRoot 'build_bundle.py'), '--verify-directory', $PackageRoot)
    }
    if (-not $Wheel) {
        $Candidates = @(
            foreach ($DirectoryName in @('wheels', 'dist')) {
                $CandidateDirectory = Join-Path $PackageRoot $DirectoryName
                if (Test-Path -LiteralPath $CandidateDirectory) {
                    Get-ChildItem -LiteralPath $CandidateDirectory -Filter 'jst_personal_connector-*.whl' -File
                }
            }
        )
        if ($Candidates.Count -ne 1) {
            throw '需要唯一的本项目 wheel。请先运行 uv build --wheel，或用 -Wheel 指定已构建文件。'
        }
        $Wheel = $Candidates[0].FullName
    }
    $Wheel = (Resolve-Path -LiteralPath $Wheel).Path
    if ([System.IO.Path]::GetFileName($Wheel) -notmatch '^jst_personal_connector-.+\.whl$') {
        throw '指定文件不是本项目的 wheel。'
    }
    $LockFile = Join-Path $PackageRoot 'requirements.lock.txt'
    if (-not (Test-Path -LiteralPath $LockFile -PathType Leaf)) { throw '缺少带哈希的依赖锁文件。' }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $EnvironmentDirectory = Join-Path $InstallDir '.venv'
    if ((Test-Path -LiteralPath $EnvironmentDirectory) -and -not (Test-Path -LiteralPath (Join-Path $EnvironmentDirectory 'pyvenv.cfg'))) {
        throw '目标 .venv 已存在但不是可识别的虚拟环境，已停止，未删除或覆盖该目录。'
    }
    if (-not (Test-Path -LiteralPath $EnvironmentDirectory)) {
        Invoke-Checked $Python @('-m', 'venv', $EnvironmentDirectory)
    }
    $EnvironmentPython = Join-Path $EnvironmentDirectory 'Scripts/python.exe'
    Invoke-Checked $EnvironmentPython @('-c', 'import site,sys; sys.exit(int(sys.version_info < (3, 11) or sys.prefix == sys.base_prefix or bool(site.ENABLE_USER_SITE)))') -FailureMessage '需要隔离的 Python 3.11+ 虚拟环境，不能借用系统包。'
    Invoke-Checked $EnvironmentPython @('-m', 'ensurepip')
    Invoke-Checked $EnvironmentPython @('-m', 'pip', 'install', '--require-hashes', '--only-binary=:all:', '-r', $LockFile)
    Invoke-Checked $EnvironmentPython @('-m', 'pip', 'install', '--no-deps', '--force-reinstall', $Wheel)
    if (-not $SkipBrowser) {
        Invoke-Checked $EnvironmentPython @('-m', 'playwright', 'install', 'chromium')
    }
    $ConfigurationDirectory = Join-Path $InstallDir 'client-configs'
    New-Item -ItemType Directory -Path $ConfigurationDirectory -Force | Out-Null
    foreach ($Client in @('workbuddy', 'codex')) {
        $Extension = if ($Client -eq 'codex') { 'toml' } else { 'json' }
        $Destination = Join-Path $ConfigurationDirectory "$Client-mcp.$Extension"
        if (Test-Path -LiteralPath $Destination) {
            Write-Output "已有配置未覆盖：$Destination"
        } else {
            Invoke-Checked $EnvironmentPython @('-m', 'jst_connector', 'config', '--client', $Client, '--format', $Client, '--output', $Destination)
        }
    }
    Write-Output '组件及独立客户端配置已安装；请自行合并配置。未注册开机任务，未登录账号。'
    Invoke-Checked $EnvironmentPython @('-m', 'jst_connector', 'doctor')
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
