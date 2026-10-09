param(
    [string]$Toolchain = '1.88.0'
)

$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..\'))
$artifact = Join-Path $repositoryRoot 'target\i686-pc-windows-msvc\release\RZhuangJi.exe'
$toolchainArgument = "+$Toolchain"

if (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot 'Cargo.toml') -PathType Leaf)) {
    throw "The repository root could not be resolved from $scriptRoot"
}

# 确保 i686 target 已安装
& rustup target add i686-pc-windows-msvc --toolchain $Toolchain 2>&1 | Out-Null

Push-Location $repositoryRoot
try {
    # 32 位构建：静态链接 CRT，无外部依赖，Win7 SP1 / Win10 32 位通用
    $env:RUSTFLAGS = '-C target-feature=+crt-static'

    & cargo $toolchainArgument build `
        -p RZhuangJi `
        --release `
        --locked `
        --target i686-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) {
        throw 'The x86 (32-bit) normal-endpoint build failed.'
    }

    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        throw "The x86 build completed without producing the expected executable: $artifact"
    }

    Write-Host "x86 build succeeded: $artifact"
}
finally {
    Pop-Location
    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
}
