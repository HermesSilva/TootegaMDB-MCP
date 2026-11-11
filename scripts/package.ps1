# Empacota a extensão (.vsix) com os binários das duas plataformas.
#
# Pré-requisito: binários já gerados em dist/ (no WSL:  bash scripts/build-dist.sh).
# Uso (PowerShell, na raiz do projeto):
#   pwsh scripts/package.ps1                              pacote para instalar localmente
#   pwsh scripts/package.ps1 -ImagesUrl https://...       pacote para publicar no Marketplace
param([string]$ImagesUrl = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$ext = Join-Path $root 'extension'

foreach ($plat in 'win32-x64', 'linux-x64') {
    $exe = if ($plat -like 'win32*') { 'tmdb.exe' } else { 'tmdb' }
    $src = Join-Path $root "dist\$plat\$exe"
    if (-not (Test-Path $src)) { throw "Binário ausente: $src (rode scripts/build-dist.sh no WSL)" }
    $dst = Join-Path $ext "bin\$plat"
    New-Item -ItemType Directory -Force $dst | Out-Null
    Copy-Item $src (Join-Path $dst $exe) -Force
}

Push-Location $ext
try {
    # O Marketplace só mostra imagens servidas por https. Com -ImagesUrl os caminhos relativos do
    # README viram URLs absolutas (ex.: https://raw.githubusercontent.com/ORG/REPO/main/extension).
    # Sem ele o pacote mantém os caminhos relativos: funciona instalado localmente, mas as
    # animações não apareceriam na página do Marketplace.
    # O nome do pacote leva o número do build que gerou os binários (arquivo BUILD).
    $build = (Get-Content (Join-Path $root 'BUILD') -ErrorAction SilentlyContinue | Select-Object -First 1)
    $version = (Get-Content (Join-Path $ext 'package.json') -Raw | ConvertFrom-Json).version
    $vsix = Join-Path $root "dist\tootega-mdb-$version.$build.vsix"
    $vsceArgs = @('package', '--no-dependencies', '--allow-missing-repository', '--skip-license', '--out', $vsix)
    if ($ImagesUrl) { $vsceArgs += @('--baseImagesUrl', $ImagesUrl, '--baseContentUrl', $ImagesUrl) }
    else { $vsceArgs += '--no-rewrite-relative-links' }
    npx --yes '@vscode/vsce' @vsceArgs
    if ($LASTEXITCODE -ne 0) { throw "vsce falhou" }
}
finally {
    Pop-Location
}
Get-ChildItem (Join-Path $root 'dist') -Filter *.vsix | Format-Table Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } } -AutoSize
