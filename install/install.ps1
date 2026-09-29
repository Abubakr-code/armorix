# Armorix CLI installer for Windows (x64). No Python or pip needed.
#
#   irm https://abubakr-code.github.io/install.ps1 | iex
#
# Options: $env:ARMORIX_VERSION = "v0.3.0"  (default: latest)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Repo = "Abubakr-code/armorix"
$Version = if ($env:ARMORIX_VERSION) { $env:ARMORIX_VERSION } else { "latest" }
$InstallDir = if ($env:ARMORIX_INSTALL) { $env:ARMORIX_INSTALL } else { Join-Path $env:LOCALAPPDATA "Armorix\cli" }
$Asset = "armorix-cli-windows-x64.zip"
$Base = if ($Version -eq "latest") { "https://github.com/$Repo/releases/latest/download" } else { "https://github.com/$Repo/releases/download/$Version" }

function Say($msg) { Write-Host "armorix " -ForegroundColor Blue -NoNewline; Write-Host $msg }

if ([Environment]::Is64BitOperatingSystem -eq $false) { throw "Armorix needs 64-bit Windows" }

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("armorix-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  Say "downloading $Asset ($Version)"
  Invoke-WebRequest -UseBasicParsing -Uri "$Base/$Asset" -OutFile (Join-Path $Tmp $Asset)
  Invoke-WebRequest -UseBasicParsing -Uri "$Base/SHA256SUMS" -OutFile (Join-Path $Tmp "SHA256SUMS")

  $Line = Get-Content (Join-Path $Tmp "SHA256SUMS") | Where-Object { $_ -match " $([Regex]::Escape($Asset))$" } | Select-Object -First 1
  if (-not $Line) { throw "$Asset is missing from SHA256SUMS" }
  $Expected = ($Line -split "\s+")[0].ToLower()
  $Actual = (Get-FileHash -Algorithm SHA256 (Join-Path $Tmp $Asset)).Hash.ToLower()
  if ($Expected -ne $Actual) { throw "checksum mismatch - the download is corrupted or was tampered with" }
  Say "checksum verified"

  if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
  New-Item -ItemType Directory -Path $InstallDir | Out-Null
  Expand-Archive -Path (Join-Path $Tmp $Asset) -DestinationPath $InstallDir -Force
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

$Bin = Join-Path $InstallDir "armorix"
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($UserPath -split ";" | Where-Object { $_ -eq $Bin })) {
  [Environment]::SetEnvironmentVariable("Path", (($UserPath.TrimEnd(";") + ";" + $Bin).TrimStart(";")), "User")
  Say "added $Bin to your PATH (open a new terminal)"
}
$env:Path = "$Bin;$env:Path"
$Installed = & (Join-Path $Bin "armorix.exe") --version
Say "installed $Installed"
Write-Host ""
Write-Host "  Next steps"
Write-Host "    armorix scan .              scan the current project"
Write-Host "    armorix db update           offline CVE database for npm / PyPI (once)"
Write-Host "    armorix ai setup            local AI for fixes (once, 1.1 GB)"
Write-Host "    armorix update              update Armorix later"
Write-Host ""
