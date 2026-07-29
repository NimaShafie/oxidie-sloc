$ErrorActionPreference = 'Stop'

$version  = '1.6.1'
$url      = "https://github.com/oxide-sloc/oxide-sloc/releases/download/v$version/oxide-sloc-windows-x64.zip"
$checksum = 'c48fdf0789797892dbe2db5d2bf84d94934f67b89b9945152818f2d1b0f4affc'

$packageArgs = @{
    packageName    = $env:ChocolateyPackageName
    unzipLocation  = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
    url            = $url
    checksum       = $checksum
    checksumType   = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

$binDir = Join-Path $packageArgs.unzipLocation 'oxide-sloc.exe'
Install-BinFile -Name 'oxide-sloc' -Path $binDir
