$ErrorActionPreference = 'Stop'

$version  = '1.6.11'
$url      = "https://github.com/oxide-sloc/oxide-sloc/releases/download/v$version/oxide-sloc-windows-x64.zip"
$checksum = 'b580e3dcb46ec3b63f4f34639838ce07d786536258d3861d57a742eab6203979'

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
