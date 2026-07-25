$ErrorActionPreference = 'Stop'

$version  = '1.6.0'
$url      = "https://github.com/oxide-sloc/oxide-sloc/releases/download/v$version/oxide-sloc-windows-x64.zip"
$checksum = '4ab799ccf62e1644efbe31ebea165c5d357da097e9944a287b88b99148275932'

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
