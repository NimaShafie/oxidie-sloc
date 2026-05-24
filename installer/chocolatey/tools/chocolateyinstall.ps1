$ErrorActionPreference = 'Stop'

$version  = '1.5.61'
$url      = "https://github.com/oxide-sloc/oxide-sloc/releases/download/v$version/oxide-sloc-windows-x64.zip"
$checksum = 'TODO_FILLED_BY_RELEASE_WORKFLOW'

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
