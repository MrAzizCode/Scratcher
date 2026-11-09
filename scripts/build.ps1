param([string]$Configuration='Release',[string]$Destination='dist-v0.8')
$ErrorActionPreference='Stop'
$projectRoot=Split-Path $PSScriptRoot -Parent
$env:TEMP=Join-Path $projectRoot '.tmp'
$env:TMP=$env:TEMP
New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
$cmake=(Get-ChildItem (Join-Path $projectRoot 'vendor/tools') -Filter cmake.exe -Recurse | Select-Object -First 1).FullName
if (-not $cmake) { throw 'Download and extract a Windows CMake distribution into vendor/tools first.' }
& $cmake -S $projectRoot -B (Join-Path $projectRoot 'build') -G 'Visual Studio 17 2022' -A x64
if ($LASTEXITCODE) { throw 'CMake configure failed' }
& $cmake --build (Join-Path $projectRoot 'build') --config $Configuration --parallel 6
if ($LASTEXITCODE) { throw 'Build failed' }
& (Join-Path (Split-Path $cmake) 'ctest.exe') --test-dir (Join-Path $projectRoot 'build') -C $Configuration --output-on-failure
if ($LASTEXITCODE) { throw 'Tests failed' }
& $cmake --install (Join-Path $projectRoot 'build') --config $Configuration --prefix (Join-Path $projectRoot $Destination)
if ($LASTEXITCODE) { throw 'Packaging failed' }
