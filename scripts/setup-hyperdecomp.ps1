param(
 [switch]$CpuOnly,
 [switch]$Build,
 [switch]$Test,
 [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$taskRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskTemporary = Join-Path $taskRoot '.tmp'
New-Item -ItemType Directory -Path $taskTemporary -Force | Out-Null
$env:TEMP = $taskTemporary
$env:TMP = $taskTemporary
$env:PIP_CACHE_DIR = Join-Path $taskTemporary 'pip-cache'
$taskCmake = Join-Path $taskRoot 'vendor\tools\cmake-4.4.4-windows-x86_64\bin\cmake.exe'
if (-not (Test-Path -LiteralPath $taskCmake)) {
 $taskCmake = (Get-Command cmake -ErrorAction Stop).Source
}
$taskCudaRoot = Join-Path $taskRoot 'vendor\cuda-runtime'
if (-not $CpuOnly) {
 $taskLock = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'hyperdecomp-cuda-lock.json') | ConvertFrom-Json
 $taskValid = $true
 foreach ($taskFile in $taskLock.files) {
  $taskPath = Join-Path $taskCudaRoot $taskFile.path
  if (-not (Test-Path -LiteralPath $taskPath) -or (Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash -ne $taskFile.sha256) { $taskValid = $false }
 }
 if (-not $taskValid) {
  if (-not (Test-Path -LiteralPath $Python)) { $Python = (Get-Command $Python -CommandType Application -ErrorAction Stop).Source }
  $taskDownloads = Join-Path $taskRoot 'downloads\hyperdecomp'
  New-Item -ItemType Directory -Path $taskDownloads -Force | Out-Null
  $taskWheels = @()
  foreach ($taskPackage in $taskLock.packages) {
   $taskWheel = Join-Path $taskDownloads $taskPackage.wheel.filename
   if (-not (Test-Path -LiteralPath $taskWheel)) { Invoke-WebRequest -Uri $taskPackage.wheel.url -OutFile $taskWheel }
   if ((Get-FileHash -LiteralPath $taskWheel -Algorithm SHA256).Hash -ne $taskPackage.wheel.sha256) { throw "CUDA wheel hash mismatch: $taskWheel" }
   $taskWheels += $taskWheel
  }
  & $Python -m pip install --no-index --no-deps --upgrade --target $taskCudaRoot @taskWheels
  if ($LASTEXITCODE -ne 0) { throw 'Pinned CUDA component installation failed' }
 }
 foreach ($taskFile in $taskLock.files) {
  if ((Get-FileHash -LiteralPath (Join-Path $taskCudaRoot $taskFile.path) -Algorithm SHA256).Hash -ne $taskFile.sha256) { throw "Installed CUDA component differs from lock: $($taskFile.path)" }
 }
}
$taskBuildFolder = Join-Path $taskRoot $(if ($CpuOnly) { 'build-cpu' } else { 'build' })
$taskCudaOption = if ($CpuOnly) { 'OFF' } else { 'ON' }
& $taskCmake -S $taskRoot -B $taskBuildFolder -G 'Visual Studio 17 2022' -A x64 "-DSCRATCHER_ENABLE_CUDA=$taskCudaOption"
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
if ($Build) {
 & $taskCmake --build $taskBuildFolder --config Release --parallel 3
 if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
}
if ($Test) {
 $taskCtest = Join-Path (Split-Path -Parent $taskCmake) 'ctest.exe'
 & $taskCtest --test-dir $taskBuildFolder -C Release --output-on-failure
 if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
}
Write-Output "Configured $taskBuildFolder with CUDA=$taskCudaOption. No display driver, system PATH, or input binary was changed."
