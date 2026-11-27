param(
    [string]$Sdk = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$Avd = 'SCA_Dynamic_API36',
    [int]$Port = 5590,
    [int]$FridaPort = 37042,
    [switch]$ShowWindow
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$adb = Join-Path $Sdk 'platform-tools\adb.exe'
$emulator = Join-Path $Sdk 'emulator\emulator.exe'
$python = Join-Path $repo '.venv\Scripts\python.exe'
$serial = "emulator-$Port"
$version = '17.28.0'
$asset = "frida-server-$version-android-x86_64.xz"
$expectedHash = '754f35424c318a70793ae443a6f5396e860d045fa7f8a6f68d1d36406d15bc1d'
$toolDir = Join-Path $repo 'data\dynamic-tools'
if ($Avd -notmatch '^SCA_Dynamic[A-Za-z0-9_]*$') { throw 'Choose a dedicated SCA_Dynamic lab AVD.' }
foreach ($binary in @($adb, $emulator, $python)) {
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "Missing prerequisite: $binary" }
}
$profiles = & $emulator -list-avds
if ($Avd -notin $profiles) { throw "Create the dedicated $Avd AVD with Android SDK Manager first (Google APIs x86_64, API 36)." }
$devices = & $adb devices
if ($devices -match "^$serial\s+device") {
    $actualAvd = (& $adb -s $serial emu avd name | Select-Object -First 1).Trim()
    if ($actualAvd -ne $Avd) { throw "Port $Port belongs to another AVD ($actualAvd)." }
} else {
    $launchArgs = @('-avd', $Avd, '-port', "$Port", '-no-audio', '-no-snapshot', '-no-boot-anim',
        '-gpu', 'swiftshader_indirect', '-memory', '3072', '-cores', '4')
    if ($ShowWindow) {
        # Visible mode is opt-in for a user explicitly requesting an interactive lab.
        Start-Process -FilePath $emulator -ArgumentList $launchArgs -WindowStyle Normal
    } else {
        Start-Process -FilePath $emulator -ArgumentList ($launchArgs + '-no-window') -WindowStyle Hidden
    }
}
$deadline = (Get-Date).AddMinutes(3)
do {
    Start-Sleep -Seconds 2
    $boot = & $adb -s $serial shell getprop sys.boot_completed 2>$null
    if ((Get-Date) -gt $deadline) { throw 'The lab did not finish booting in three minutes.' }
} until ($boot -eq '1')
$actualAvd = (& $adb -s $serial emu avd name | Select-Object -First 1).Trim()
if ($actualAvd -ne $Avd) { throw 'The selected device is not the dedicated lab.' }
& $adb -s $serial root
if ($LASTEXITCODE -ne 0) { throw 'Use a rootable Google APIs lab image (not a Play Store image).' }
& $adb -s $serial wait-for-device
$deviceUid = (& $adb -s $serial shell id -u).Trim()
if ($deviceUid -ne '0') { throw 'The lab image did not enable root; use a Google APIs development image.' }
New-Item -ItemType Directory -Force -Path $toolDir | Out-Null
$archive = Join-Path $toolDir $asset
$server = Join-Path $toolDir "frida-server-$version"
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest "https://github.com/frida/frida/releases/download/$version/$asset" -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLower() -ne $expectedHash) {
    throw 'Frida server asset checksum mismatch.'
}
& $python -c 'import lzma,pathlib,sys; pathlib.Path(sys.argv[2]).write_bytes(lzma.decompress(pathlib.Path(sys.argv[1]).read_bytes()))' $archive $server
if ($LASTEXITCODE -ne 0) { throw 'Cannot decompress the verified server asset.' }
$remote = "/data/local/tmp/sca-frida-server-$version"
& $adb -s $serial push $server $remote
if ($LASTEXITCODE -ne 0) { throw 'Cannot copy Frida server into the lab.' }
& $adb -s $serial shell chmod 700 $remote
if ($LASTEXITCODE -ne 0) { throw 'Cannot set lab server executable permissions.' }
$existing = & $adb -s $serial shell pidof "sca-frida-server-$version"
if (-not $existing) { & $adb -s $serial shell "$remote -D -l 127.0.0.1:27042" }
& $adb -s $serial forward "tcp:$FridaPort" 'tcp:27042'
if ($LASTEXITCODE -ne 0) { throw 'Frida port forwarding failed.' }
& $python -c 'import frida,sys; d=frida.get_device_manager().add_remote_device(sys.argv[1]); print("Frida connected:",frida.__version__,"processes:",len(d.enumerate_processes()))' "127.0.0.1:$FridaPort"
if ($LASTEXITCODE -ne 0) { throw 'The Frida client could not communicate with the lab server.' }
Write-Output "Lab ready: $Avd / $serial / Frida 127.0.0.1:$FridaPort"
