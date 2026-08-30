# Windows installation

nah ships an unsigned x86-64 Windows binary. ARM64 Windows and package-manager
installations through Winget, Chocolatey, or Scoop are not supported yet.
Windows may show a SmartScreen warning because the binary is unsigned.

## Install

Run in PowerShell:

```powershell
irm https://nahguard.ai/install.ps1 | iex
```

The installer downloads the release ZIP and checksum, verifies the archive,
and installs `nah.exe` under
`%USERPROFILE%\AppData\Local\Programs\nah`. It adds that directory to the
user PATH without expanding or reordering existing entries.

Set `$env:NAH_VERSION` to a release tag before running the installer to select
that version. Without it, the installer uses the latest release.

Running the command again upgrades nah. The previous executable is retained as
`nah.exe.old` until a subsequent successful install of the same binary removes
it. If Windows has the executable locked, the installed version is left
unchanged.

Restart open terminals and coding agents if they do not see the updated PATH.
Then install the runtime integration you use; `nah docs runtimes` shows the
qualified Windows support matrix.

## Uninstall

This removes both installed executables and only the user PATH entry written by
the installer.

<!-- nah:windows-uninstall:start -->
```powershell
$installDirectory = Join-Path $env:USERPROFILE 'AppData\Local\Programs\nah'
Remove-Item -LiteralPath (Join-Path $installDirectory 'nah.exe'), `
    (Join-Path $installDirectory 'nah.exe.old') -Force -ErrorAction SilentlyContinue
$pathEntry = '%USERPROFILE%\AppData\Local\Programs\nah'
$environmentKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment', $true)
try {
    $rawPath = [string]$environmentKey.GetValue(
        'Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $rawPath = (($rawPath -split ';') -ne $pathEntry) -join ';'
    $environmentKey.SetValue(
        'Path', $rawPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
} finally {
    $environmentKey.Dispose()
}
```
<!-- nah:windows-uninstall:end -->

Restart open terminals and coding agents after removal. nah does not provide
an uninstall command for the executable.
