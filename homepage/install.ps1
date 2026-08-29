param(
    [string]$AcceptanceArtifactSource,
    [string]$AcceptanceChecksumsSource
)

function Copy-NahInstallerSource {
    param(
        [Parameter(Mandatory)] [string]$Source,
        [Parameter(Mandatory)] [string]$Destination,
        [Parameter(Mandatory)] [bool]$AcceptanceSource
    )

    if ($AcceptanceSource) {
        Copy-Item -LiteralPath $Source -Destination $Destination
    } else {
        Invoke-WebRequest -Uri $Source -OutFile $Destination
    }
}

function Test-NahPathContains {
    param(
        [AllowEmptyString()] [string]$PathValue,
        [Parameter(Mandatory)] [string]$InstallDirectory
    )

    $expected = $InstallDirectory.TrimEnd('\')
    foreach ($entry in $PathValue -split ';') {
        $expanded = [Environment]::ExpandEnvironmentVariables($entry.Trim()).TrimEnd('\')
        if ([StringComparer]::OrdinalIgnoreCase.Equals($expanded, $expected)) {
            return $true
        }
    }
    return $false
}

function Add-NahPathEntry {
    param(
        [AllowEmptyString()] [string]$PathValue,
        [Parameter(Mandatory)] [string]$PathEntry
    )

    if ([string]::IsNullOrEmpty($PathValue)) {
        return $PathEntry
    }
    if ($PathValue.EndsWith(';')) {
        return "$PathValue$PathEntry"
    }
    return "$PathValue;$PathEntry"
}

function Send-NahEnvironmentChange {
    if (-not ('Nah.EnvironmentChange' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;

namespace Nah {
    public static class EnvironmentChange {
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SendMessageTimeout(
            IntPtr window, uint message, UIntPtr wParam, string lParam,
            uint flags, uint timeout, out UIntPtr result);

        public static void Broadcast() {
            UIntPtr result;
            SendMessageTimeout(new IntPtr(0xffff), 0x001a, UIntPtr.Zero,
                "Environment", 0x0002, 5000, out result);
        }
    }
}
'@
    }
    [Nah.EnvironmentChange]::Broadcast()
}

function Install-NahWindows {
    param(
        [string]$AcceptanceArtifactSource,
        [string]$AcceptanceChecksumsSource
    )

    $ErrorActionPreference = 'Stop'
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'nah: install.ps1 supports Windows only'
    }
    if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
        [System.Runtime.InteropServices.Architecture]::X64) {
        throw 'nah: only x86-64 Windows is supported'
    }
    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        throw 'nah: USERPROFILE is unavailable'
    }
    if ([string]::IsNullOrWhiteSpace($AcceptanceArtifactSource) -ne
        [string]::IsNullOrWhiteSpace($AcceptanceChecksumsSource)) {
        throw 'nah: acceptance artifact and checksum sources must be provided together'
    }

    $asset = 'nah-x86_64-pc-windows-msvc.zip'
    $acceptanceSource = -not [string]::IsNullOrWhiteSpace($AcceptanceArtifactSource)
    if ($acceptanceSource) {
        $artifactSource = $AcceptanceArtifactSource
        $checksumsSource = $AcceptanceChecksumsSource
    } else {
        if ([string]::IsNullOrWhiteSpace($env:NAH_VERSION)) {
            $releaseBase = 'https://github.com/manuelschipper/nah/releases/latest/download'
        } else {
            $releaseBase = "https://github.com/manuelschipper/nah/releases/download/$($env:NAH_VERSION)"
        }
        $artifactSource = "$releaseBase/$asset"
        $checksumsSource = "$releaseBase/sha256sums.txt"
    }

    $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) (
        'nah-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    try {
        $archive = Join-Path $temporaryDirectory $asset
        $checksums = Join-Path $temporaryDirectory 'sha256sums.txt'
        Write-Output "downloading $asset ..."
        Copy-NahInstallerSource -Source $artifactSource -Destination $archive `
            -AcceptanceSource $acceptanceSource
        Copy-NahInstallerSource -Source $checksumsSource -Destination $checksums `
            -AcceptanceSource $acceptanceSource

        $checksumPattern = '^([0-9A-Fa-f]{64})\s+\*?' + [Regex]::Escape($asset) + '$'
        $expectedHashes = @(
            foreach ($line in Get-Content -LiteralPath $checksums) {
                if ($line -match $checksumPattern) {
                    $Matches[1].ToLowerInvariant()
                }
            }
        )
        if ($expectedHashes.Count -ne 1) {
            throw "nah: checksum not found for $asset"
        }
        $actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHashes[0]) {
            throw "nah: checksum mismatch for $asset"
        }

        $expanded = Join-Path $temporaryDirectory 'expanded'
        Expand-Archive -LiteralPath $archive -DestinationPath $expanded
        $replacement = Join-Path $expanded 'nah.exe'
        if (-not (Test-Path -LiteralPath $replacement -PathType Leaf)) {
            throw 'nah: archive does not contain nah.exe'
        }

        $installDirectory = Join-Path $env:USERPROFILE 'AppData\Local\Programs\nah'
        $installed = Join-Path $installDirectory 'nah.exe'
        $old = "$installed.old"
        $staged = "$installed.new"
        New-Item -ItemType Directory -Force -Path $installDirectory | Out-Null

        if ((Test-Path -LiteralPath $old -PathType Leaf) -and
            -not (Test-Path -LiteralPath $installed -PathType Leaf)) {
            Move-Item -LiteralPath $old -Destination $installed
        }

        $sameBinary = (Test-Path -LiteralPath $installed -PathType Leaf) -and
            ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -eq
             (Get-FileHash -LiteralPath $replacement -Algorithm SHA256).Hash)
        if ($sameBinary) {
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        } elseif (Test-Path -LiteralPath $installed -PathType Leaf) {
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
            Copy-Item -LiteralPath $replacement -Destination $staged
            try {
                [IO.File]::Replace($staged, $installed, $old, $true)
            } catch {
                Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
                throw 'nah: existing nah.exe could not be replaced; the installed version is unchanged'
            }
        } else {
            Move-Item -LiteralPath $replacement -Destination $installed
        }

        $pathEntry = '%USERPROFILE%\AppData\Local\Programs\nah'
        $environmentKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment', $true)
        try {
            $rawUserPath = [string]$environmentKey.GetValue(
                'Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if (-not (Test-NahPathContains -PathValue $rawUserPath `
                -InstallDirectory $installDirectory)) {
                $rawUserPath = Add-NahPathEntry -PathValue $rawUserPath -PathEntry $pathEntry
            }
            $environmentKey.SetValue(
                'Path', $rawUserPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
        } finally {
            $environmentKey.Dispose()
        }

        if (-not (Test-NahPathContains -PathValue $env:PATH `
            -InstallDirectory $installDirectory)) {
            $env:PATH = Add-NahPathEntry -PathValue $env:PATH -PathEntry $installDirectory
        }
        Send-NahEnvironmentChange

        $resolved = Get-Command nah -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $resolved -and
            -not [StringComparer]::OrdinalIgnoreCase.Equals($resolved.Source, $installed)) {
            Write-Warning "nah: another nah comes first on PATH: $($resolved.Source)"
        }

        Write-Output "installed nah to $installed"
        Write-Output 'next: nah docs start'
    } finally {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Install-NahWindows -AcceptanceArtifactSource $AcceptanceArtifactSource `
        -AcceptanceChecksumsSource $AcceptanceChecksumsSource
}
