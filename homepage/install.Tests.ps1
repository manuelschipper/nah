param(
    [string]$ArtifactPath,
    [string]$ChecksumsPath,
    [string]$ExpectedVersion
)

BeforeAll {
$installerPath = Join-Path $PSScriptRoot 'install.ps1'
$removalDocumentationPath = Join-Path $PSScriptRoot '..\docs\windows.md'
. $installerPath

function New-NahTestRelease {
    param(
        [Parameter(Mandatory)] [string]$Root,
        [Parameter(Mandatory)] [string]$BinaryContents,
        [switch]$WrongChecksum
    )

    $releaseRoot = Join-Path $Root ([Guid]::NewGuid().ToString('N'))
    $packageRoot = Join-Path $releaseRoot 'package'
    New-Item -ItemType Directory -Path $packageRoot | Out-Null
    [IO.File]::WriteAllText((Join-Path $packageRoot 'nah.exe'), $BinaryContents)
    [IO.File]::WriteAllText((Join-Path $packageRoot 'LICENSE'), 'MIT')
    $archive = Join-Path $releaseRoot 'nah-x86_64-pc-windows-msvc.zip'
    Compress-Archive -Path (Join-Path $packageRoot '*') -DestinationPath $archive
    $hash = if ($WrongChecksum) {
        '0' * 64
    } else {
        (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $checksums = Join-Path $releaseRoot 'sha256sums.txt'
    [IO.File]::WriteAllText(
        $checksums, "$hash  nah-x86_64-pc-windows-msvc.zip`n")
    [pscustomobject]@{ Archive = $archive; Checksums = $checksums }
}

function Get-RawUserPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    try {
        return [string]$key.GetValue(
            'Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } finally {
        $key.Dispose()
    }
}

function Set-RawUserPath {
    param(
        [AllowEmptyString()] [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Kind =
            [Microsoft.Win32.RegistryValueKind]::ExpandString
    )

    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment', $true)
    try {
        $key.SetValue('Path', $Value, $Kind)
    } finally {
        $key.Dispose()
    }
}

function Get-UserPathKind {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    try {
        return $key.GetValueKind('Path')
    } finally {
        $key.Dispose()
    }
}

function Invoke-NahProcess {
    param(
        [Parameter(Mandatory)] [string]$Executable,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [string]$Payload
    )

    $stderrPath = Join-Path ([IO.Path]::GetTempPath()) (
        'nah-stderr-' + [Guid]::NewGuid().ToString('N'))
    try {
        if ($PSBoundParameters.ContainsKey('Payload')) {
            $stdout = @($Payload | & $Executable @Arguments 2> $stderrPath)
        } else {
            $stdout = @(& $Executable @Arguments 2> $stderrPath)
        }
        $exitCode = $LASTEXITCODE
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            Get-Content -LiteralPath $stderrPath -Raw
        } else {
            ''
        }
        [pscustomobject]@{
            ExitCode = $exitCode
            Stdout = $stdout -join "`n"
            Stderr = $stderr
        }
    } finally {
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }
}
}

Describe 'nah Windows installer and release artifact' `
    -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    BeforeAll {
        $script:originalUserProfile = $env:USERPROFILE
        $script:originalHome = $env:HOME
        $script:originalProcessPath = $env:PATH
        $pythonLauncher = Get-Command py -CommandType Application -ErrorAction Stop |
            Select-Object -First 1
        $script:pythonLauncherDirectory = Split-Path -Parent $pythonLauncher.Path
        $script:originalVariables = @{}
        foreach ($name in @('XDG_CONFIG_HOME', 'CODEX_HOME', 'COPILOT_HOME', 'KIRO_HOME')) {
            $script:originalVariables[$name] = [Environment]::GetEnvironmentVariable(
                $name, [EnvironmentVariableTarget]::Process)
        }

        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment', $true)
        try {
            $script:originalPathExists = $key.GetValueNames() -contains 'Path'
            if ($script:originalPathExists) {
                $script:originalRawPath = [string]$key.GetValue(
                    'Path', '',
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $script:originalPathKind = $key.GetValueKind('Path')
            }
        } finally {
            $key.Dispose()
        }
    }

    BeforeEach {
        $env:USERPROFILE = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $env:HOME = $env:USERPROFILE
        New-Item -ItemType Directory -Path $env:USERPROFILE | Out-Null
        $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
        foreach ($name in @('XDG_CONFIG_HOME', 'CODEX_HOME', 'COPILOT_HOME', 'KIRO_HOME')) {
            Remove-Item -LiteralPath "Env:$name" -Force -ErrorAction SilentlyContinue
        }
        Set-RawUserPath -Value '%SystemRoot%\System32;C:\Existing'
    }

    AfterAll {
        $env:USERPROFILE = $script:originalUserProfile
        $env:HOME = $script:originalHome
        $env:PATH = $script:originalProcessPath
        foreach ($entry in $script:originalVariables.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable(
                $entry.Key, $entry.Value, [EnvironmentVariableTarget]::Process)
        }

        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment', $true)
        try {
            if ($script:originalPathExists) {
                $key.SetValue('Path', $script:originalRawPath, $script:originalPathKind)
            } else {
                $key.DeleteValue('Path', $false)
            }
        } finally {
            $key.Dispose()
        }
        Send-NahEnvironmentChange
    }

    It 'rejects a checksum mismatch before changing the installation or PATH' {
        Mock Send-NahEnvironmentChange
        $release = New-NahTestRelease -Root $TestDrive -BinaryContents 'bad' -WrongChecksum
        $beforePath = Get-RawUserPath

        {
            Install-NahWindows -AcceptanceArtifactSource $release.Archive `
                -AcceptanceChecksumsSource $release.Checksums
        } | Should -Throw

        $installed = Join-Path $env:USERPROFILE 'AppData\Local\Programs\nah\nah.exe'
        (Test-Path -LiteralPath $installed) | Should -BeFalse
        (Get-RawUserPath) | Should -BeExactly $beforePath
        Should -Invoke Send-NahEnvironmentChange -Times 0 -Exactly
    }

    It 'installs at the protected path and preserves expandable user PATH bytes' {
        Mock Send-NahEnvironmentChange
        $release = New-NahTestRelease -Root $TestDrive -BinaryContents 'one'
        $rawPath = '%SystemRoot%\System32;%TOOLS_HOME%\bin;C:\Existing'
        Set-RawUserPath -Value $rawPath -Kind String

        Install-NahWindows -AcceptanceArtifactSource $release.Archive `
            -AcceptanceChecksumsSource $release.Checksums

        $installDirectory = Join-Path $env:USERPROFILE 'AppData\Local\Programs\nah'
        [IO.File]::ReadAllText((Join-Path $installDirectory 'nah.exe')) | Should -BeExactly 'one'
        (Get-RawUserPath) | Should -BeExactly (
            $rawPath + ';%USERPROFILE%\AppData\Local\Programs\nah')
        (Get-UserPathKind) | Should -Be ([Microsoft.Win32.RegistryValueKind]::ExpandString)
        (Test-NahPathContains -PathValue $env:PATH `
            -InstallDirectory $installDirectory) | Should -BeTrue
        Should -Invoke Send-NahEnvironmentChange -Times 1 -Exactly
    }

    It 'does not reorder or duplicate an existing install directory in PATH' {
        Mock Send-NahEnvironmentChange
        $release = New-NahTestRelease -Root $TestDrive -BinaryContents 'one'
        $rawPath = '%SystemRoot%\System32;%USERPROFILE%\AppData\Local\Programs\nah;C:\After'
        Set-RawUserPath -Value $rawPath -Kind String

        Install-NahWindows -AcceptanceArtifactSource $release.Archive `
            -AcceptanceChecksumsSource $release.Checksums

        (Get-RawUserPath) | Should -BeExactly $rawPath
        (Get-UserPathKind) | Should -Be ([Microsoft.Win32.RegistryValueKind]::ExpandString)
    }

    It 'warns when another nah executable shadows the installed binary' {
        Mock Send-NahEnvironmentChange
        Mock Write-Warning
        $shadowDirectory = Join-Path $TestDrive 'shadow'
        New-Item -ItemType Directory -Path $shadowDirectory | Out-Null
        [IO.File]::WriteAllText((Join-Path $shadowDirectory 'nah.exe'), 'shadow')
        $env:PATH = "$shadowDirectory;$env:PATH"
        $release = New-NahTestRelease -Root $TestDrive -BinaryContents 'one'

        Install-NahWindows -AcceptanceArtifactSource $release.Archive `
            -AcceptanceChecksumsSource $release.Checksums

        Should -Invoke Write-Warning -Times 1 -Exactly
    }

    It 'keeps upgrades recoverable and removes the old binary on reinstall' {
        Mock Send-NahEnvironmentChange
        $first = New-NahTestRelease -Root $TestDrive -BinaryContents 'one'
        $second = New-NahTestRelease -Root $TestDrive -BinaryContents 'two'
        $installed = Join-Path $env:USERPROFILE 'AppData\Local\Programs\nah\nah.exe'
        $old = "$installed.old"

        Install-NahWindows -AcceptanceArtifactSource $first.Archive `
            -AcceptanceChecksumsSource $first.Checksums
        Install-NahWindows -AcceptanceArtifactSource $second.Archive `
            -AcceptanceChecksumsSource $second.Checksums
        [IO.File]::ReadAllText($installed) | Should -BeExactly 'two'
        [IO.File]::ReadAllText($old) | Should -BeExactly 'one'

        Install-NahWindows -AcceptanceArtifactSource $second.Archive `
            -AcceptanceChecksumsSource $second.Checksums
        [IO.File]::ReadAllText($installed) | Should -BeExactly 'two'
        (Test-Path -LiteralPath $old) | Should -BeFalse

        Move-Item -LiteralPath $installed -Destination $old
        Install-NahWindows -AcceptanceArtifactSource $first.Archive `
            -AcceptanceChecksumsSource $first.Checksums
        [IO.File]::ReadAllText($installed) | Should -BeExactly 'one'
        [IO.File]::ReadAllText($old) | Should -BeExactly 'two'

        $stream = [IO.File]::Open(
            $installed, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            {
                Install-NahWindows -AcceptanceArtifactSource $second.Archive `
                    -AcceptanceChecksumsSource $second.Checksums
            } | Should -Throw
        } finally {
            $stream.Dispose()
        }
        [IO.File]::ReadAllText($installed) | Should -BeExactly 'one'
    }

    It 'executes the documented Windows removal procedure' {
        Mock Send-NahEnvironmentChange
        $release = New-NahTestRelease -Root $TestDrive -BinaryContents 'one'
        Install-NahWindows -AcceptanceArtifactSource $release.Archive `
            -AcceptanceChecksumsSource $release.Checksums
        $installed = Join-Path $env:USERPROFILE 'AppData\Local\Programs\nah\nah.exe'

        $documentation = Get-Content -LiteralPath $removalDocumentationPath -Raw
        $procedure = [Regex]::Match(
            $documentation,
            '(?s)<!-- nah:windows-uninstall:start -->\s+```powershell\s+(?<script>.*?)\s+```\s+<!-- nah:windows-uninstall:end -->')
        $procedure.Success | Should -BeTrue
        $procedurePath = Join-Path $TestDrive 'uninstall.ps1'
        [IO.File]::WriteAllText($procedurePath, $procedure.Groups['script'].Value)
        & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File $procedurePath
        $LASTEXITCODE | Should -Be 0

        (Test-Path -LiteralPath $installed) | Should -BeFalse
        (Test-NahPathContains -PathValue (Get-RawUserPath) `
            -InstallDirectory (Split-Path $installed)) | Should -BeFalse
    }

    It 'accepts the packaged product before publication' `
        -Skip:([string]::IsNullOrWhiteSpace($ArtifactPath)) {
        $archive = (Resolve-Path -LiteralPath $ArtifactPath).Path
        $checksums = (Resolve-Path -LiteralPath $ChecksumsPath).Path
        $expanded = Join-Path $TestDrive 'release-contents'
        Expand-Archive -LiteralPath $archive -DestinationPath $expanded
        (@((Get-ChildItem -LiteralPath $expanded -File).Name | Sort-Object) -join ',') |
            Should -BeExactly 'LICENSE,nah.exe'

        $installDirectory = Join-Path $env:USERPROFILE 'AppData\Local\Programs\nah'
        New-Item -ItemType Directory -Force -Path $installDirectory | Out-Null
        [IO.File]::WriteAllText((Join-Path $installDirectory 'nah.exe'), 'previous release')
        {
            & $installerPath -AcceptanceArtifactSource $archive `
                -AcceptanceChecksumsSource $checksums
        } | Should -Not -Throw
        $nah = Join-Path $installDirectory 'nah.exe'
        [IO.File]::ReadAllText("$nah.old") | Should -BeExactly 'previous release'

        $version = Invoke-NahProcess -Executable $nah -Arguments @('--version')
        $version.ExitCode | Should -Be 0
        $version.Stdout.Split()[-1] | Should -BeExactly $ExpectedVersion.TrimStart('v')

        Install-NahWindows -AcceptanceArtifactSource $archive `
            -AcceptanceChecksumsSource $checksums
        (Test-Path -LiteralPath "$nah.old") | Should -BeFalse

        $project = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
        $dangerousCommand = 'Remove-Item -LiteralPath C:\ -Recurse -Force'
        $powerShellPayload = @{
            sessionId = 'release-acceptance'; cwd = $project; toolName = 'powershell'
            toolArgs = (@{ command = $dangerousCommand } | ConvertTo-Json -Compress)
        } | ConvertTo-Json -Compress -Depth 8
        $powerShellDecision = Invoke-NahProcess -Executable $nah `
            -Arguments @('hook', 'copilot', 'run') -Payload $powerShellPayload
        $powerShellDecision.ExitCode | Should -Be 0
        $powerShellResponses = @(
            $powerShellDecision.Stdout -split "`r?`n" |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { $_ | ConvertFrom-Json })
        $powerShellResponse = $powerShellResponses |
            Where-Object permissionDecision -eq 'deny' | Select-Object -First 1
        $powerShellProgress = $powerShellResponses |
            Where-Object type -eq 'progress' | Select-Object -First 1
        $powerShellAudit = $null
        if ($null -eq $powerShellResponse -or $null -ne $powerShellProgress) {
            $powerShellAudit = Invoke-NahProcess -Executable $nah `
                -Arguments @('log', '--json', '-n', '1')
        }
        $powerShellResponse.permissionDecision |
            Should -BeExactly 'deny' -Because (
                "stdout: $($powerShellDecision.Stdout); stderr: $($powerShellDecision.Stderr); " +
                "audit: $($powerShellAudit.Stdout)")
        $powerShellProgress | Should -BeNullOrEmpty -Because (
            "stdout: $($powerShellDecision.Stdout); audit: $($powerShellAudit.Stdout)")

        foreach ($runtime in @('claude', 'codex', 'cursor', 'copilot', 'cline', 'kiro')) {
            $before = Invoke-NahProcess -Executable $nah -Arguments @('hook', $runtime, 'status')
            $before.ExitCode | Should -Be 0
            (Invoke-NahProcess -Executable $nah `
                -Arguments @('hook', $runtime, 'install')).ExitCode | Should -Be 0
            $installedStatus = Invoke-NahProcess -Executable $nah `
                -Arguments @('hook', $runtime, 'status')
            $installedStatus.ExitCode | Should -Be 0
            $installedStatus.Stdout | Should -Not -BeExactly $before.Stdout
            (Invoke-NahProcess -Executable $nah `
                -Arguments @('hook', $runtime, 'install')).ExitCode | Should -Be 0
            (Invoke-NahProcess -Executable $nah `
                -Arguments @('hook', $runtime, 'status')).Stdout |
                Should -BeExactly $installedStatus.Stdout
            (Invoke-NahProcess -Executable $nah `
                -Arguments @('hook', $runtime, 'uninstall')).ExitCode | Should -Be 0
            (Invoke-NahProcess -Executable $nah `
                -Arguments @('hook', $runtime, 'status')).Stdout |
                Should -BeExactly $before.Stdout
        }

        $partialPayloads = @{
            codex = @{
                session_id = 'release-acceptance'; turn_id = 'turn-1'
                hook_event_name = 'PreToolUse'; cwd = $project; tool_name = 'Bash'
                tool_use_id = 'call-1'; model = 'test'; permission_mode = 'default'
                tool_input = @{ command = $dangerousCommand }
            }
            cursor = @{
                hook_event_name = 'preToolUse'; cwd = $project; tool_name = 'Shell'
                tool_input = @{ command = $dangerousCommand; working_directory = $project }
            }
            copilot = @{
                hook_event_name = 'PreToolUse'; cwd = $project; tool_name = 'Bash'
                tool_input = @{ command = $dangerousCommand }
            }
        }
        foreach ($runtime in $partialPayloads.Keys) {
            $result = Invoke-NahProcess -Executable $nah `
                -Arguments @('hook', $runtime, 'run') `
                -Payload ($partialPayloads[$runtime] | ConvertTo-Json -Compress -Depth 8)
            $result.ExitCode | Should -Be 0
            $result.Stdout | Should -BeNullOrEmpty
        }
        $clinePayload = @{
            taskId = 'release-acceptance'; hookName = 'PreToolUse'
            workspaceRoots = @($project)
            preToolUse = @{
                toolName = 'execute_command'; parameters = @{ command = $dangerousCommand }
            }
        } | ConvertTo-Json -Compress -Depth 8
        $cline = Invoke-NahProcess -Executable $nah `
            -Arguments @('hook', 'cline', 'run') -Payload $clinePayload
        $cline.ExitCode | Should -Be 0
        ($cline.Stdout | ConvertFrom-Json).cancel | Should -BeFalse

        $env:PATH = "$env:PATH;$script:pythonLauncherDirectory"
        $created = Invoke-NahProcess -Executable $nah `
            -Arguments @('guard', 'new', 'release-acceptance')
        $created.ExitCode | Should -Be 0
        (Invoke-NahProcess -Executable $nah `
            -Arguments @('guard', 'enable', 'release-acceptance')).ExitCode | Should -Be 0
        $customInput = @{
            v = 1; tool = 'Bash'; cwd = $project
            input = @{ command = 'release-acceptance destroy --all' }
        } | ConvertTo-Json -Compress -Depth 8
        $custom = Invoke-NahProcess -Executable $nah -Arguments @('decide') -Payload $customInput
        $customAudit = $null
        if ($custom.ExitCode -ne 1) {
            $customAudit = Invoke-NahProcess -Executable $nah -Arguments @('log', '--json', '-n', '1')
        }
        $custom.ExitCode | Should -Be 1 -Because (
            "stdout: $($custom.Stdout); stderr: $($custom.Stderr); " +
            "audit: $($customAudit.Stdout)")
        ($custom.Stdout | ConvertFrom-Json).verdict | Should -BeExactly 'block'
    }
}
