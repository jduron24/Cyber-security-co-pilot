[CmdletBinding()]
param(
    [string]$BindHost = "127.0.0.1",
    [int]$BackendPort = 8000,
    [int]$AgentPort = 8001,
    [switch]$IncludeMcpServer,
    [switch]$InstallNodeJs,
    [switch]$InstallNodeDeps,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-RepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Import-DotEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        return
    }

    Get-Content -Path $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) {
            return
        }
        $parts = $line.Split("=", 2)
        $name = $parts[0].Trim()
        $value = $parts[1].Trim().Trim('"').Trim("'")
        if ($name) {
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}

function Resolve-PythonExe {
    param([string]$RepoRoot)

    $venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        return $venvPython
    }

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -ne $pythonCommand) {
        return $pythonCommand.Source
    }

    throw "Python was not found. Create .venv or add python to PATH."
}

function Resolve-NpmExe {
    param([switch]$InstallNodeJs)

    $npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($null -ne $npmCommand) {
        return $npmCommand.Source
    }

    $npmCommand = Get-Command npm -ErrorAction SilentlyContinue
    if ($null -ne $npmCommand) {
        return $npmCommand.Source
    }

    if ($InstallNodeJs) {
        Install-NodeJs

        $npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
        if ($null -ne $npmCommand) {
            return $npmCommand.Source
        }

        $npmCommand = Get-Command npm -ErrorAction SilentlyContinue
        if ($null -ne $npmCommand) {
            return $npmCommand.Source
        }
    }

    throw "npm was not found. Install Node.js or add npm to PATH."
}

function Install-NodeJs {
    $wingetCommand = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -eq $wingetCommand) {
        throw "Node.js is not installed and winget is unavailable. Install Node.js manually or add winget to PATH."
    }

    $arguments = @(
        "install",
        "--id", "OpenJS.NodeJS.LTS",
        "--exact",
        "--accept-package-agreements",
        "--accept-source-agreements"
    )

    & $wingetCommand.Source $arguments

    $machineNodeRoot = "C:\Program Files\nodejs"
    if (Test-Path $machineNodeRoot) {
        $env:PATH = "$machineNodeRoot;$env:PATH"
    }
}

function Test-PythonModules {
    param(
        [string]$PythonExe,
        [string[]]$Modules
    )

    $importList = ($Modules | ForEach-Object { "import $_" }) -join "; "
    & $PythonExe -c $importList | Out-Null
}

function Start-LoggedProcess {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory,
        [string]$StdOutPath,
        [string]$StdErrPath
    )

    return Start-Process `
        -FilePath $FilePath `
        -ArgumentList $ArgumentList `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $StdOutPath `
        -RedirectStandardError $StdErrPath `
        -PassThru
}

function Get-ListeningProcessIdsForPort {
    param([int]$Port)

    $processIds = @()

    $getNetTcpCommand = Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue
    if ($null -ne $getNetTcpCommand) {
        $processIds = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique
    }
    else {
        $processIds = netstat -ano -p tcp |
            Select-String "LISTENING" |
            ForEach-Object {
                $line = ($_ -replace "\s+", " ").Trim()
                $parts = $line.Split(" ")
                if ($parts.Length -lt 5) {
                    return
                }
                $localAddress = $parts[1]
                $pid = $parts[-1]
                if ($localAddress -match ":(\d+)$" -and [int]$Matches[1] -eq $Port) {
                    $pid
                }
            } |
            Select-Object -Unique
    }

    return @($processIds | Where-Object { $_ })
}

function Stop-StaleListeners {
    param(
        [int[]]$Ports,
        [switch]$DryRun
    )

    $stopped = @()

    foreach ($port in $Ports | Select-Object -Unique) {
        $processIds = Get-ListeningProcessIdsForPort -Port $port
        foreach ($processId in $processIds) {
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($null -eq $process) {
                continue
            }

            if ($DryRun) {
                $stopped += [ordered]@{
                    port = $port
                    pid = $processId
                    process_name = $process.ProcessName
                    action = "would_stop"
                }
                continue
            }

            Stop-Process -Id $processId -Force -ErrorAction Stop
            $stopped += [ordered]@{
                port = $port
                pid = $processId
                process_name = $process.ProcessName
                action = "stopped"
            }
        }
    }

    return @($stopped)
}

function Wait-ForBackend {
    param(
        [string]$Url,
        [int]$TimeoutSeconds = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }

    throw "Backend did not become healthy at $Url within $TimeoutSeconds seconds."
}

$repoRoot = Get-RepoRoot
$runRoot = Join-Path $repoRoot ".local\services"
$logRoot = Join-Path $runRoot "logs"
$statePath = Join-Path $runRoot "local_services.json"
$backendUrl = "http://$BindHost`:$BackendPort"
$agentUrl = "http://$BindHost`:$AgentPort"

New-Item -ItemType Directory -Path $logRoot -Force | Out-Null

Import-DotEnv -Path (Join-Path $repoRoot ".env")
if ($env:POSTGRES_DSN -and -not $env:DATABASE_URL) {
    $env:DATABASE_URL = $env:POSTGRES_DSN
}

if ((Test-Path $statePath) -and -not $DryRun) {
    throw "Existing service state found at $statePath. Stop the current services first."
}

$pythonExe = Resolve-PythonExe -RepoRoot $repoRoot
if (-not $DryRun) {
    Test-PythonModules -PythonExe $pythonExe -Modules @("fastapi", "uvicorn", "psycopg")
}

$services = @()
$staleListeners = Stop-StaleListeners -Ports @($BackendPort, $AgentPort) -DryRun:$DryRun

$backendStdOut = Join-Path $logRoot "backend.stdout.log"
$backendStdErr = Join-Path $logRoot "backend.stderr.log"
$backendArgs = @(
    "-m", "uvicorn",
    "backend.main:app",
    "--host", $BindHost,
    "--port", "$BackendPort",
    "--reload"
)

if ($DryRun) {
    $services += [ordered]@{
        name = "backend"
        command = $pythonExe
        arguments = $backendArgs
        url = $backendUrl
        stdout_log = $backendStdOut
        stderr_log = $backendStdErr
    }
}
else {
    $backendProcess = Start-LoggedProcess `
        -FilePath $pythonExe `
        -ArgumentList $backendArgs `
        -WorkingDirectory $repoRoot `
        -StdOutPath $backendStdOut `
        -StdErrPath $backendStdErr

    Wait-ForBackend -Url "$backendUrl/health"

    $services += [ordered]@{
        name = "backend"
        pid = $backendProcess.Id
        url = $backendUrl
        stdout_log = $backendStdOut
        stderr_log = $backendStdErr
    }
}

$agentStdOut = Join-Path $logRoot "agent.stdout.log"
$agentStdErr = Join-Path $logRoot "agent.stderr.log"
$agentArgs = @(
    "-m", "uvicorn",
    "agent_backend.main:app",
    "--host", $BindHost,
    "--port", "$AgentPort",
    "--reload"
)

if ($DryRun) {
    $services += [ordered]@{
        name = "agent"
        command = $pythonExe
        arguments = $agentArgs
        url = $agentUrl
        stdout_log = $agentStdOut
        stderr_log = $agentStdErr
    }
}
else {
    $agentProcess = Start-LoggedProcess `
        -FilePath $pythonExe `
        -ArgumentList $agentArgs `
        -WorkingDirectory $repoRoot `
        -StdOutPath $agentStdOut `
        -StdErrPath $agentStdErr

    Wait-ForBackend -Url "$agentUrl/health"

    $services += [ordered]@{
        name = "agent"
        pid = $agentProcess.Id
        url = $agentUrl
        stdout_log = $agentStdOut
        stderr_log = $agentStdErr
    }
}

if ($IncludeMcpServer) {
    $npmExe = Resolve-NpmExe -InstallNodeJs:$InstallNodeJs
    $mcpRoot = Join-Path $repoRoot "mcp_server"
    $mcpStdOut = Join-Path $logRoot "mcp.stdout.log"
    $mcpStdErr = Join-Path $logRoot "mcp.stderr.log"

    if (-not (Test-Path (Join-Path $mcpRoot "node_modules"))) {
        if ($InstallNodeDeps -or $InstallNodeJs) {
            if (-not $DryRun) {
                & $npmExe install --prefix $mcpRoot
            }
        }
        elseif (-not $DryRun) {
            throw "mcp_server/node_modules is missing. Re-run with -InstallNodeDeps or run npm install in mcp_server."
        }
    }

    $mcpArgs = @("run", "dev")
    if ($DryRun) {
        $services += [ordered]@{
            name = "mcp_server"
            command = $npmExe
            arguments = $mcpArgs
            working_directory = $mcpRoot
            stdout_log = $mcpStdOut
            stderr_log = $mcpStdErr
        }
    }
    else {
        $mcpProcess = Start-LoggedProcess `
            -FilePath $npmExe `
            -ArgumentList $mcpArgs `
            -WorkingDirectory $mcpRoot `
            -StdOutPath $mcpStdOut `
            -StdErrPath $mcpStdErr

        $services += [ordered]@{
            name = "mcp_server"
            pid = $mcpProcess.Id
            working_directory = $mcpRoot
            stdout_log = $mcpStdOut
            stderr_log = $mcpStdErr
        }
    }
}

$state = [ordered]@{
    started_at = (Get-Date).ToString("o")
    repo_root = $repoRoot
    stale_listeners = $staleListeners
    services = $services
}

if (-not $DryRun) {
    $state | ConvertTo-Json -Depth 8 | Set-Content -Path $statePath -Encoding UTF8
}

$state | ConvertTo-Json -Depth 8
