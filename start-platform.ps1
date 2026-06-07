param(
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8NoBom
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$repoRoot = $PSScriptRoot
$backendDir = Join-Path $repoRoot "backend"
$frontendDir = Join-Path $repoRoot "frontend"
$backendPort = 8000
$frontendPort = 3000

function Write-Info {
    param([string]$Message)

    [Console]::WriteLine($Message)
}

function Test-CommandExists {
    param([string]$Name)

    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-Step {
    param(
        [string]$Description,
        [scriptblock]$Action
    )

    Write-Info "[STEP] $Description"
    if ($DryRun) {
        return
    }
    & $Action
}

function Test-TcpPortOpen {
    param([int]$Port)

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $asyncResult = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        $connected = $asyncResult.AsyncWaitHandle.WaitOne(300)
        if (-not $connected) {
            return $false
        }
        $client.EndConnect($asyncResult) | Out-Null
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Ensure-BackendDependencies {
    if ($DryRun) {
        Write-Info "[DRYRUN] Skip backend dependency check"
        return
    }

    & python -c "import fastapi,uvicorn,sqlalchemy,aiosqlite"
    if ($LASTEXITCODE -eq 0) {
        Write-Info "[OK] Backend dependencies ready"
        return
    }

    Invoke-Step "Install backend dependencies" {
        Push-Location $backendDir
        & python -m pip install -r requirements.txt
        $exitCode = $LASTEXITCODE
        Pop-Location
        if ($exitCode -ne 0) {
            throw "Backend dependency install failed."
        }
    }
}

function Ensure-FrontendDependencies {
    $nodeModulesDir = Join-Path $frontendDir "node_modules"
    if (Test-Path $nodeModulesDir) {
        Write-Info "[OK] Frontend dependencies ready"
        return
    }

    Invoke-Step "Install frontend dependencies" {
        Push-Location $frontendDir
        & npm.cmd install
        $exitCode = $LASTEXITCODE
        Pop-Location
        if ($exitCode -ne 0) {
            throw "Frontend dependency install failed."
        }
    }
}

function Start-BackendWindow {
    if ($DryRun) {
        Invoke-Step "Start backend http://127.0.0.1:$backendPort" { }
        return
    }

    if (Test-TcpPortOpen -Port $backendPort) {
        Write-Info "[SKIP] Backend port $backendPort is already in use"
        return
    }

    Invoke-Step "Start backend http://127.0.0.1:$backendPort" {
        $backendCommand = @"
`$utf8NoBom = [System.Text.UTF8Encoding]::new(`$false)
[Console]::InputEncoding = `$utf8NoBom
[Console]::OutputEncoding = `$utf8NoBom
`$OutputEncoding = `$utf8NoBom
`$env:PYTHONUTF8 = '1'
`$env:PYTHONIOENCODING = 'utf-8'
python -m uvicorn main:app --host 127.0.0.1 --port $backendPort --reload
"@
        Start-Process -FilePath "powershell.exe" -WorkingDirectory $backendDir -ArgumentList @(
            "-NoExit",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            $backendCommand
        ) | Out-Null
    }
}

function Start-FrontendWindow {
    if ($DryRun) {
        Invoke-Step "Start frontend http://127.0.0.1:$frontendPort" { }
        return
    }

    if (Test-TcpPortOpen -Port $frontendPort) {
        Write-Info "[SKIP] Frontend port $frontendPort is already in use"
        return
    }

    Invoke-Step "Start frontend http://127.0.0.1:$frontendPort" {
        $frontendCommand = @"
`$utf8NoBom = [System.Text.UTF8Encoding]::new(`$false)
[Console]::InputEncoding = `$utf8NoBom
[Console]::OutputEncoding = `$utf8NoBom
`$OutputEncoding = `$utf8NoBom
npm.cmd run dev -- --host 127.0.0.1 --port $frontendPort
"@
        Start-Process -FilePath "powershell.exe" -WorkingDirectory $frontendDir -ArgumentList @(
            "-NoExit",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            $frontendCommand
        ) | Out-Null
    }
}

if (-not (Test-CommandExists -Name "python")) {
    throw "python was not found in PATH."
}

if (-not (Test-CommandExists -Name "npm.cmd")) {
    throw "npm.cmd was not found in PATH."
}

Ensure-BackendDependencies
Ensure-FrontendDependencies
Start-BackendWindow
Start-FrontendWindow

Write-Info ""
Write-Info "Launch commands sent:"
Write-Info "  Backend:  http://127.0.0.1:$backendPort"
Write-Info "  Frontend: http://127.0.0.1:$frontendPort"
Write-Info ""
Write-Info "To stop the platform, close the two PowerShell windows opened by this script."
