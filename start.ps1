# Запуск портала SOC локально.
#   powershell -ExecutionPolicy Bypass -File start.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Подгружаем ключи из .env (SECRET_KEY, RPZ_FERNET_KEY)
Get-Content "$PSScriptRoot\.env" | ForEach-Object {
    if ($_ -match '^\s*([^#=]+)=(.*)$') {
        Set-Item -Path "env:$($matches[1].Trim())" -Value $matches[2].Trim()
    }
}
$env:FLASK_APP = "run.py"

# Порт 5000 на этой машине занят сторонней программой (Mftp2), поэтому 5050.
$port = if ($env:PORT) { $env:PORT } else { "5050" }
Write-Host "Портал SOC: http://127.0.0.1:$port"

& "$PSScriptRoot\venv\Scripts\python.exe" -m flask run --host 127.0.0.1 --port $port --debug
