# tyto — rebuild the Linux binary and redeploy the console into Kali (WSL2).
# Run from Windows (PowerShell):  pwsh C:\Users\dukot\tyto\scripts\redeploy.ps1
# Edit internal/webui/index.html or cmd/tyto/serve.go, run this, refresh the browser.
$ErrorActionPreference = "Stop"
$proj = "C:\Users\dukot\tyto"

Write-Host "==> go test ./cmd/tyto/ ..." -ForegroundColor Cyan
go -C $proj test ./cmd/tyto/
if ($LASTEXITCODE -ne 0) { throw "tests failed — not deploying" }

Write-Host "==> Cross-compiling static Linux binary ..." -ForegroundColor Cyan
$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go -C $proj build -o bin/tyto-linux-amd64 ./cmd/tyto
$ok = $LASTEXITCODE -eq 0
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
if (-not $ok) { throw "build failed" }

Write-Host "==> Restarting console inside Kali ..." -ForegroundColor Cyan
wsl -d kali-linux -- bash -lc 'pkill -x tyto; sleep 2; cp /mnt/c/Users/dukot/tyto/bin/tyto-linux-amd64 /root/tyto && chmod +x /root/tyto; cd /root; nohup setsid env TYTO_MODEL=qwen3:30b-a3b /root/tyto serve --addr 0.0.0.0:8088 --ollama-url http://172.22.208.1:11434 >/tmp/tyto-serve.log 2>&1 & sleep 3; cat /tmp/tyto-serve.log'

Write-Host "==> Done. Hard-refresh http://localhost:8088 (Ctrl+Shift+R)" -ForegroundColor Green
