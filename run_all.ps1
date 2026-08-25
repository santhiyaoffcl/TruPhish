# run_all.ps1
Write-Host "🟢 Starting Node Backend (Port 5000)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd d:\TruPhish\backend; npm run dev"

Write-Host "🟡 Starting React Frontend (Vite)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd d:\TruPhish\frontend; npm run dev"

Write-Host "✅ All services have been launched in separate terminal windows." -ForegroundColor Magenta
