# SecureEye One-Click Deploy Script
Write-Host "🚀 Starting SecureEye Automated Deployment..." -ForegroundColor Cyan

# 1. Stage all changes
Write-Host "📦 Staging changes..." -ForegroundColor Yellow
git add .

# 2. Commit with timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$message = "Auto-update: $timestamp"
Write-Host "💾 Committing changes with message: '$message'..." -ForegroundColor Yellow
git commit -m $message

# 3. Push to GitHub
Write-Host "☁️ Pushing to GitHub (origin main)..." -ForegroundColor Yellow
git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Deployment Successful! Your website will be updated in 2-3 minutes." -ForegroundColor Green
} else {
    Write-Host "❌ Deployment Failed. Please check the error messages above." -ForegroundColor Red
}

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
