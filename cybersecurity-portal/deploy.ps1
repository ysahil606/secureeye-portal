# SecureEye One-Click Deploy Script
Write-Host "Starting SecureEye Automated Deployment..."

# 1. Stage all changes
Write-Host "Staging changes..."
git add .

# 2. Commit with timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd HH-mm-ss"
$message = "Auto-update $timestamp"
Write-Host "Committing changes..."
git commit -m "$message"

# 3. Push to GitHub
Write-Host "Pushing to GitHub..."
git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS: Deployment complete."
} else {
    Write-Host "ERROR: Deployment failed."
}

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
