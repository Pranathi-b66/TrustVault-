# Restarts the local TrustVault dev server on 8088 against the current build.
# Any process already listening on 8088 is stopped first; the server then runs in the
# foreground of whatever terminal launches this script.
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-24'
$repo = 'c:\Users\hp\Desktop\trustvalut'
Set-Location $repo

if (-not $env:TRUSTVAULT_DB_PASSWORD) {
    throw 'TRUSTVAULT_DB_PASSWORD is not set. Export the Aiven database password in this shell before starting.'
}

Get-NetTCPConnection -LocalPort 8088 -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "stopping pid $($_.OwningProcess) on 8088"
    Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

& 'C:\Users\hp\AppData\Local\Programs\Maven\apache-maven-3.9.9\bin\mvn.cmd' -o spring-boot:run
