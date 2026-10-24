# Runs the TrustVault test suites against a scratch schema so the demo database keeps a clean
# audit trail. The schema (trustvault_verify) is a DDL-only copy of `trustvault`.
#
# The datasource is overridden through the environment (SPRING_DATASOURCE_URL) rather than a
# -D flag: the JDBC URL contains '&', which cmd.exe would split on the way into mvn.cmd.
#
#   .\run-biometric-tests.ps1         # the two biometric suites only
#   .\run-biometric-tests.ps1 -Full   # every suite
param([switch]$Full)

$env:JAVA_HOME = 'C:\Program Files\Java\jdk-24'
$env:SPRING_DATASOURCE_URL = 'jdbc:mysql://localhost:3306/trustvault_verify?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC'
$mvn = 'C:\Users\hp\AppData\Local\Programs\Maven\apache-maven-3.9.9\bin\mvn.cmd'
$repo = 'c:\Users\hp\Desktop\trustvalut'
$log = Join-Path $env:TEMP 'tv-tests.log'

$goals = if ($Full) {
    @('-o', 'test')
} else {
    @('-o', '-Dtest=AuthorizationAndBiometricHardeningTest,FaceUniquenessIntegrationTest',
        '-DfailIfNoSpecifiedTests=false', 'test')
}

Set-Location $repo
$output = & $mvn @goals 2>&1 | Out-String
Set-Content -Path $log -Value $output

($output -split "`r?`n") |
    Select-String -Pattern 'Tests run|BUILD SUCCESS|BUILD FAILURE|ERROR|FAILURE' |
    ForEach-Object { $_.Line.Trim() } |
    Select-Object -First 60
