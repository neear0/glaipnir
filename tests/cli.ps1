param([string]$Harness, [string]$Fixture, [string]$Root)
$ErrorActionPreference = 'Stop'
$location = Join-Path $Root ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $location | Out-Null
$store = Join-Path $location 'store'
$created = & $Harness --store $store --json session create $Fixture | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !$created.session_id) { throw 'CLI session creation failed' }
$session = $created.session_id
$argumentsFile = Join-Path $location 'arguments.json'
@{path=$Fixture} | ConvertTo-Json | Set-Content -Encoding utf8 $argumentsFile
$result = & $Harness --store $store --json tool run $session file_sha256 "@$argumentsFile" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !$result.ok -or !$result.sha256) { throw 'CLI native dispatch failed' }
$commands = "session show $session`nexit`n"
$history = $commands | & $Harness --store $store --json shell | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $history.session.id -ne $session -or $history.records.Count -ne 3) { throw 'Interactive session history failed' }
$destination = Join-Path $location 'export'
$exported = & $Harness --store $store --json session export $session $destination | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath (Join-Path $destination 'reproduction.json'))) { throw 'CLI export failed' }
$manifest = Get-Content -Raw (Join-Path $destination 'reproduction.json') | ConvertFrom-Json
if ($manifest.operations.Count -ne 1 -or $manifest.operations[0].state -ne 'succeeded') { throw 'CLI reproduction data failed' }
Write-Output 'PASS CLI create, manual dispatch, interactive prompt, restart and export'
