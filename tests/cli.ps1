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
$typedTargets = @(
    @{kind='file'; locator=$Fixture; tool='file_metadata'; arguments=@{path=$Fixture}},
    @{kind='process'; locator=[string]$PID; tool='process_info'; arguments=@{pid=$PID}},
    @{kind='service'; locator='EventLog'; tool='service_info'; arguments=@{name='EventLog'}},
    @{kind='registry'; locator='HKCU\Software'; tool='registry_list'; arguments=@{key='HKCU\Software'; limit=2}},
    @{kind='machine'; locator=$null; tool='token_info'; arguments=@{}}
)
foreach ($target in $typedTargets) {
    $createArgs = @('--store', $store, '--json', 'session', 'create', '--type', $target.kind)
    if ($target.locator) { $createArgs += $target.locator }
    if ($target.kind -eq 'registry') { $createArgs += @('--view', '64') }
    $created = & $Harness @createArgs | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or !$created.session_id) { throw "Typed CLI session failed: $($target.kind)" }
    $id = $created.session_id
    $target.arguments | ConvertTo-Json | Set-Content -Encoding utf8 $argumentsFile
    $native = & $Harness --store $store --json tool run $id $target.tool "@$argumentsFile" | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or !$native.ok) { throw "Typed CLI inspection failed: $($target.kind)" }
    $shown = & $Harness --store $store --json session show $id | ConvertFrom-Json
    if ($shown.session.target_info.kind -ne $target.kind) { throw 'Typed CLI metadata failed' }
    $commands = @("session show $id", 'exit')
    $reopened = $commands | & $Harness --store $store --json shell | ConvertFrom-Json
    if ($reopened.session.target_info.kind -ne $target.kind) { throw 'Typed interactive session failed' }
    $typedExport = Join-Path $location "export-$id"
    & $Harness --store $store --json session export $id $typedExport | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Typed CLI export failed' }
}
$version = & $Harness --version
if ($version -ne '0.3.0') { throw 'CLI version mismatch' }
Write-Output 'PASS CLI typed file, process, service, registry and machine sessions'
