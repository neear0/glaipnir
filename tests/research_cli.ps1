param([string]$Harness, [string]$Fixture, [string]$Root)
$ErrorActionPreference = 'Stop'
$location = Join-Path $Root ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $location | Out-Null
$store = Join-Path $location 'store'
$session = (& $Harness --store $store --json session create $Fixture | ConvertFrom-Json).session_id
if ($LASTEXITCODE -ne 0 -or !$session) { throw 'Research CLI session failed' }
$parameters = Join-Path $location 'parameters.json'
@{executable=$Fixture; arguments=@('crash'); entry_breakpoint=$false} | ConvertTo-Json | Set-Content -Encoding utf8 $parameters
$result = & $Harness --store $store --json debug run $session "@$parameters" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $result.outcome -ne 'crash') { throw 'Research CLI debugger failed' }
$catalog = @(& $Harness --store $store --json crash list $session | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0 -or $catalog.Count -lt 1) { throw 'Research CLI catalog failed' }
$record = & $Harness --store $store --json crash show $session $catalog[0].id | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $record.data.verified_vulnerability) { throw 'Research CLI record failed' }
$workspace = Join-Path $store $result.artifact_root
$manifest = Join-Path $workspace $result.crashes[0].reproducer
@{manifest=$manifest} | ConvertTo-Json | Set-Content -Encoding utf8 $parameters
$replayed = & $Harness --store $store --json crash replay $session "@$parameters" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !$replayed.reproduced) { throw 'Research CLI replay failed' }
$corpus = Join-Path $location 'corpus'
New-Item -ItemType Directory -Force $corpus | Out-Null
[IO.File]::WriteAllText((Join-Path $corpus 'seed.bin'), 'CRASH')
@{executable=$Fixture; arguments=@('input','{input}'); corpus=$corpus; iterations=1} | ConvertTo-Json | Set-Content -Encoding utf8 $parameters
$campaign = & $Harness --store $store --json fuzz run $session "@$parameters" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $campaign.crash_count -ne 1) { throw 'Research CLI campaign failed' }
& $Harness --store $store --json session export $session (Join-Path $location 'export') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Research CLI export failed' }
$dumps = @(Get-ChildItem -LiteralPath (Join-Path $location 'export') -Filter '*.dmp' -Recurse)
if ($dumps.Count -lt 3) { throw 'Research CLI binary export incomplete' }
Write-Output 'PASS research CLI workflows, catalog, replay and binary export'
