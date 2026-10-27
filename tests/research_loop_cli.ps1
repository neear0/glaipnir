param([string]$Harness, [string]$Fixture, [string]$Root)
$ErrorActionPreference = 'Stop'
$location = Join-Path $Root ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $location | Out-Null
$store = Join-Path $location 'store'
$parameters = Join-Path $location 'parameters.json'
function Invoke-ResearchCommand {
    param([string[]]$CommandArguments)
    $result = & $Harness --store $store --json @CommandArguments
    if ($LASTEXITCODE -ne 0) { throw "Research command failed: $($CommandArguments -join ' ')" }
    return $result | ConvertFrom-Json
}
function Write-Parameters {
    param($Value)
    $Value | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 $parameters
}
$source = (Invoke-ResearchCommand @('session', 'create', $Fixture)).session_id
Write-Parameters @{path=$Fixture}
$observation = Invoke-ResearchCommand @('tool', 'run', $source, 'file_metadata', "@$parameters")
Write-Parameters @{text='The fixture exits normally'; observation_ids=@($observation.observation_id)}
$hypothesis = Invoke-ResearchCommand @('hypothesis', 'create', $source, "@$parameters")
Write-Parameters @{hypothesis_id=$hypothesis.hypothesis_id; tool='debug_run'; arguments=@{executable=$Fixture; arguments=@('normal'); entry_breakpoint=$false}; expected_outcome='Exit status zero'}
$experiment = Invoke-ResearchCommand @('experiment', 'run', $source, "@$parameters")
if ($experiment.outcome -ne 'exit' -or !$experiment.experiment_id) { throw 'Experiment did not collect measurements' }
Write-Parameters @{hypothesis_id=$hypothesis.hypothesis_id; experiment_ids=@($experiment.experiment_id); status='supported'; conclusion='Measured normal exit; unverified interpretation'}
$assessment = Invoke-ResearchCommand @('hypothesis', 'assess', $source, "@$parameters")
if ($assessment.record.data.verified) { throw 'Assessment incorrectly promoted to verified' }
$shown = Invoke-ResearchCommand @('hypothesis', 'show', $source, $hypothesis.hypothesis_id)
if ($shown.record.data.status -ne 'supported') { throw 'Hypothesis status was not reconstructed' }
$listed = Invoke-ResearchCommand @('experiment', 'list', $source)
if ($listed.records.Count -ne 1 -or $listed.records[0].state -ne 'succeeded') { throw 'Experiment listing lost persisted state' }
Write-Parameters @{artifact_id=$experiment.artifact_id; length=32}
$bytes = Invoke-ResearchCommand @('tool', 'run', $source, 'evidence_read', "@$parameters")
if ($bytes.bytes_read -ne 32 -or $bytes.hex.Length -ne 64) { throw 'Evidence read did not honor its bound' }
$destination = (Invoke-ResearchCommand @('session', 'create', $Fixture)).session_id
Write-Parameters @{record_ids=@($hypothesis.hypothesis_id)}
$imported = Invoke-ResearchCommand @('research', 'import', $destination, $source, "@$parameters")
if (!$imported.import_id -or $imported.record_ids.Count -lt 5) { throw 'Research import omitted dependencies' }
$context = Invoke-ResearchCommand @('research', 'context', $destination)
if ($context.records.Count -lt 3 -or $context.verified) { throw 'Imported context unavailable or incorrectly verified' }
$export = Join-Path $location 'export'
Invoke-ResearchCommand @('session', 'export', $destination, $export) | Out-Null
$history = Get-Content -LiteralPath (Join-Path $export 'history.json') -Raw | ConvertFrom-Json
foreach ($record in $history.records) {
    if ($record.kind -eq 'artifact') {
        $stream = [IO.File]::OpenRead((Join-Path $export $record.data.path))
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose(); $stream.Dispose() }
        if ($hash -ne $record.data.sha256) { throw 'Imported export artifact integrity mismatch' }
    }
}
@("research context $destination", "hypothesis list $source", 'exit') | & $Harness --store $store --json shell | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Interactive research commands failed' }
Write-Output 'PASS research hypotheses, experiments, assessments, context, explicit imports and self-contained exports'
