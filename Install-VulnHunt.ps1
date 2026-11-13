[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
# Executables are resolved before Git can name the top level, so every ancestor holding a .git entry bounds repository-controlled content, as does the main checkout named by a linked worktree's .git file.
function Get-LinkedMainRoot([string]$GitFile){
  try{
    $m=[regex]::Match([IO.File]::ReadAllText($GitFile),'(?m)^gitdir:\s*(.+?)\s*$');if(-not $m.Success){return $null}
    $gitdir=[IO.Path]::GetFullPath([IO.Path]::Combine([IO.Path]::GetDirectoryName($GitFile),$m.Groups[1].Value));$common=$gitdir
    $cd=Join-Path $gitdir 'commondir';if(Test-Path -LiteralPath $cd -PathType Leaf){$common=[IO.Path]::GetFullPath([IO.Path]::Combine($gitdir,[IO.File]::ReadAllText($cd).Trim()))}
    $common=$common.TrimEnd('\','/');if([IO.Path]::GetFileName($common) -eq '.git'){return [IO.Path]::GetDirectoryName($common)}
  }catch{}
  return $null
}
function Get-RepositoryBoundaries{
  $start=[IO.Path]::GetFullPath((Get-Location).Path);$roots=@()
  for($d=$start;$d;$d=[IO.Path]::GetDirectoryName($d)){
    $g=Join-Path $d '.git'
    if(Test-Path -LiteralPath $g){$roots+=$d;if(Test-Path -LiteralPath $g -PathType Leaf){$main=Get-LinkedMainRoot $g;if($main){$roots+=$main}}}
  }
  if(-not $roots.Count){$roots=@($start)}
  return $roots
}
function Get-TrustedApplication([string]$Name){
  $sep=[IO.Path]::DirectorySeparatorChar.ToString();$prefixes=@(Get-RepositoryBoundaries|ForEach-Object{if($_.EndsWith($sep)){$_}else{$_+$sep}})
  foreach($cmd in @(Get-Command $Name -All -CommandType Application -ErrorAction SilentlyContinue)){
    $p=[IO.Path]::GetFullPath($cmd.Source);if(-not @($prefixes|Where-Object{$p.StartsWith($_,[StringComparison]::OrdinalIgnoreCase)}).Count){return $cmd}
  }
  return $null
}
$workflowSrc=Join-Path $PSScriptRoot 'vuln-hunt.js'
$attestSrc=Join-Path $PSScriptRoot 'vuln-hunt-attest.js'
$wrapperSrc=Join-Path $PSScriptRoot 'Get-VulnHuntAttestation.ps1'
$prereqSrc=Join-Path $PSScriptRoot 'Test-VulnHuntPrereqs.ps1'
$postflightSrc=Join-Path $PSScriptRoot 'Compare-VulnHuntPostflight.ps1'
$agentsSrc=Join-Path $PSScriptRoot 'vuln-hunt-agents.json'
$launchSrc=Join-Path $PSScriptRoot 'vuln-hunt-launch.js'
foreach($p in @($workflowSrc,$attestSrc,$wrapperSrc,$prereqSrc,$postflightSrc,$agentsSrc,$launchSrc)){if(-not(Test-Path -LiteralPath $p)){throw "Missing package file: $p"}}
$nodeCmd=Get-TrustedApplication 'node'
if(-not $nodeCmd){throw 'Node.js was not found on PATH. v8 strict provenance requires the bundled Node attestation helper.'}
try{
  $nodeCaps=& $nodeCmd.Source -e "const c=require('crypto'),f=require('fs');if(typeof TextDecoder!=='function'||typeof c.randomUUID!=='function'||typeof f.lstatSync!=='function')process.exit(2);process.stdout.write(process.version)"
  if($LASTEXITCODE -ne 0){throw "Node runtime lacks required standard-library APIs"}
  Write-Host "Node prerequisite OK: $nodeCaps"
}catch{throw "Node prerequisite failed: $($_.Exception.Message)"}
$gitCmd=Get-TrustedApplication 'git'
if(-not $gitCmd){throw 'Git was not found on PATH. /vuln-hunt v8 requires Git-backed provenance.'}
$tmp=Join-Path ([IO.Path]::GetTempPath()) ('vuln-hunt-selftest-'+[guid]::NewGuid().ToString('N'))
try{
  New-Item -ItemType Directory -Force $tmp|Out-Null
  & $gitCmd.Source -C $tmp init -q
  if($LASTEXITCODE -ne 0){throw 'git init failed during capability self-test'}
  Push-Location $tmp
  try{$selfJson=& $nodeCmd.Source $attestSrc --self-test;if($LASTEXITCODE -ne 0){throw 'attestation helper self-test failed'};$self=$selfJson|ConvertFrom-Json;if(-not $self.ok){throw 'attestation helper reported a failed capability'}}finally{Pop-Location}
  Write-Host "Git/helper prerequisite OK: $($self.checks.gitVersion)"
}finally{if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue}}
$claudeCmd=Get-TrustedApplication 'claude'
if($claudeCmd){
  try{
    $verText=(& $claudeCmd.Source --version 2>$null | Out-String)
    if($verText -match '(\d+\.\d+\.\d+)'){
      $ver=[version]$Matches[1]
      if($ver -lt [version]'2.1.305'){Write-Warning "Claude Code $ver detected. Update to v2.1.305+ before running v8; older workflow runtimes could unexpectedly rerun completed agents on replay."}
    }
  }catch{Write-Warning "Could not verify Claude Code version: $($_.Exception.Message)"}
}else{Write-Warning 'Claude Code CLI was not found on PATH; install/update it before running the workflow.'}
$claude=Join-Path $HOME '.claude'
$workflowDir=Join-Path $claude 'workflows'
$workflowDst=Join-Path $workflowDir 'vuln-hunt.js'
$toolDir=Join-Path $claude 'vuln-hunt'
$nonce=(Get-Date -Format 'yyyyMMdd-HHmmss-fff')+'-'+([guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force $workflowDir,$toolDir|Out-Null
if(Test-Path -LiteralPath $workflowDst){$backup="$workflowDst.$nonce.bak";Copy-Item -LiteralPath $workflowDst -Destination $backup -Force;Write-Host "Backed up existing workflow to: $backup"}
Copy-Item -LiteralPath $workflowSrc -Destination $workflowDst -Force
Copy-Item -LiteralPath $attestSrc -Destination (Join-Path $toolDir 'vuln-hunt-attest.js') -Force
Copy-Item -LiteralPath $wrapperSrc -Destination (Join-Path $toolDir 'Get-VulnHuntAttestation.ps1') -Force
Copy-Item -LiteralPath $prereqSrc -Destination (Join-Path $toolDir 'Test-VulnHuntPrereqs.ps1') -Force
Copy-Item -LiteralPath $postflightSrc -Destination (Join-Path $toolDir 'Compare-VulnHuntPostflight.ps1') -Force
Copy-Item -LiteralPath $agentsSrc -Destination (Join-Path $toolDir 'vuln-hunt-agents.json') -Force
Copy-Item -LiteralPath $launchSrc -Destination (Join-Path $toolDir 'vuln-hunt-launch.js') -Force
# User-level copies of the worker agents let /vuln-hunt run in an ordinary session; vuln-hunt-launch.js passes the same definitions with --agents instead.
$agentDir=Join-Path $claude 'agents'
New-Item -ItemType Directory -Force $agentDir|Out-Null
$defs=[IO.File]::ReadAllText($agentsSrc)|ConvertFrom-Json
foreach($p in $defs.PSObject.Properties){
  $d=$p.Value
  $text=(@('---',"name: $($p.Name)","description: `"$($d.description)`"","tools: $(@($d.tools) -join ', ')","model: $($d.model)","omitClaudeMd: $(([string]$d.omitClaudeMd).ToLowerInvariant())",'---','',$d.prompt,'') -join "`n")
  $dst=Join-Path $agentDir "$($p.Name).md"
  if((Test-Path -LiteralPath $dst) -and [IO.File]::ReadAllText($dst) -ne $text){Copy-Item -LiteralPath $dst -Destination "$dst.$nonce.bak" -Force;Write-Host "Backed up existing agent to: $dst.$nonce.bak"}
  [IO.File]::WriteAllText($dst,$text,[Text.UTF8Encoding]::new($false))
  Write-Host "Installed worker agent: $dst"
}
$legacySkill=Join-Path $claude 'skills\vuln-hunt'
if(Test-Path -LiteralPath $legacySkill){$legacyBackup=Join-Path $claude "vuln-hunt-legacy-skill-$nonce";Move-Item -LiteralPath $legacySkill -Destination $legacyBackup;Write-Host "Moved legacy user-level vuln-hunt Skill to: $legacyBackup"}
foreach($rel in @('.claude\workflows\vuln-hunt.js','.claude\commands\vuln-hunt.md','.claude\skills\vuln-hunt')){$projectCollision=Join-Path (Get-Location) $rel;if(Test-Path -LiteralPath $projectCollision){Write-Warning "Project-local /vuln-hunt command collision detected: $projectCollision. Rename/remove it before using the personal v8 workflow."}}
Write-Host "Installed vuln-hunt v8 workflow: $workflowDst"
Write-Host "Installed attestation helper: $toolDir"
Write-Host 'Next: in Claude Code run /reload-skills (or start a fresh session), ensure Dynamic workflows are enabled in /config, choose /model, then run /vuln-hunt.'
Write-Host "For strict provenance and benchmarks, start Claude Code from the repository root with: node `"$(Join-Path $toolDir 'vuln-hunt-launch.js')`""
Write-Host 'and generate a fresh attestation for every run.'
