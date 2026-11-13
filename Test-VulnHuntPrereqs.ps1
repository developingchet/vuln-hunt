[CmdletBinding()]
param([switch]$RequireClaudeSecurity)
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
$rows=@()
$gitEnvNames=@('GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES','GIT_COMMON_DIR','GIT_NAMESPACE','GIT_CONFIG','GIT_CONFIG_GLOBAL','GIT_CONFIG_SYSTEM','GIT_CONFIG_NOSYSTEM','GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS','GIT_QUARANTINE_PATH','GIT_SHALLOW_FILE','GIT_EXEC_PATH','GIT_EXTERNAL_DIFF','GIT_ATTR_NOSYSTEM')
function Add-Result([string]$Name,[bool]$OK,[string]$Detail){$script:rows+=[pscustomobject]@{Prerequisite=$Name;OK=$OK;Detail=$Detail}}
$claude=Get-TrustedApplication 'claude'
if($claude){$v=(& $claude.Source --version 2>$null|Out-String).Trim();$ok=$false;if($v -match '(\d+\.\d+\.\d+)'){$ok=([version]$Matches[1] -ge [version]'2.1.305')};Add-Result 'Claude Code >= 2.1.305' $ok $v}else{Add-Result 'Claude Code >= 2.1.305' $false 'claude not on PATH'}
$node=Get-TrustedApplication 'node'
if($node){$out=& $node.Source -e "const c=require('crypto'),f=require('fs');const ok=typeof TextDecoder==='function'&&typeof c.randomUUID==='function'&&typeof f.lstatSync==='function';process.stdout.write(process.version+' '+(ok?'OK':'MISSING_APIS'));process.exit(ok?0:2)";Add-Result 'Node standard-library capabilities' ($LASTEXITCODE -eq 0) $out}else{Add-Result 'Node standard-library capabilities' $false 'node not on PATH'}
$poison=@();foreach($n in $gitEnvNames){if(Test-Path "Env:$n"){$poison+=$n}};Get-ChildItem Env: | Where-Object {$_.Name -match '^GIT_CONFIG_(KEY|VALUE)_\d+$' -or $_.Name -match '^GIT_TRACE($|_)'} | ForEach-Object {$poison+=$_.Name};Add-Result 'Git repository-selection/config environment clean' ($poison.Count -eq 0) ($(if($poison.Count){$poison -join ', '}else{'OK'}))
$git=Get-TrustedApplication 'git'
if($git){
  Add-Result 'Git' $true ((& $git.Source --version|Out-String).Trim())
  if($poison.Count -eq 0){
    try{
      $repoRoot=(& $git.Source --no-replace-objects --no-optional-locks -c core.fsmonitor=false -C (Get-Location).Path rev-parse --show-toplevel 2>$null | Out-String).Trim()
      if($LASTEXITCODE -eq 0 -and $repoRoot){
        $cur=[IO.Path]::GetFullPath((Get-Location).Path);$stop=[IO.Path]::GetFullPath($repoRoot);$shadows=@()
        while($true){foreach($rel in @('.claude\workflows\vuln-hunt.js','.claude\commands\vuln-hunt.md','.claude\skills\vuln-hunt')){$candidate=Join-Path $cur $rel;if(Test-Path -LiteralPath $candidate){$shadows+=$candidate}};if([IO.Path]::GetFullPath($cur) -eq [IO.Path]::GetFullPath($stop)){break};$parent=[IO.Directory]::GetParent($cur);if(-not $parent){break};$cur=$parent.FullName}
        Add-Result 'No project /vuln-hunt command shadow' ($shadows.Count -eq 0) ($(if($shadows.Count){$shadows -join ', '}else{'OK'}))
      }else{Add-Result 'No project /vuln-hunt command shadow' $false 'could not resolve repository root'}
    }catch{Add-Result 'No project /vuln-hunt command shadow' $false $_.Exception.Message}
  }else{Add-Result 'No project /vuln-hunt command shadow' $false 'Git environment must be cleaned before resolving workflow precedence'}
}else{Add-Result 'Git' $false 'git not on PATH';Add-Result 'No project /vuln-hunt command shadow' $false 'requires Git'}
$helper=Join-Path $PSScriptRoot 'vuln-hunt-attest.js'
if($git -and $node -and (Test-Path -LiteralPath $helper)){
  $tmp=Join-Path ([IO.Path]::GetTempPath()) ('vuln-hunt-prereq-'+[guid]::NewGuid().ToString('N'))
  try{New-Item -ItemType Directory -Force $tmp|Out-Null;& $git.Source -C $tmp init -q;Push-Location $tmp;try{$j=& $node.Source $helper --self-test;$ok=$LASTEXITCODE -eq 0;if($ok){$o=$j|ConvertFrom-Json;$ok=[bool]$o.ok};Add-Result 'Attestation Git capability self-test' $ok ($j|Out-String).Trim()}finally{Pop-Location}}catch{Add-Result 'Attestation Git capability self-test' $false $_.Exception.Message}finally{if(Test-Path -LiteralPath $tmp){Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue}}
}else{Add-Result 'Attestation Git capability self-test' $false 'requires node, git, and bundled helper'}
if($RequireClaudeSecurity){$py=Get-TrustedApplication 'python3';if($py){$pv=(& $py.Source --version 2>&1|Out-String).Trim();$ok=$false;if($pv -match '(\d+\.\d+\.\d+)'){$ok=([version]$Matches[1] -ge [version]'3.9.0')};Add-Result 'python3 >= 3.9 (Claude Security comparison)' $ok $pv}else{Add-Result 'python3 >= 3.9 (Claude Security comparison)' $false 'python3 not on PATH'}}
$rows|Format-Table -AutoSize
Write-Host 'Manual check: in Claude Code /config, ensure Dynamic workflows are enabled; keep the workflow size/concurrency settings fixed for benchmarks.'
if($rows.Where({-not $_.OK}).Count){exit 1}
