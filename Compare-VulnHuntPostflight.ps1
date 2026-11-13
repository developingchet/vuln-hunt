[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$BeforeFile,
  [string]$Range
)
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
  throw "No trusted $Name executable outside the target repository was found on PATH."
}
# rootCounts and other path-keyed objects may hold keys that differ only by case, which ConvertFrom-Json rejects on Windows PowerShell.
function ConvertFrom-CaseSensitiveJson([string]$Json){
  # -AsHashtable keys are case-insensitive before PowerShell 7.3.
  if($PSVersionTable.PSEdition -eq 'Core'){if($PSVersionTable.PSVersion -lt [version]'7.3'){throw 'Run postflight comparison under Windows PowerShell 5.1 or PowerShell 7.3+.'};return ($Json|ConvertFrom-Json -AsHashtable)}
  Add-Type -AssemblyName System.Web.Extensions
  $serializer=New-Object System.Web.Script.Serialization.JavaScriptSerializer;$serializer.MaxJsonLength=[int]::MaxValue
  return $serializer.DeserializeObject($Json)
}
$helper=Join-Path $PSScriptRoot 'vuln-hunt-attest.js'
if(-not(Test-Path -LiteralPath $helper)){throw "Missing attestation helper: $helper"}
$before=(Resolve-Path -LiteralPath $BeforeFile).Path
$node=Get-TrustedApplication 'node'
$argsList=@($helper)
if($Range){$argsList+=@('--range',$Range)}
$argsList+=@('--compare',$before)
$json=& $node.Source @argsList
$code=$LASTEXITCODE
if($code -ne 0 -and $code -ne 2){throw "Attestation helper failed with exit code $code; postflight provenance was not compared."}
$result=ConvertFrom-CaseSensitiveJson ($json -join "`n")
[pscustomobject]@{ok=$result['ok'];mismatches=@($result['mismatches']);beforeRunId=$result['beforeRunId'];currentRunId=$result['currentRunId'];current=$result['current']}
if($code -ne 0 -or -not $result['ok']){throw "Postflight provenance changed: $(@($result['mismatches']) -join ', ')"}
Write-Host 'Postflight provenance matches the pre-run attestation.'
