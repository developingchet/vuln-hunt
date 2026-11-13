#!/usr/bin/env node
'use strict';
// Starts Claude Code with the vuln-hunt worker agents defined for this
// session only. Session definitions outrank project and user agents, so a
// scanned repository cannot replace a worker; project settings, hooks,
// CLAUDE.md and every MCP server are left out. The user-level /vuln-hunt
// workflow still loads, which --restricted would prevent.
const fs=require('fs'),os=require('os'),path=require('path'),{spawnSync}=require('child_process');
const argv=process.argv.slice(2),dryRun=argv[0]==='--dry-run',passThrough=dryRun?argv.slice(1):argv;
if(argv[0]==='--help'){console.log('Usage: node vuln-hunt-launch.js [--dry-run] [claude arguments...]\nRun from the repository root, then start the scan with /vuln-hunt.');process.exit(0)}
function inside(base,target){const r=path.relative(base,target);return r===''||(!r.startsWith(`..${path.sep}`)&&r!=='..'&&!path.isAbsolute(r))}
// Same boundary as vuln-hunt-attest.js: every ancestor holding a .git entry,
// plus the main checkout named by a linked worktree's .git file.
function repositoryBoundaries(start){
  const roots=[];
  for(let d=start;;){
    const g=path.join(d,'.git');let st=null;try{st=fs.lstatSync(g)}catch{}
    if(st){roots.push(d);if(st.isFile())try{const m=/^gitdir:\s*(.+?)\s*$/m.exec(fs.readFileSync(g,'utf8'));if(m){const gitdir=path.resolve(d,m[1]);let common=gitdir;try{common=path.resolve(gitdir,fs.readFileSync(path.join(gitdir,'commondir'),'utf8').trim())}catch{}if(path.basename(common)==='.git')roots.push(fs.realpathSync(path.dirname(common)))}}catch{}}
    const up=path.dirname(d);if(up===d)break;d=up;
  }
  return roots.length?roots:[start];
}
const untrustedRoots=repositoryBoundaries(fs.realpathSync(process.cwd()));
function resolveClaude(){
  const exts=process.platform==='win32'?['.exe','.com']:[''];
  for(let dir of String(process.env.PATH||'').split(path.delimiter)){
    dir=dir.trim().replace(/^"(.*)"$/,'$1');if(!dir||!path.isAbsolute(dir))continue;
    for(const ext of exts){try{const real=fs.realpathSync(path.join(dir,`claude${ext}`));if(fs.statSync(real).isFile()&&!untrustedRoots.some(r=>inside(r,real)))return real}catch{}}
  }
  throw new Error(`no claude executable found on PATH outside the enclosing repository roots (${untrustedRoots.join(', ')})${process.platform==='win32'?'; a claude.cmd shim cannot carry the inline agent definitions, so install the native claude.exe':''}`);
}
const agents=JSON.parse(fs.readFileSync(path.join(__dirname,'vuln-hunt-agents.json'),'utf8'));
// The empty MCP configuration lives in a private directory: a predictable
// shared-temp path would let another local user substitute MCP servers.
const claude=resolveClaude(),privateDir=fs.mkdtempSync(path.join(os.tmpdir(),'vuln-hunt-')),noMcp=path.join(privateDir,'no-mcp.json');
// Interactive sessions accept --agents only as inline JSON, not as a file path.
const args=['--agents',JSON.stringify(agents),'--setting-sources','user','--strict-mcp-config','--mcp-config',noMcp,...passThrough];
// A headless (-p) session stops waiting for background workflows after ten
// minutes and the scan is aborted; wait for it unless the caller set a limit.
const waitCeiling=process.env.CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS??'0',env={...process.env,CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS:waitCeiling};
let status=1;
try{
  if(dryRun){process.stdout.write(JSON.stringify({claude,args,env:{CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS:waitCeiling}}));status=0}
  else{fs.writeFileSync(noMcp,'{"mcpServers":{}}\n',{flag:'wx',mode:0o600});const r=spawnSync(claude,args,{stdio:'inherit',env});if(r.error)throw r.error;status=r.status??1}
}finally{fs.rmSync(privateDir,{recursive:true,force:true})}
process.exit(status);
