#!/usr/bin/env node
'use strict';
const {spawnSync}=require('child_process');
const fs=require('fs'),os=require('os'),path=require('path'),crypto=require('crypto');
const cwd=process.cwd(),argv=process.argv.slice(2);
// A runId names a directory under .vuln-hunt/runs. Windows drops trailing
// dots from a path segment, so "." and ".." (which would leave the namespace)
// and any name ending in a dot are refused, as are names Windows maps to a
// device whatever their extension.
const RUN_ID_RE=/^(?!.*\.$)(?!(?:con|prn|aux|nul|com\d|lpt\d)(?:\.|$))[A-Za-z0-9._-]{1,96}$/i;
let range=null,selfTest=false,comparePath=null,checkOutputIgnoreTracked=false,fingerprintRunId=null,policyDocArgs=[],emitRun=false,validateCitationsPath=null,validateReportRunDir=null,validateReportExpect=null,priorFindings=false,priorFindingsExclude=null,inputBase64=false;
for(let i=0;i<argv.length;i++){
  if(argv[i]==='--range'){if(i+1>=argv.length)throw new Error('--range requires a value');range=argv[++i]}
  else if(argv[i]==='--self-test'){selfTest=true}
  else if(argv[i]==='--compare'){if(i+1>=argv.length)throw new Error('--compare requires a JSON file');comparePath=argv[++i]}
  else if(argv[i]==='--fingerprint'){if(i+1>=argv.length||!RUN_ID_RE.test(argv[i+1]))throw new Error('--fingerprint requires the attested runId');fingerprintRunId=argv[++i]}
  else if(argv[i]==='--check-output-ignore-tracked'){checkOutputIgnoreTracked=true}
  else if(argv[i]==='--policy-doc'){if(i+1>=argv.length||!argv[i+1])throw new Error('--policy-doc requires a repository-relative path');policyDocArgs.push(argv[++i])}
  else if(argv[i]==='--emit-run'){emitRun=true}
  else if(argv[i]==='--validate-citations'){if(i+1>=argv.length)throw new Error('--validate-citations requires a JSON file of citations');validateCitationsPath=argv[++i]}
  else if(argv[i]==='--validate-report'){if(i+2>=argv.length)throw new Error('--validate-report requires a run directory name and an expect JSON file');validateReportRunDir=argv[++i];validateReportExpect=argv[++i]}
  else if(argv[i]==='--prior-findings'){priorFindings=true}
  else if(argv[i]==='--input-base64'){inputBase64=true}
  else if(argv[i]==='--exclude-run'){if(i+1>=argv.length||!RUN_ID_RE.test(argv[i+1]))throw new Error('--exclude-run requires a runId');priorFindingsExclude=argv[++i]}
  else if(argv[i]==='--help'){console.log('Usage: node vuln-hunt-attest.js [--self-test] [--range <ref|A..B|A...B>] [--policy-doc <path>]... [--emit-run] [--compare <before-attestation.json> | --fingerprint <runId>] [--check-output-ignore-tracked]\nStandalone mechanical modes (from the repository root): [--input-base64] [--validate-citations <citations.json>] [--validate-report <runId> <expect.json>] [--prior-findings [--exclude-run <runId>]]');process.exit(0)}
  else throw new Error(`Unknown argument: ${argv[i]}`);
}
if(comparePath&&fingerprintRunId)throw new Error('--compare and --fingerprint are mutually exclusive');
if(emitRun&&(comparePath||fingerprintRunId))throw new Error('--emit-run cannot be combined with --compare or --fingerprint');
const rangeRe=/^[A-Za-z0-9][A-Za-z0-9._~^/@:+{}-]*(?:\.{2,3}[A-Za-z0-9][A-Za-z0-9._~^/@:+{}-]*)?$/;
// Split once at the first separator. Refs cannot contain "..", so text left
// over after it is a malformed range, never a longer valid one.
function rangeParts(spec){const m=/^(.*?)(\.{2,3})(.*)$/s.exec(spec);if(!m)return null;const [,a,sep,b]=m;if(!a||!b||b.startsWith('.')||b.includes('..'))throw new Error(`malformed range: ${spec}; use REF, A..B or A...B`);return{a,b,symmetric:sep==='...'}}
if(range){if(!rangeRe.test(range))throw new Error('range contains unsupported characters');rangeParts(range)}
// realpathSync.native resolves letter case and 8.3 short names on Windows, so
// one directory reached through two spellings compares equal.
function real(p){try{return fs.realpathSync.native(p)}catch(e){if(e&&['ENOENT','ENOTDIR','ELOOP'].includes(e.code))throw e;return fs.realpathSync(p)}}
function inside(base,target){const r=path.relative(base,target);return r===''||(!r.startsWith(`..${path.sep}`)&&r!=='..'&&!path.isAbsolute(r))}
// Executables are resolved before Git can name the top level, so every
// ancestor holding a .git entry bounds repository-controlled content. A
// linked worktree nested in its main checkout (.claude/worktrees/x) has two
// such ancestors, and a .git file also names the main checkout through its
// gitdir/commondir even when that checkout is not an ancestor.
function linkedMainRoot(gitFile){
  try{
    const m=/^gitdir:\s*(.+?)\s*$/m.exec(fs.readFileSync(gitFile,'utf8'));if(!m)return null;
    const gitdir=path.resolve(path.dirname(gitFile),m[1]);let common=gitdir;
    try{common=path.resolve(gitdir,fs.readFileSync(path.join(gitdir,'commondir'),'utf8').trim())}catch(e){if(!e||e.code!=='ENOENT')throw e}
    return path.basename(common)==='.git'?real(path.dirname(common)):null;
  }catch{return null}
}
function repositoryBoundaries(start){
  const roots=[];
  for(let d=start;;){
    const g=path.join(d,'.git');let st=null;try{st=fs.lstatSync(g)}catch(e){if(!e||!['ENOENT','ENOTDIR'].includes(e.code))throw e}
    if(st){roots.push(d);if(st.isFile()){const main=linkedMainRoot(g);if(main)roots.push(main)}}
    const up=path.dirname(d);if(up===d)break;d=up;
  }
  return roots.length?[...new Set(roots)]:[start];
}
const untrustedRoots=repositoryBoundaries(real(cwd)),untrusted=p=>untrustedRoots.some(r=>inside(r,p));
function resolveGitExecutable(){
  const dirs=String(process.env.PATH||'').split(path.delimiter),exts=process.platform==='win32'?[...new Set(String(process.env.PATHEXT||'.EXE;.COM').split(';').filter(e=>/^\.(?:exe|com)$/i.test(e)))]:[''];
  for(let raw of dirs){raw=raw.trim();if(raw.length>=2&&raw[0]==='\"'&&raw.at(-1)==='\"')raw=raw.slice(1,-1);if(!raw||!path.isAbsolute(raw))continue;let dir;try{dir=real(raw)}catch{continue}if(untrusted(dir))continue;
    for(const ext of exts){const candidate=path.join(dir,`git${ext}`);try{const exe=real(candidate),st=fs.statSync(exe);if(untrusted(exe)||!st.isFile())continue;if(process.platform!=='win32')fs.accessSync(exe,fs.constants.X_OK);return exe}catch{}}
  }
  throw new Error(`could not resolve a trusted Git executable from PATH outside the enclosing repository roots (${untrustedRoots.join(', ')}). If one of them is a home-directory repository, run from a checkout outside it or install Git elsewhere`);
}
const gitExecutable=resolveGitExecutable();
// The workflow's freshness check re-executes this helper with this Node, so
// neither may live in repository-controlled content.
const helperPath=real(__filename),nodePath=real(process.execPath);
if(untrusted(helperPath)||untrusted(nodePath))throw new Error('run the installed attestation helper with a Node runtime outside the target repository');
const env={...process.env};for(const k of Object.keys(env))if(['GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES','GIT_COMMON_DIR','GIT_NAMESPACE','GIT_CEILING_DIRECTORIES','GIT_DISCOVERY_ACROSS_FILESYSTEM','GIT_CONFIG','GIT_CONFIG_GLOBAL','GIT_CONFIG_SYSTEM','GIT_CONFIG_NOSYSTEM','GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS','GIT_QUARANTINE_PATH','GIT_SHALLOW_FILE','GIT_EXEC_PATH','GIT_EXTERNAL_DIFF','GIT_DIFF_OPTS','GIT_ATTR_NOSYSTEM','GIT_ATTR_SOURCE'].includes(k)||/^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(k)||/^GIT_TRACE(?:_|$)/.test(k))delete env[k];Object.assign(env,{GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0',GIT_PAGER:'cat',PAGER:'cat',GIT_NO_LAZY_FETCH:'1',GIT_NO_REPLACE_OBJECTS:'1',NoDefaultCurrentDirectoryInExePath:'1'});
function git(args,{input=null,allow=[0]}={}){
  const r=spawnSync(gitExecutable,['--no-replace-objects','--no-optional-locks','-c','core.fsmonitor=false','-c','core.pager=cat',...args],{cwd,env,input,encoding:null,maxBuffer:1024*1024*256});
  if(!allow.includes(r.status)){const err=(r.stderr||Buffer.alloc(0)).toString('utf8').trim();throw new Error(`git ${args[0]} failed (${r.status}): ${err.slice(0,500)}`)}
  return r;
}
const text=(r)=>r.stdout.toString('utf8').trim();
// Escape non-ASCII so a console that decodes native output with an OEM or ANSI
// code page cannot garble pathnames in the JSON.
const emit=o=>process.stdout.write(JSON.stringify(o).replace(/[\u007f-￿]/g,c=>`\\u${c.charCodeAt(0).toString(16).padStart(4,'0')}`));
if(selfTest){
  const checks={nodeApis:typeof TextDecoder==='function'&&typeof crypto.randomUUID==='function'&&typeof fs.lstatSync==='function'};
  if(!checks.nodeApis)throw new Error('Node runtime lacks required standard-library APIs');
  const gv=git(['--version']);checks.gitVersion=text(gv);checks.gitExecutable=gitExecutable;
  checks.repoRoot=Boolean(text(git(['rev-parse','--show-toplevel'])));
  checks.hashObject=oidLike(text(git(['hash-object','--no-filters','--stdin'],{input:Buffer.alloc(0)})));
  git(['check-attr','-z','--stdin','filter'],{input:Buffer.alloc(0)});checks.checkAttrZ=true;
  git(['ls-files','--cached','-z']);checks.lsFilesZ=true;
  emit({ok:Object.values(checks).every(Boolean),checks});process.exit(0);
}
function oidLike(s){return /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i.test(s)}
const topRaw=text(git(['rev-parse','--show-toplevel'])),topReal=fs.realpathSync(topRaw);if(real(cwd)!==real(topRaw))throw new Error(`run attestation from repository root: ${topReal}`);if(/[\0\r\n\t]/.test(topReal)||(path.sep==='/'&&topReal.includes('\\')))throw new Error('repository root contains an unsupported control/backslash character');const repoRoot=topReal.replace(/\\/g,'/');
if(checkOutputIgnoreTracked){const r=git(['ls-files','--error-unmatch','--','.vuln-hunt/.gitignore'],{allow:[0,1]});emit({tracked:r.status===0,repoRoot});process.exit(0)}
const commandShadows=[path.join(cwd,'.claude','workflows','vuln-hunt.js'),path.join(cwd,'.claude','commands','vuln-hunt.md'),path.join(cwd,'.claude','skills','vuln-hunt')];
for(const p of commandShadows)try{fs.lstatSync(p);throw new Error(`project-local /vuln-hunt command shadow detected: ${path.relative(cwd,p).replace(/\\/g,'/')}. Remove/rename it so the installed personal workflow is the command that runs`)}catch(e){if(e&&e.code!=='ENOENT')throw e}
// A project agent named like a worker outranks the installed user-level
// worker, which would let the repository choose that worker's tools and
// instructions. Keep this list identical to vuln-hunt-agents.json.
const WORKER_AGENTS=['vuln-hunt-researcher','vuln-hunt-mechanic','vuln-hunt-reporter'];
// YAML lets a name hide behind a BOM, quoted keys, trailing comments, block
// scalars, escapes and aliases, and Claude Code ends frontmatter at the first
// later `---` wherever it falls on a line, so neither an exact parse nor a
// strict delimiter can be trusted. Any agent file that opens with `---` is
// refused when its whole text mentions a worker name once double-quoted
// escapes and escaped line breaks are decoded, and a file named after a worker
// is refused whatever it contains.
function namesWorker(file,text){
  if(WORKER_AGENTS.includes(path.basename(file).replace(/\.md$/i,'').toLowerCase()))return true;
  if(!/^\uFEFF?\s*---/.test(text))return false;
  const decoded=text.replace(/\\(?:\r\n?|\n)[ \t]*/g,'').replace(/\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))/g,(m,x,u,U)=>{const c=parseInt(x||u||U,16);return c<=0x10ffff?String.fromCodePoint(c):m}).toLowerCase();
  return WORKER_AGENTS.some(n=>decoded.includes(n));
}
function agentShadows(){
  const key=p=>process.platform==='win32'?path.resolve(p).toLowerCase():path.resolve(p),userAgentsPath=path.join(require('os').homedir(),'.claude','agents'),userAgents=key(userAgentsPath),found=[],seen=new Set();
  let userAgentsReal=userAgents;try{userAgentsReal=key(real(userAgentsPath))}catch(e){if(!e||!['ENOENT','ENOTDIR'].includes(e.code))throw e}
  // Directory links and junctions are followed, since Claude Code loads agents
  // through them; each real directory is walked once, which also ends cycles.
  const walk=dir=>{let entries,where;try{where=key(real(dir));entries=fs.readdirSync(dir,{withFileTypes:true})}catch(e){if(e&&['ENOENT','ENOTDIR','ELOOP'].includes(e.code))return;throw e}
    if(seen.has(where)||where===userAgentsReal)return;seen.add(where);
    for(const e of entries){const p=path.join(dir,e.name);let st=e;if(e.isSymbolicLink())try{st=fs.statSync(p)}catch(err){if(err&&['ENOENT','ENOTDIR','ELOOP'].includes(err.code))continue;throw err}
      if(st.isDirectory())walk(p);else if(st.isFile()&&/\.md$/i.test(e.name)&&namesWorker(p,fs.readFileSync(p,'utf8')))found.push(p)}};
  for(let d=cwd;;){const a=path.join(d,'.claude','agents');if(key(a)!==userAgents)walk(a);const up=path.dirname(d);if(up===d)break;d=up}
  return found;
}
const shadows=agentShadows();if(shadows.length)throw new Error(`project agent shadows a vuln-hunt worker: ${shadows.join(', ')}. Remove or rename it before scanning`);
const dec=new TextDecoder('utf-8',{fatal:true});
const outputIgnorePath=path.join(cwd,'.vuln-hunt','.gitignore');try{const st=fs.lstatSync(outputIgnorePath);if(st.isFile()){const raw=fs.readFileSync(outputIgnorePath,'utf8');if(raw==='runs/'||raw==='runs/\n'||raw==='runs/\r\n')throw new Error('.vuln-hunt/.gitignore contains runs/ and would let tool output into the manifest; replace its contents with *')}}catch(e){if(e&&e.code!=='ENOENT')throw e}
function zlist(b){const out=[];let start=0;for(let i=0;i<b.length;i++)if(b[i]===0){try{out.push(dec.decode(b.subarray(start,i)))}catch{throw new Error('repository contains a non-UTF-8 pathname; unsupported for safe workflow citation')}start=i+1}if(start!==b.length)throw new Error('expected NUL-terminated Git output');return out}
const hash=b=>text(git(['hash-object','--no-filters','--stdin'],{input:b}));
// Untracked OS, editor and Claude Code metadata never enters the manifest.
// --exclude patterns apply only to untracked files, so tracked copies (for
// example a committed .vscode/tasks.json) stay in coverage. Keep this list
// identical to LOCAL_METADATA_EXCLUDES in vuln-hunt.js.
const LOCAL_METADATA_EXCLUDES=[".DS_Store","Thumbs.db","ehthumbs.db","desktop.ini","/.idea/","/.vscode/","/.claude/settings.local.json"];
const untrackedFilter=['--exclude-per-directory=.gitignore',...LOCAL_METADATA_EXCLUDES.map(p=>`--exclude=${p}`)];
const oid=s=>/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i.test(s);
// ls-files --others lists an untracked nested repository as one "dir/" entry
// and never its files, so the entry is unsupported rather than scanned.
const safeRel=p=>p.length>0&&!p.endsWith('/')&&!p.includes('\\')&&!/[\0\r\n\t]/.test(p)&&!path.isAbsolute(p)&&!p.split('/').includes('..');
function rev(ref){const s=text(git(['rev-parse','--verify',`${ref}^{commit}`]));if(!oid(s))throw new Error(`could not resolve commit: ${ref}`);return s}
// --- Standalone mechanical modes --------------------------------------------
// The workflow dispatches these through the mechanic worker so citation,
// report and prior-run checks are computed by this trusted helper rather
// than judged by a model. Each reads the repository only; none writes it.
// The helper echoes a hash of the input it received, which the workflow
// recomputes, and adds a resultHash over the rest of its own output, which
// the workflow recomputes over what came back: together they catch a list or
// result the transport dropped, reordered or garbled in either direction.
// Neither is a signature, so a mechanic that rewrote this helper's output on
// purpose would not be detected by them. Outputs name inputs by index and
// carry no repository file names, so the mechanic never reads file-name text
// back either.
// With --input-base64 the input file holds base64 of the UTF-8 JSON. The
// workflow sends input that way so the command a mechanic copies carries no
// quote, shell metacharacter or prose taken from repository file names.
function readJsonArg(p,what){
  let raw=fs.readFileSync(path.resolve(p),'utf8').replace(/^﻿/,'');
  if(inputBase64){
    const b=raw.replace(/\s+/g,'');
    if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b))throw new Error(`${what} is not valid base64: ${p}`);
    try{raw=dec.decode(Buffer.from(b,'base64'))}catch{throw new Error(`${what} is not UTF-8 once base64-decoded: ${p}`)}
  }
  try{return JSON.parse(raw)}catch{throw new Error(`${what} is not valid JSON: ${p}`)}
}
// Repository-controlled files are read through one descriptor after lstat has
// checked every parent directory and the file itself, on every platform: a
// symlink or junction anywhere on the path is refused (Node reports other
// Windows reparse points, such as cloud-file placeholders, as ordinary files),
// and the descriptor must be the file lstat saw (same device and inode), so a
// swap of the final component between the check and the open is detected.
// O_NOFOLLOW and O_NONBLOCK add the same refusal on POSIX and keep a FIFO
// swapped in from blocking the read. A concurrent writer that replaces a
// parent directory after its check is beyond what Node's path-based API can
// stop; the workflow's closing freshness check reports source that changed
// during the run.
const notRegularError=m=>Object.assign(new Error(m),{code:'VH_NOT_REGULAR'});
function openRepoFile(rel){
  const parts=rel.split('/');let dir=cwd;
  for(const seg of parts.slice(0,-1)){dir=path.join(dir,seg);const s=fs.lstatSync(dir);if(s.isSymbolicLink()||!s.isDirectory())throw notRegularError('path crosses a symlink, junction or non-directory')}
  const abs=path.join(cwd,...parts),pre=fs.lstatSync(abs,{bigint:true});
  if(pre.isSymbolicLink()||!pre.isFile())throw notRegularError('not a regular file (symlink, submodule or directory)');
  const fd=fs.openSync(abs,process.platform==='win32'?'r':(fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK));
  try{const st=fs.fstatSync(fd,{bigint:true});if(!st.isFile()||st.ino!==pre.ino||st.dev!==pre.dev)throw notRegularError('file was replaced while it was being opened');return fd}
  catch(e){fs.closeSync(fd);throw e}
}
const emitWithHash=o=>emit({...o,resultHash:crypto.createHash('sha256').update(JSON.stringify(o)).digest('hex')});
// Reads at most cap bytes from an open descriptor; returns null when the file
// is larger, so no caller reads an unbounded file.
function readBounded(fd,cap){const size=Number(fs.fstatSync(fd).size);if(size>cap)return null;const buf=Buffer.alloc(size);let off=0;while(off<size){const k=fs.readSync(fd,buf,off,size-off,off);if(!k)break;off+=k}return buf.subarray(0,off)}
const loneSurrogate=/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const openFailure=e=>e&&e.code==='VH_NOT_REGULAR'?e.message:e&&['ELOOP','EISDIR'].includes(e.code)?'not a regular file (symlink, submodule or directory)':e&&['ENOENT','ENOTDIR'].includes(e.code)?'missing from the working tree':null;
const MAX_LINE=10000000,SEVERITIES=['critical','high','medium','low'],EVIDENCE_LEVELS=['STATICALLY_VERIFIED','EXECUTION_REPRODUCED'],RELATIONS=['REPRODUCED_AGAIN','TENTATIVE_MATCH','NEW','UNKNOWN'];
const canonCitations=cs=>JSON.stringify((Array.isArray(cs)?cs:[]).map(c=>c&&typeof c==='object'?[String(c.file),Number(c.line),c.endLine==null?null:Number(c.endLine)]:null));
if(validateCitationsPath){
  const input=readJsonArg(validateCitationsPath,'--validate-citations input');
  if(!Array.isArray(input)||input.length>4096||!input.every(c=>c&&typeof c==='object'&&typeof c.file==='string'&&c.file.length<=1024&&Number.isInteger(c.line)&&c.line>=1&&c.line<=MAX_LINE&&(c.endLine==null||(Number.isInteger(c.endLine)&&c.endLine>=c.line&&c.endLine<=MAX_LINE))))throw new Error('citation input must be an array of at most 4096 {file,line,endLine?} objects (file at most 1024 characters, line>=1, endLine>=line, both at most 10000000)');
  const manifest=zlist(git(['ls-files','--cached','--others',...untrackedFilter,'-z']).stdout),manifestSet=new Set(manifest);
  // A case-insensitive checkout resolves a citation in any letter case to its
  // manifest spelling, as the workflow's own path checks do. Two manifest
  // paths that differ only in case make the resolution ambiguous.
  const ignoreCase=boolConfig('core.ignoreCase'),folded=new Map();
  if(ignoreCase)for(const p of manifest){const k=p.toLowerCase();folded.set(k,folded.has(k)&&folded.get(k)!==p?null:p)}
  const special=stageSpecial(),linkSet=new Set([...special.trackedSymlinks,...special.submodules]);
  const invalid=[],fileLines=new Map();
  const bad=(index,c,reason)=>({index,reason});
  const countLines=fd=>{const buf=Buffer.alloc(1<<20);let n=0,bytes=0,last=-1;for(let r;(r=fs.readSync(fd,buf,0,buf.length,null))>0;){bytes+=r;last=buf[r-1];for(let i=0;i<r;i++)if(buf[i]===10)n++}return bytes===0?0:last===10?n:n+1};
  input.forEach((c,index)=>{
    if(!safeRel(c.file)){invalid.push(bad(index,c,'path is absolute, backslashed, or contains .. or a control character'));return}
    let target=manifestSet.has(c.file)?c.file:undefined;
    if(target===undefined&&ignoreCase){const hit=folded.get(c.file.toLowerCase());if(hit===null){invalid.push(bad(index,c,'ambiguous letter case: several manifest paths match'));return}target=hit}
    if(target===undefined){invalid.push(bad(index,c,'not in the live manifest'));return}
    if(linkSet.has(target)){invalid.push(bad(index,c,'not a regular file (symlink, submodule or directory)'));return}
    if(!fileLines.has(target)){
      let lines=null,reason=null,fd=null;
      try{fd=openRepoFile(target);lines=countLines(fd)}catch(e){reason=openFailure(e)||'unreadable'}finally{if(fd!==null)fs.closeSync(fd)}
      fileLines.set(target,{lines,reason});
    }
    const {lines,reason}=fileLines.get(target);
    if(lines===null){invalid.push(bad(index,c,reason));return}
    if(lines===0||c.line>lines||(c.endLine!=null&&c.endLine>lines))invalid.push(bad(index,c,`line beyond the file's ${lines} line(s)`));
  });
  emitWithHash({version:3,inputHash:crypto.createHash('sha256').update(canonCitations(input)).digest('hex'),total:input.length,invalidCount:invalid.length,invalid,lineChecks:[...fileLines.values()].filter(x=>x.lines!==null).length});process.exit(0);
}
// The expectation names every verified finding with the findingId, relation
// and evidence level the run assigned it, and every unit with its coverage
// status, so a report that restates any of them differently fails.
const canonExpect=e=>JSON.stringify({runId:String(e.runId||''),findings:(Array.isArray(e.findings)?e.findings:[]).map(f=>[String(f.candidateId),String(f.findingId),String(f.relation),String(f.evidence)]).sort(),coverage:(Array.isArray(e.coverage)?e.coverage:[]).map(u=>[String(u.unitId),String(u.status)]).sort()});
// An output namespace directory reached through a link would read run
// artifacts from outside the repository.
function outputDirExists(rel){try{const s=fs.lstatSync(path.join(cwd,...rel.split('/')));if(s.isSymbolicLink()||!s.isDirectory())throw new Error(`${rel} is a symlink, junction or non-directory; refusing to read run artifacts through it`);return true}catch(e){if(e&&['ENOENT','ENOTDIR'].includes(e.code))return false;throw e}}
if(validateReportRunDir!==null){
  const expect=readJsonArg(validateReportExpect,'--validate-report expect');
  const goodExpect=expect&&typeof expect==='object'&&RUN_ID_RE.test(String(expect.runId||''))
    &&Array.isArray(expect.findings)&&expect.findings.length<=1024&&expect.findings.every(f=>f&&typeof f.candidateId==='string'&&/^[0-9a-f]{64}$/.test(String(f.findingId))&&RELATIONS.includes(f.relation)&&EVIDENCE_LEVELS.includes(f.evidence))&&new Set(expect.findings.map(f=>f.candidateId)).size===expect.findings.length
    &&Array.isArray(expect.coverage)&&expect.coverage.length<=64&&expect.coverage.every(u=>u&&typeof u.unitId==='string'&&typeof u.status==='string')&&new Set(expect.coverage.map(u=>u.unitId)).size===expect.coverage.length;
  if(!goodExpect)throw new Error('expect input needs a runId, a findings array of unique {candidateId,findingId,relation,evidence} and a coverage array of unique {unitId,status}');
  if(validateReportRunDir!==expect.runId)throw new Error('--validate-report run directory must equal the expect runId');
  if(!outputDirExists('.vuln-hunt')||!outputDirExists('.vuln-hunt/runs')||!outputDirExists(`.vuln-hunt/runs/${expect.runId}`))throw new Error('run directory does not exist');
  const errors=[],REPORT_FILE_CAP=16*1024*1024;
  const readRunFile=f=>{let fd=null;try{fd=openRepoFile(`.vuln-hunt/runs/${expect.runId}/${f}`);const buf=readBounded(fd,REPORT_FILE_CAP);if(buf===null){errors.push(`${f}: larger than 16 MiB`);return null}return{text:buf.toString('utf8'),size:buf.length}}catch(e){const why=openFailure(e);if(!why)throw e;errors.push(`${f}: ${why==='missing from the working tree'?'missing':why}`);return null}finally{if(fd!==null)fs.closeSync(fd)}};
  const report=readRunFile('vuln-hunt-report.md'),findingsFile=readRunFile('findings.jsonl'),coverageFile=readRunFile('coverage.jsonl');
  if(report&&report.size<200)errors.push('vuln-hunt-report.md is under 200 bytes');
  const readJsonl=(f,r)=>{if(!r)return[];const out=[];for(const line of r.text.split(/\r?\n/)){if(!line.trim())continue;let o;try{o=JSON.parse(line)}catch{errors.push(`${f}: a line is not JSON`);continue}if(!o||typeof o!=='object'||Array.isArray(o)){errors.push(`${f}: a line is not a JSON object`);continue}out.push(o)}return out};
  const findings=readJsonl('findings.jsonl',findingsFile),coverage=readJsonl('coverage.jsonl',coverageFile);
  const show=v=>JSON.stringify(String(v).slice(0,64)).replace(/[^\x20-\x7e]/g,'?');
  const want=new Map(expect.findings.map(f=>[f.candidateId,f])),seen=new Set();
  for(const f of findings){
    const id=typeof f.candidateId==='string'?f.candidateId:'',w=want.get(id);
    if(!w){errors.push(`findings.jsonl: candidate ${id?show(id):'(missing)'} is not in the verified set`);continue}
    if(seen.has(id))errors.push(`findings.jsonl: duplicate candidate ${id}`);
    seen.add(id);
    if(!SEVERITIES.includes(f.severity))errors.push(`findings.jsonl: candidate ${id} has invalid severity`);
    if(f.findingId!==w.findingId)errors.push(`findings.jsonl: candidate ${id} does not carry this run's findingId, which the next run's reconciliation needs`);
    if(f.relation!==w.relation)errors.push(`findings.jsonl: candidate ${id} has relation ${show(f.relation)}, expected ${w.relation}`);
    if(f.evidence!==w.evidence)errors.push(`findings.jsonl: candidate ${id} has evidence ${show(f.evidence)}, expected ${w.evidence}`);
    if(typeof f.file!=='string'||!f.file||!Number.isInteger(f.line)||f.line<1||typeof f.symbol!=='string')errors.push(`findings.jsonl: candidate ${id} lacks the file, line and symbol the next run's reconciliation needs`);
  }
  for(const id of want.keys())if(!seen.has(id))errors.push(`findings.jsonl: verified candidate ${id} is missing`);
  const wantUnits=new Map(expect.coverage.map(u=>[u.unitId,u.status])),unitSeen=new Map();
  for(const c of coverage){
    const id=typeof c.unitId==='string'?c.unitId:'';
    if(!wantUnits.has(id)){errors.push(`coverage.jsonl: unit ${id?show(id):'(missing)'} is not attested`);continue}
    unitSeen.set(id,(unitSeen.get(id)||0)+1);
    if(c.status!==wantUnits.get(id))errors.push(`coverage.jsonl: unit ${id} has status ${show(c.status)}, expected ${wantUnits.get(id)}`);
  }
  for(const id of wantUnits.keys())if(!unitSeen.has(id))errors.push(`coverage.jsonl: unit ${id} is missing`);else if(unitSeen.get(id)>1)errors.push(`coverage.jsonl: unit ${id} appears more than once`);
  emitWithHash({version:3,ok:errors.length===0,errors:errors.slice(0,64),errorCount:errors.length,counts:{findings:findings.length,coverage:coverage.length},expectHash:crypto.createHash('sha256').update(canonExpect(expect)).digest('hex')});process.exit(0);
}
// Prior findings come from earlier run directories under the repository's
// own output namespace, so every field is bounded and typed here and the
// output stays small enough for a mechanic to return verbatim: the most
// recent runs first, a fixed number of runs and findings per run, and a
// truncated flag when anything was left out.
if(priorFindings){
  const PRIOR_RUN_CAP=16,PER_RUN_CAP=64,PRIOR_FILE_CAP=4*1024*1024;
  let truncated=false;const runs=[];
  if(outputDirExists('.vuln-hunt')&&outputDirExists('.vuln-hunt/runs')){
    const runsRoot=path.join(cwd,'.vuln-hunt','runs');
    for(const e of fs.readdirSync(runsRoot,{withFileTypes:true})){
      if(!RUN_ID_RE.test(e.name)||e.name===priorFindingsExclude)continue;
      let st;try{st=fs.lstatSync(path.join(runsRoot,e.name))}catch{continue}
      if(!st.isSymbolicLink()&&st.isDirectory())runs.push({name:e.name,mtime:st.mtimeMs});
    }
  }
  runs.sort((a,b)=>b.mtime-a.mtime||(a.name<b.name?-1:a.name>b.name?1:0));
  if(runs.length>PRIOR_RUN_CAP)truncated=true;
  const bounded=(v,n)=>typeof v==='string'&&v.length>0&&v.length<=n&&!/[\0-\x1f\x7f]/.test(v)&&!loneSurrogate.test(v)?v:null;
  const prior=[];
  for(const r of runs.slice(0,PRIOR_RUN_CAP)){
    let raw=null,fd=null;
    try{
      fd=openRepoFile(`.vuln-hunt/runs/${r.name}/findings.jsonl`);
      const size=Number(fs.fstatSync(fd).size),n=Math.min(size,PRIOR_FILE_CAP),buf=Buffer.alloc(n);let off=0;
      while(off<n){const k=fs.readSync(fd,buf,off,n-off,off);if(!k)break;off+=k}
      raw=buf.subarray(0,off).toString('utf8');
      if(size>PRIOR_FILE_CAP){truncated=true;raw=raw.slice(0,raw.lastIndexOf('\n')+1)}
    }catch{raw=null}finally{if(fd!==null)fs.closeSync(fd)}
    if(raw===null)continue;
    const findings=[];
    for(const line of raw.split(/\r?\n/)){
      if(!line.trim())continue;
      if(findings.length>=PER_RUN_CAP){truncated=true;break}
      let o;try{o=JSON.parse(line)}catch{continue}
      if(!o||typeof o!=='object'||Array.isArray(o))continue;
      findings.push({candidateId:typeof o.candidateId==='string'&&/^[A-Za-z0-9._-]{1,32}$/.test(o.candidateId)?o.candidateId:null,findingId:typeof o.findingId==='string'&&/^[0-9a-f]{64}$/.test(o.findingId)?o.findingId:null,file:typeof o.file==='string'&&o.file.length<=1024&&safeRel(o.file)&&!loneSurrogate.test(o.file)?o.file:null,line:Number.isInteger(o.line)&&o.line>=1&&o.line<=MAX_LINE?o.line:null,symbol:bounded(o.symbol,256),severity:SEVERITIES.includes(o.severity)?o.severity:null,evidence:EVIDENCE_LEVELS.includes(o.evidence)?o.evidence:null,rootKey:bounded(o.rootKey,512)});
    }
    prior.push({runId:r.name,findings});
  }
  emitWithHash({version:3,priorRuns:prior,truncated});process.exit(0);
}
function mergeBase(a,b){const s=text(git(['merge-base',a,b]));if(!oid(s))throw new Error(`could not resolve merge-base for ${a} and ${b}`);return s}
function emptyTree(){const s=text(git(['hash-object','-t','tree','--stdin'],{input:Buffer.alloc(0)}));if(!oid(s))throw new Error('could not hash empty tree');return s}
// Research workers have no shell, so range mode carries the change itself:
// per-file status, modes and hunk coordinates, plus removed lines, which the
// checked-out head cannot show. Added lines are read from the head checkout.
const RANGE_FILE_CAP=256,REMOVED_FILE_CAP=16384,REMOVED_TOTAL_CAP=262144;
function rangeFiles(base,head){
  const raw=zlist(git(['diff','--raw','-z','-M','--no-abbrev','--no-color','--no-ext-diff','--no-textconv',base,head,'--']).stdout),entries=[];
  for(let i=0;i<raw.length;){const m=/^:(\d{6}) (\d{6}) [0-9a-f]+ [0-9a-f]+ ([A-Z])\d*$/.exec(raw[i]);if(!m)throw new Error('unexpected git diff --raw output');const two=m[3]==='R'||m[3]==='C';entries.push({status:m[3],oldMode:m[1],newMode:m[2],oldPath:two?raw[i+1]:null,path:two?raw[i+2]:raw[i+1]});i+=two?3:2}
  let budget=REMOVED_TOTAL_CAP,evidenceTruncated=false;
  const files=entries.slice(0,RANGE_FILE_CAP).map(e=>{
    const f={...e,binary:false,submodule:e.oldMode==='160000'||e.newMode==='160000',hunks:[],removedTruncated:false};
    if(f.submodule)return f;
    const r=git(['--literal-pathspecs','diff','-U0','-M','--no-color','--no-ext-diff','--no-textconv',base,head,'--',...(e.oldPath?[e.oldPath]:[]),e.path]).stdout.toString('utf8');
    let hunk=null,used=0;
    for(const line of r.split('\n')){
      // A type change prints two diffs for one path; the second one's ---
      // header is not a removed line of the first one's last hunk.
      if(line.startsWith('diff --git ')){hunk=null;continue}
      const h=/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
      if(h){hunk={oldStart:+h[1],oldLines:h[2]===undefined?1:+h[2],newStart:+h[3],newLines:h[4]===undefined?1:+h[4],removed:''};f.hunks.push(hunk);continue}
      if(!hunk){if(/^Binary files /.test(line))f.binary=true;continue}
      if(line.startsWith('-')){const add=line.slice(1)+'\n';if(used+add.length>REMOVED_FILE_CAP||add.length>budget){f.removedTruncated=true;continue}hunk.removed+=add;used+=add.length;budget-=add.length}
    }
    if(f.removedTruncated)evidenceTruncated=true;
    return f;
  });
  return{rangeFiles:files,rangeFilesTruncated:entries.length>files.length,rangeEvidenceTruncated:evidenceTruncated};
}
function rangeInfo(spec){
  if(!spec)return{range:null,rangeBase:'',rangeHead:'',changedRaw:Buffer.alloc(0),rangeFiles:[],rangeFilesTruncated:false,rangeEvidenceTruncated:false};
  let base,head;const parts=rangeParts(spec);
  if(parts?.symmetric){const ra=rev(parts.a),rb=rev(parts.b);base=mergeBase(ra,rb);head=rb}
  else if(parts){base=rev(parts.a);head=rev(parts.b)}
  else {head=rev(spec);const p=git(['rev-parse','--verify',`${spec}^1^{commit}`],{allow:[0,128]});base=p.status===0?text(p):emptyTree()}
  // --no-renames lists both sides of a rename whatever diff.renames says.
  const changedRaw=git(['diff','--name-only','-z','--no-renames','--no-ext-diff','--no-textconv',base,head,'--']).stdout;
  return{range:spec,rangeBase:base,rangeHead:head,changedRaw,...rangeFiles(base,head)};
}
function stageSpecial(){
  const entries=zlist(git(['ls-files','-s','-z']).stdout),trackedSymlinks=[],submodules=[];
  for(const e of entries){const tab=e.indexOf('\t');if(tab<0)continue;const meta=e.slice(0,tab),p=e.slice(tab+1),mode=meta.split(' ')[0];if(mode==='120000')trackedSymlinks.push(p);else if(mode==='160000')submodules.push(p)}
  return{trackedSymlinks,submodules};
}
function filterInfo(trackedRaw){
  if(!trackedRaw.length)return{customFiltersCount:0,customFiltersHash:hash(Buffer.alloc(0)),customFilterDrivers:[]};
  const parts=zlist(git(['check-attr','-z','--stdin','filter'],{input:trackedRaw}).stdout);if(parts.length%3)throw new Error('unexpected git check-attr output');
  const active=[];for(let i=0;i<parts.length;i+=3){const [p,a,v]=parts.slice(i,i+3);if(a!=='filter')throw new Error('unexpected git check-attr attribute');if(v!=='unspecified'&&v!=='unset')active.push([p,v])}
  const raw=Buffer.concat(active.map(([p,v])=>Buffer.from(`${p}\0filter\0${v}\0`,'utf8')));
  return{customFiltersCount:active.length,customFiltersHash:hash(raw),customFilterDrivers:[...new Set(active.map(x=>x[1]))].sort()};
}
function boolConfig(key){const r=git(['config','--bool',key],{allow:[0,1]});return r.status===0&&text(r)==='true'}
function isPartialClone(){
  const ext=git(['config','--get','extensions.partialClone'],{allow:[0,1]}),rem=git(['config','--get-regexp','^remote\..*\.(promisor|partialclonefilter)$'],{allow:[0,1]});
  if(ext.status===0&&text(ext))return true;
  if(rem.status!==0)return false;
  return rem.stdout.toString('utf8').split(/\r?\n/).some(line=>{const m=/^(\S+)\s+(.*)$/.exec(line);if(!m)return false;const k=m[1].toLowerCase(),v=m[2].trim().toLowerCase();return k.endsWith('.partialclonefilter')||(k.endsWith('.promisor')&&['true','yes','on','1'].includes(v))});
}
function hasGrafts(){const gp=text(git(['rev-parse','--git-path','info/grafts'])),p=path.isAbsolute(gp)?gp:path.resolve(cwd,gp);try{fs.lstatSync(p);return true}catch(e){if(e&&e.code==='ENOENT')return false;throw e}}
function hasAlternates(){const ap=text(git(['rev-parse','--git-path','objects/info/alternates'])),p=path.isAbsolute(ap)?ap:path.resolve(cwd,ap);try{const st=fs.lstatSync(p);if(st.isSymbolicLink()||!st.isFile())return true;return fs.readFileSync(p,'utf8').split(/\r?\n/).some(x=>x.trim().length>0)}catch(e){if(e&&e.code==='ENOENT')return false;throw e}}
function isOutputSafe(runId,tracked,ignoreCase){
  const fold=p=>ignoreCase?p.toLowerCase():p;
  if([...tracked].some(p=>fold(p)==='.vuln-hunt'||fold(p).startsWith('.vuln-hunt/')))return false;
  for(const rel of ['.vuln-hunt','.vuln-hunt/runs']){
    const p=path.join(cwd,...rel.split('/'));let s;try{s=fs.lstatSync(p)}catch(e){if(e&&e.code==='ENOENT')continue;throw e}if(s.isSymbolicLink()||!s.isDirectory())return false;
  }
  const gi=path.join(cwd,'.vuln-hunt','.gitignore');try{const s=fs.lstatSync(gi);if(s.isSymbolicLink()||!s.isFile())return false}catch(e){if(!e||e.code!=='ENOENT')throw e}
  const run=path.join(cwd,'.vuln-hunt','runs',runId);try{fs.lstatSync(run);return false}catch(e){if(!e||e.code!=='ENOENT')throw e}
  return true;
}

const UNIT_TARGET=25,UNIT_CAP=24,FLAT_SPLIT_FACTOR=2,cmp=(a,b)=>Buffer.compare(Buffer.from(a,'utf8'),Buffer.from(b,'utf8'));
function mechanicalUnits(manifest){
  if(!manifest.length)return{mechanicalUnitTarget:UNIT_TARGET,mechanicalUnitCap:UNIT_CAP,units:[],unitsHash:hash(Buffer.alloc(0))};
  const root={prefix:"",files:[],direct:[],children:new Map()};
  for(const file of manifest){
    const parts=file.split('/');let node=root;node.files.push(file);
    for(let i=0;i<parts.length-1;i++){const prefix=parts.slice(0,i+1).join('/');if(!node.children.has(parts[i]))node.children.set(parts[i],{prefix,files:[],direct:[],children:new Map()});node=node.children.get(parts[i]);node.files.push(file)}
    node.direct.push(file);
  }
  const atomFile=f=>({path:f,files:[f],node:null}),atomNode=n=>({path:n.prefix,files:n.files,node:n});
  let atoms=[...root.direct.map(atomFile),...[...root.children.values()].map(atomNode)].sort((a,b)=>cmp(a.path,b.path));
  const desired=Math.min(UNIT_CAP,Math.max(1,Math.ceil(manifest.length/UNIT_TARGET))),target=Math.ceil(manifest.length/desired);
  // Single-child directory chains are descended so src/main/java/... can split
  // below the chain. A flat directory keeps its files together unless it is
  // grossly oversized.
  function splitAtom(a){
    if(!a.node)return null;
    let n=a.node;while(!n.direct.length&&n.children.size===1)n=n.children.values().next().value;
    if(n.children.size===0&&n.direct.length<=target*FLAT_SPLIT_FACTOR)return null;
    const parts=[...n.direct.map(atomFile),...[...n.children.values()].map(atomNode)].sort((x,y)=>cmp(x.path,y.path));
    return parts.length>1?parts:null;
  }
  for(;;){
    let pick=-1,best=target;
    for(let i=0;i<atoms.length;i++){const sp=splitAtom(atoms[i]);if(sp&&atoms[i].files.length>best){pick=i;best=atoms[i].files.length}}
    if(pick<0)break;
    const sp=splitAtom(atoms[pick]);atoms.splice(pick,1,...sp);atoms.sort((a,b)=>cmp(a.path,b.path));
  }
  const order=new Map(manifest.map((f,i)=>[f,i])),groups=[];let cur=[],count=0,assigned=0;
  for(const a of atoms){
    const remainUnits=Math.max(1,desired-groups.length),remainFiles=manifest.length-assigned,aim=Math.ceil(remainFiles/remainUnits);
    if(cur.length&&groups.length<desired-1&&count+a.files.length>aim){groups.push(cur);assigned+=count;cur=[];count=0}
    cur.push(a);count+=a.files.length;
  }
  if(cur.length)groups.push(cur);
  const units=groups.map((g,i)=>{
    const files=g.flatMap(a=>a.files).sort((x,y)=>order.get(x)-order.get(y)),paths=g.map(a=>a.path).sort(cmp),roots=[...new Set(files.map(f=>f.split('/')[0]))].sort(cmp);
    const raw=Buffer.concat(files.map(f=>Buffer.from(`${f}\0`,'utf8')));
    return{id:`U${String(i+1).padStart(2,'0')}`,paths,roots,fileCount:files.length,membershipHash:hash(raw)};
  });
  const canon=Buffer.from(units.map(u=>`${u.id}\0${u.fileCount}\0${u.membershipHash}\0${u.paths.join('\0')}\0`).join(''),'utf8');
  return{mechanicalUnitTarget:UNIT_TARGET,mechanicalUnitCap:UNIT_CAP,units,unitsHash:hash(canon)};
}
const partialClone=isPartialClone(),graftsPresent=hasGrafts(),alternatesPresent=hasAlternates();if(alternatesPresent)throw new Error('Git object alternates detected; external attestation refuses external object stores. Use a standalone fully hydrated clone');if(range&&graftsPresent)throw new Error('Git info/grafts detected; remove it before range attestation because it rewrites commit ancestry');if(range&&partialClone)throw new Error('partial clone detected; range attestation refuses commands that may demand-fetch missing objects. Use a fully hydrated clone');
const revision=rev('HEAD'),trackedRaw=git(['ls-files','--cached','-z']).stdout,manifestRaw=git(['ls-files','--cached','--others',...untrackedFilter,'-z']).stdout,manifest=zlist(manifestRaw);
const unsafePaths=manifest.filter(p=>!safeRel(p)),untracked=zlist(git(['ls-files','--others',...untrackedFilter,'-z']).stdout),deletedTracked=zlist(git(['ls-files','--deleted','-z']).stdout),special=stageSpecial(),filters=filterInfo(trackedRaw);
// Git does not compare an assume-unchanged (lowercase tag) or skip-worktree
// (S, set by sparse checkout or by hand) entry with the working tree, so edits
// to one are invisible to the diffs below and the tree cannot be called clean.
const hiddenEntries=zlist(git(['ls-files','-v','-z']).stdout).filter(e=>/^(?:[a-z]|S) /.test(e)).map(e=>e.slice(2));
if(hiddenEntries.length){const msg=`index entries marked assume-unchanged or skip-worktree hide working-tree edits from Git (${hiddenEntries.slice(0,5).join(', ')}${hiddenEntries.length>5?', ...':''}); clear them with git update-index --no-assume-unchanged --no-skip-worktree, or disable sparse checkout`;if(range)throw new Error(`${msg} before range attestation`);process.stderr.write(`warning: ${msg}. The worktree is attested as DIRTY.\n`)}
let worktreeState,dirty;
if(partialClone){worktreeState='UNKNOWN_PARTIAL';dirty=false}
else {const staged=git(['diff-index','--cached','--quiet','HEAD','--'],{allow:[0,1]});if(staged.status===1||untracked.length>0||deletedTracked.length>0||hiddenEntries.length>0){worktreeState='DIRTY';dirty=true}else if(filters.customFiltersCount>0){worktreeState='UNKNOWN_FILTERS';dirty=false}else{const unstaged=git(['diff','--quiet','--no-ext-diff','--no-textconv','HEAD','--'],{allow:[0,1]});worktreeState=unstaged.status===1?'DIRTY':'CLEAN';dirty=unstaged.status===1}}
const ri=rangeInfo(range),changed=zlist(ri.changedRaw),runId=fingerprintRunId||crypto.randomUUID();
// contentHash binds the working-tree bytes of every manifest entry, so a
// DIRTY attestation still detects later edits. Bytes are read directly, never
// through Git filters; links and submodules contribute only their kind.
const lfsPointers=[],contentParts=[],trackedSymlinkSet=new Set(special.trackedSymlinks),submoduleSet=new Set(special.submodules),deletedSet=new Set(deletedTracked);let lfsPointerCount=0;
function fileDigest(p){const h=crypto.createHash('sha256'),fd=fs.openSync(p,'r'),buf=Buffer.alloc(1<<20);let head=Buffer.alloc(0);try{for(let n;(n=fs.readSync(fd,buf,0,buf.length,null))>0;){if(head.length<160)head=Buffer.concat([head,buf.subarray(0,Math.min(n,160-head.length))]);h.update(buf.subarray(0,n))}}finally{fs.closeSync(fd)}return{digest:h.digest('hex'),head}}
for(const rel of manifest){
  let kind='missing',digest='';
  if(submoduleSet.has(rel))kind='submodule';
  else if(!deletedSet.has(rel)&&safeRel(rel))try{
    const p=path.resolve(cwd,rel),st=fs.lstatSync(p);
    if(st.isSymbolicLink()){kind='symlink';digest=crypto.createHash('sha256').update(fs.readlinkSync(p)).digest('hex');if(!trackedSymlinkSet.has(rel)&&!unsafePaths.includes(rel))unsafePaths.push(rel)}
    else if(st.isFile()){kind='file';const r=fileDigest(p);digest=r.digest;if(r.head.toString('utf8').startsWith('version https://git-lfs.github.com/spec/v1\n')){lfsPointerCount++;if(lfsPointers.length<64)lfsPointers.push(rel)}}
    else kind='other';
  }catch(e){if(!e||!['ENOENT','ENOTDIR'].includes(e.code))throw e}
  contentParts.push(Buffer.from(`${rel}\0${kind}\0${digest}\0`,'utf8'));
}
const contentHash=crypto.createHash('sha256').update(Buffer.concat(contentParts)).digest('hex');
const rootCounts=Object.create(null);for(const p of manifest){const root=p.split('/')[0];rootCounts[root]=(rootCounts[root]||0)+1}
const unitInfo=mechanicalUnits(manifest);
const ignoreCase=boolConfig('core.ignoreCase'),caseMap=new Map(),caseCollisions=[];let caseCollisionCount=0;if(ignoreCase)for(const p of manifest){const k=p.normalize('NFC').toLowerCase();if(caseMap.has(k)&&caseMap.get(k)!==p){caseCollisionCount++;if(caseCollisions.length<32)caseCollisions.push([caseMap.get(k),p])}else caseMap.set(k,p)}
// Policy documents are repository-local files the operator names as security
// context. They are hashed into the attestation, so their bytes are covered by
// stateHash and the freshness check; the workflow treats their text as
// untrusted evidence, never as instructions.
const policyFold=p=>ignoreCase?p.toLowerCase():p;
const policyDocEntries=[];
for(const p of policyDocArgs){
  if(!safeRel(p))throw new Error(`--policy-doc must be a repository-relative path: ${p}`);
  if(!manifest.includes(p))throw new Error(`policy document is not in the attested manifest (it must be tracked or non-ignored untracked): ${p}`);
  if(trackedSymlinkSet.has(p)||submoduleSet.has(p))throw new Error(`policy document is not a regular file: ${p}`);
  let bytes=null,fd=null;
  try{fd=openRepoFile(p);bytes=fs.readFileSync(fd)}
  catch(e){const why=openFailure(e);if(why)throw new Error(`policy document is not a regular file (${why}): ${p}`);throw e}
  finally{if(fd!==null)fs.closeSync(fd)}
  policyDocEntries.push({path:p,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length});
}
if(new Set(policyDocEntries.map(d=>policyFold(d.path))).size!==policyDocEntries.length)throw new Error('--policy-doc names the same document twice');
const out={version:5,runId,repoRoot,revision,dirty,worktreeState,...filters,manifestHash:hash(manifestRaw),contentHash,totalFiles:manifest.length,rootCounts,...unitInfo,policyDocs:policyDocEntries,trackedSymlinks:special.trackedSymlinks,submodules:special.submodules,deletedTracked,sparse:boolConfig('core.sparseCheckout'),shallow:text(git(['rev-parse','--is-shallow-repository']))==='true',partialClone,graftsPresent,alternatesPresent,ignoreCase,caseCollisionCount,caseCollisions,lfsPointers,lfsPointerCount,lfsPointersTruncated:lfsPointerCount>lfsPointers.length,unsupportedPaths:unsafePaths,outputPathSafe:isOutputSafe(runId,new Set(zlist(trackedRaw)),ignoreCase),range:ri.range,rangeBase:ri.rangeBase,rangeHead:ri.rangeHead,changedFiles:changed.slice(0,256),changedFilesTruncated:changed.length>256,changedFilesHash:hash(ri.changedRaw),changedFilesCount:changed.length,rangeFiles:ri.rangeFiles,rangeFilesTruncated:ri.rangeFilesTruncated,rangeEvidenceTruncated:ri.rangeEvidenceTruncated,helperPath:helperPath.replace(/\\/g,'/'),nodePath:nodePath.replace(/\\/g,'/')};
// Every field that describes repository state. stateHash summarizes them so
// the workflow can compare a short --fingerprint line instead of the whole
// attestation.
const STATE_FIELDS=['version','repoRoot','revision','dirty','worktreeState','customFiltersCount','customFiltersHash','customFilterDrivers','manifestHash','contentHash','totalFiles','rootCounts','mechanicalUnitTarget','mechanicalUnitCap','units','unitsHash','policyDocs','trackedSymlinks','submodules','deletedTracked','sparse','shallow','partialClone','graftsPresent','alternatesPresent','ignoreCase','caseCollisionCount','caseCollisions','lfsPointers','lfsPointerCount','lfsPointersTruncated','unsupportedPaths','range','rangeBase','rangeHead','changedFiles','changedFilesTruncated','changedFilesHash','changedFilesCount','rangeFiles','rangeFilesTruncated','rangeEvidenceTruncated'];
// Keys are sorted at every level so the workflow, which recomputes this hash
// over the attestation it was handed, does not depend on key order surviving
// the trip through the model that passes it along.
const canon=x=>Array.isArray(x)?x.map(canon):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,canon(x[k])])):x;
out.stateHash=crypto.createHash('sha256').update(JSON.stringify(STATE_FIELDS.map(k=>[k,canon(out[k]??null)]))).digest('hex');
// The fingerprint names the helper and Node that produced it. Both passed this
// helper's own repository-boundary check from the repository root, which the
// workflow cannot repeat, so the workflow requires them to equal the attested
// helperPath and nodePath.
if(fingerprintRunId){emit({version:5,runId,repoRoot,revision,worktreeState,manifestHash:out.manifestHash,contentHash,stateHash:out.stateHash,outputPathSafe:out.outputPathSafe,helperPath:out.helperPath,nodePath:out.nodePath,policyDocCount:policyDocEntries.length});process.exit(0)}
// --emit-run writes a private run directory outside the repository holding
// the attestation and a generated workflow script with the attestation
// embedded verbatim. The session then calls the Workflow tool with that
// script's path and only its small options object, so the attestation never
// passes through a model. The generated script stays on disk so the run can
// be resumed; remove the directory by hand once the run is finished.
if(emitRun){
  const templates=[path.join(__dirname,'vuln-hunt.js'),path.join(os.homedir(),'.claude','workflows','vuln-hunt.js')];
  let template=null;
  for(const p of templates){
    let st;try{st=fs.lstatSync(p)}catch{continue}
    if(!st.isFile())continue;
    const realP=real(p);if(untrusted(realP))continue;
    const src=fs.readFileSync(realP,'utf8');
    if(!/^export const meta=/.test(src))continue;
    template={path:realP,src,sha256:crypto.createHash('sha256').update(src).digest('hex')};
    break;
  }
  if(!template)throw new Error('could not find the installed vuln-hunt.js workflow template next to this helper or in ~/.claude/workflows; the template must live outside the scanned repository');
  const m=/^export const meta=\{[\s\S]*?\};\s*/.exec(template.src);
  if(!m)throw new Error('workflow template does not begin with an export const meta literal');
  // The attestation is embedded as the text of a string literal and parsed
  // with JSON.parse, so the script sees exactly the object the attestation file
  // holds. An object literal would not: a "__proto__" key, such as a top-level
  // directory of that name in rootCounts, sets a prototype there instead of a
  // property. JSON.stringify of a string is a valid JavaScript string literal
  // once U+2028 and U+2029, which older parsers reject in literals, are
  // escaped.
  const json=JSON.stringify(out);
  const literal=JSON.stringify(json).split(String.fromCharCode(0x2028)).join('\\u2028').split(String.fromCharCode(0x2029)).join('\\u2029');
  // The prelude only declares __vhAttestation; it never touches the runtime's
  // args binding, so options arrive however the runtime passes them (object,
  // JSON string or nothing) and the template merges the embedded attestation
  // in, refusing an args.attestation that differs from it.
  const script=`${m[0]}// Generated for run ${out.runId} by vuln-hunt-attest.js --emit-run. The attestation below is this helper's own output, embedded verbatim; the rest is the installed workflow template (sha256 ${template.sha256}). The workflow cannot load scripts from the scanned repository: this file was written by the trusted helper outside it.\nconst __vhAttestation=JSON.parse(${literal});\n${template.src.slice(m[0].length)}`;
  // Compile the complete generated script the way the workflow runtime hands
  // it its bindings, as an async function body with args as a parameter, in
  // both sloppy and strict mode. This catches a prelude that breaks under
  // either, and a meta literal whose first "};" is not its end.
  const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor,body=script.replace(/^export const meta=/,'const meta=');
  for(const prefix of ['','"use strict";\n'])try{new AsyncFunction('args','agent','parallel','pipeline','phase','log',prefix+body)}catch(e){throw new Error(`the generated run script does not compile as a workflow body${prefix?' in strict mode':''}: ${String(e&&e.message||e)}`)}
  // mkdtemp creates the directory owner-only on POSIX; on Windows it inherits
  // the per-user temporary directory's ACL. A TMPDIR pointing into the scanned
  // repository would put the run script under repository control.
  const runDir=fs.mkdtempSync(path.join(os.tmpdir(),'vuln-hunt-run-'));
  if(untrusted(real(runDir))){fs.rmSync(runDir,{recursive:true,force:true});throw new Error('the temporary directory resolves inside the scanned repository; point TMPDIR (TEMP on Windows) outside it')}
  const attestationPath=path.join(runDir,'attestation.json'),scriptPath=path.join(runDir,'vuln-hunt-run.js');
  fs.writeFileSync(attestationPath,json+'\n',{mode:0o600});
  fs.writeFileSync(scriptPath,script,{mode:0o600});
  emit({version:2,ok:true,runDir,attestationPath,scriptPath,runId:out.runId,stateHash:out.stateHash,attestationBytes:Buffer.byteLength(json),templatePath:template.path.replace(/\\/g,'/'),templateHash:template.sha256,scriptHash:crypto.createHash('sha256').update(script).digest('hex'),policyDocs:policyDocEntries.map(d=>d.path)});process.exit(0);
}
// Windows PowerShell 5.1 `Set-Content -Encoding utf8` prepends a BOM.
if(comparePath){const before=JSON.parse(fs.readFileSync(path.resolve(comparePath),'utf8').replace(/^﻿/,'')),mismatches=STATE_FIELDS.filter(k=>JSON.stringify(before?.[k]??null)!==JSON.stringify(out?.[k]??null));emit({ok:mismatches.length===0,mismatches,beforeRunId:before?.runId||null,currentRunId:out.runId,current:out});process.exitCode=mismatches.length?2:0}else emit(out);
