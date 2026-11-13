#!/usr/bin/env node
'use strict';
const {spawnSync}=require('child_process');
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const cwd=process.cwd(),argv=process.argv.slice(2);
let range=null,selfTest=false,comparePath=null,checkOutputIgnoreTracked=false,fingerprintRunId=null;
for(let i=0;i<argv.length;i++){
  if(argv[i]==='--range'){if(i+1>=argv.length)throw new Error('--range requires a value');range=argv[++i]}
  else if(argv[i]==='--self-test'){selfTest=true}
  else if(argv[i]==='--compare'){if(i+1>=argv.length)throw new Error('--compare requires a JSON file');comparePath=argv[++i]}
  else if(argv[i]==='--fingerprint'){if(i+1>=argv.length||!/^[A-Za-z0-9._-]{1,96}$/.test(argv[i+1]))throw new Error('--fingerprint requires the attested runId');fingerprintRunId=argv[++i]}
  else if(argv[i]==='--check-output-ignore-tracked'){checkOutputIgnoreTracked=true}
  else if(argv[i]==='--help'){console.log('Usage: node vuln-hunt-attest.js [--self-test] [--range <ref|A..B|A...B>] [--compare <before-attestation.json> | --fingerprint <runId>] [--check-output-ignore-tracked]');process.exit(0)}
  else throw new Error(`Unknown argument: ${argv[i]}`);
}
if(comparePath&&fingerprintRunId)throw new Error('--compare and --fingerprint are mutually exclusive');
const rangeRe=/^[A-Za-z0-9][A-Za-z0-9._~^/@:+{}-]*(?:\.{2,3}[A-Za-z0-9][A-Za-z0-9._~^/@:+{}-]*)?$/;
if(range&&!rangeRe.test(range))throw new Error('range contains unsupported characters');
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
    return path.basename(common)==='.git'?fs.realpathSync(path.dirname(common)):null;
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
const untrustedRoots=repositoryBoundaries(fs.realpathSync(cwd)),untrusted=p=>untrustedRoots.some(r=>inside(r,p));
function resolveGitExecutable(){
  const dirs=String(process.env.PATH||'').split(path.delimiter),exts=process.platform==='win32'?[...new Set(String(process.env.PATHEXT||'.EXE;.COM').split(';').filter(e=>/^\.(?:exe|com)$/i.test(e)))]:[''];
  for(let raw of dirs){raw=raw.trim();if(raw.length>=2&&raw[0]==='\"'&&raw.at(-1)==='\"')raw=raw.slice(1,-1);if(!raw||!path.isAbsolute(raw))continue;let dir;try{dir=fs.realpathSync(raw)}catch{continue}if(untrusted(dir))continue;
    for(const ext of exts){const candidate=path.join(dir,`git${ext}`);try{const real=fs.realpathSync(candidate),st=fs.statSync(real);if(untrusted(real)||!st.isFile())continue;if(process.platform!=='win32')fs.accessSync(real,fs.constants.X_OK);return real}catch{}}
  }
  throw new Error(`could not resolve a trusted Git executable from PATH outside the enclosing repository roots (${untrustedRoots.join(', ')}). If one of them is a home-directory repository, run from a checkout outside it or install Git elsewhere`);
}
const gitExecutable=resolveGitExecutable();
// The workflow's freshness check re-executes this helper with this Node, so
// neither may live in repository-controlled content.
const helperPath=fs.realpathSync(__filename),nodePath=fs.realpathSync(process.execPath);
if(untrusted(helperPath)||untrusted(nodePath))throw new Error('run the installed attestation helper with a Node runtime outside the target repository');
const env={...process.env};for(const k of Object.keys(env))if(['GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES','GIT_COMMON_DIR','GIT_NAMESPACE','GIT_CEILING_DIRECTORIES','GIT_DISCOVERY_ACROSS_FILESYSTEM','GIT_CONFIG','GIT_CONFIG_GLOBAL','GIT_CONFIG_SYSTEM','GIT_CONFIG_NOSYSTEM','GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS','GIT_QUARANTINE_PATH','GIT_SHALLOW_FILE','GIT_EXEC_PATH','GIT_EXTERNAL_DIFF','GIT_ATTR_NOSYSTEM'].includes(k)||/^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(k)||/^GIT_TRACE(?:_|$)/.test(k))delete env[k];Object.assign(env,{GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0',GIT_PAGER:'cat',PAGER:'cat',GIT_NO_LAZY_FETCH:'1',GIT_NO_REPLACE_OBJECTS:'1',NoDefaultCurrentDirectoryInExePath:'1'});
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
const topRaw=text(git(['rev-parse','--show-toplevel'])),cwdReal=fs.realpathSync(cwd),topReal=fs.realpathSync(topRaw);if(cwdReal!==topReal)throw new Error(`run attestation from repository root: ${topReal}`);if(/[\0\r\n\t]/.test(topReal)||(path.sep==='/'&&topReal.includes('\\')))throw new Error('repository root contains an unsupported control/backslash character');const repoRoot=topReal.replace(/\\/g,'/');
if(checkOutputIgnoreTracked){const r=git(['ls-files','--error-unmatch','--','.vuln-hunt/.gitignore'],{allow:[0,1]});emit({tracked:r.status===0,repoRoot});process.exit(0)}
const commandShadows=[path.join(cwd,'.claude','workflows','vuln-hunt.js'),path.join(cwd,'.claude','commands','vuln-hunt.md'),path.join(cwd,'.claude','skills','vuln-hunt')];
for(const p of commandShadows)try{fs.lstatSync(p);throw new Error(`project-local /vuln-hunt command shadow detected: ${path.relative(cwd,p).replace(/\\/g,'/')}. Remove/rename it so the installed personal workflow is the command that runs`)}catch(e){if(e&&e.code!=='ENOENT')throw e}
// A project agent named like a worker outranks the installed user-level
// worker, which would let the repository choose that worker's tools and
// instructions. Keep this list identical to vuln-hunt-agents.json.
const WORKER_AGENTS=['vuln-hunt-researcher','vuln-hunt-mechanic','vuln-hunt-reporter'];
function agentShadows(){
  const key=p=>process.platform==='win32'?path.resolve(p).toLowerCase():path.resolve(p),userAgents=key(path.join(require('os').homedir(),'.claude','agents')),found=[];
  const walk=dir=>{let entries;try{entries=fs.readdirSync(dir,{withFileTypes:true})}catch(e){if(e&&['ENOENT','ENOTDIR'].includes(e.code))return;throw e}
    for(const e of entries){const p=path.join(dir,e.name);if(e.isDirectory())walk(p);else if(/\.md$/i.test(e.name)){const fm=/^---\r?\n([\s\S]*?)\r?\n---/.exec(fs.readFileSync(p,'utf8')),m=fm&&/^name:\s*["']?(.+?)["']?\s*$/m.exec(fm[1]);if(m&&WORKER_AGENTS.includes(m[1].trim()))found.push(p)}}};
  for(let d=cwd;;){const a=path.join(d,'.claude','agents');if(key(a)!==userAgents)walk(a);const up=path.dirname(d);if(up===d)break;d=up}
  return found;
}
const shadows=agentShadows();if(shadows.length)throw new Error(`project agent shadows a vuln-hunt worker: ${shadows.join(', ')}. Remove or rename it before scanning`);
const dec=new TextDecoder('utf-8',{fatal:true});
const outputIgnorePath=path.join(cwd,'.vuln-hunt','.gitignore');try{const st=fs.lstatSync(outputIgnorePath);if(st.isFile()){const raw=fs.readFileSync(outputIgnorePath,'utf8');if(raw==='runs/'||raw==='runs/\n'||raw==='runs/\r\n')throw new Error('.vuln-hunt/.gitignore contains runs/ and would let tool output into the manifest; replace its contents with *')}}catch(e){if(e&&e.code!=='ENOENT')throw e}
function zlist(b){const out=[];let start=0;for(let i=0;i<b.length;i++)if(b[i]===0){try{out.push(dec.decode(b.subarray(start,i)))}catch{throw new Error('repository contains a non-UTF-8 pathname; unsupported for safe workflow citation')}start=i+1}if(start!==b.length)throw new Error('expected NUL-terminated Git output');return out}
const hash=b=>text(git(['hash-object','--no-filters','--stdin'],{input:b}));
const oid=s=>/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i.test(s);
const safeRel=p=>p.length>0&&!p.includes('\\')&&!/[\0\r\n\t]/.test(p)&&!path.isAbsolute(p)&&!p.split('/').includes('..');
function rev(ref){const s=text(git(['rev-parse','--verify',`${ref}^{commit}`]));if(!oid(s))throw new Error(`could not resolve commit: ${ref}`);return s}
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
  let base,head;
  if(spec.includes('...')){const [a,b]=spec.split('...');const ra=rev(a),rb=rev(b);base=mergeBase(ra,rb);head=rb}
  else if(spec.includes('..')){const [a,b]=spec.split('..');base=rev(a);head=rev(b)}
  else {head=rev(spec);const p=git(['rev-parse','--verify',`${spec}^1^{commit}`],{allow:[0,128]});base=p.status===0?text(p):emptyTree()}
  const changedRaw=git(['diff','--name-only','-z','--no-ext-diff','--no-textconv',base,head,'--']).stdout;
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
function isOutputSafe(runId,tracked){
  if([...tracked].some(p=>p==='.vuln-hunt'||p.startsWith('.vuln-hunt/')))return false;
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
// Untracked OS, editor and Claude Code metadata never enters the manifest.
// --exclude patterns apply only to untracked files, so tracked copies (for
// example a committed .vscode/tasks.json) stay in coverage. Keep this list
// identical to LOCAL_METADATA_EXCLUDES in vuln-hunt.js.
const LOCAL_METADATA_EXCLUDES=[".DS_Store","Thumbs.db","ehthumbs.db","desktop.ini","/.idea/","/.vscode/","/.claude/settings.local.json"];
const untrackedFilter=['--exclude-per-directory=.gitignore',...LOCAL_METADATA_EXCLUDES.map(p=>`--exclude=${p}`)];
const revision=rev('HEAD'),trackedRaw=git(['ls-files','--cached','-z']).stdout,manifestRaw=git(['ls-files','--cached','--others',...untrackedFilter,'-z']).stdout,manifest=zlist(manifestRaw);
const unsafePaths=manifest.filter(p=>!safeRel(p)),untracked=zlist(git(['ls-files','--others',...untrackedFilter,'-z']).stdout),deletedTracked=zlist(git(['ls-files','--deleted','-z']).stdout),special=stageSpecial(),filters=filterInfo(trackedRaw);
let worktreeState,dirty;
if(partialClone){worktreeState='UNKNOWN_PARTIAL';dirty=false}
else {const staged=git(['diff-index','--cached','--quiet','HEAD','--'],{allow:[0,1]});if(staged.status===1||untracked.length>0||deletedTracked.length>0){worktreeState='DIRTY';dirty=true}else if(filters.customFiltersCount>0){worktreeState='UNKNOWN_FILTERS';dirty=false}else{const unstaged=git(['diff','--quiet','--no-ext-diff','--no-textconv','HEAD','--'],{allow:[0,1]});worktreeState=unstaged.status===1?'DIRTY':'CLEAN';dirty=unstaged.status===1}}
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
const out={version:4,runId,repoRoot,revision,dirty,worktreeState,...filters,manifestHash:hash(manifestRaw),contentHash,totalFiles:manifest.length,rootCounts,...unitInfo,trackedSymlinks:special.trackedSymlinks,submodules:special.submodules,deletedTracked,sparse:boolConfig('core.sparseCheckout'),shallow:text(git(['rev-parse','--is-shallow-repository']))==='true',partialClone,graftsPresent,alternatesPresent,ignoreCase,caseCollisionCount,caseCollisions,lfsPointers,lfsPointerCount,lfsPointersTruncated:lfsPointerCount>lfsPointers.length,unsupportedPaths:unsafePaths,outputPathSafe:isOutputSafe(runId,new Set(zlist(trackedRaw))),range:ri.range,rangeBase:ri.rangeBase,rangeHead:ri.rangeHead,changedFiles:changed.slice(0,256),changedFilesTruncated:changed.length>256,changedFilesHash:hash(ri.changedRaw),changedFilesCount:changed.length,rangeFiles:ri.rangeFiles,rangeFilesTruncated:ri.rangeFilesTruncated,rangeEvidenceTruncated:ri.rangeEvidenceTruncated,helperPath:helperPath.replace(/\\/g,'/'),nodePath:nodePath.replace(/\\/g,'/')};
// Every field that describes repository state. stateHash summarizes them so
// the workflow can compare a short --fingerprint line instead of the whole
// attestation.
const STATE_FIELDS=['version','repoRoot','revision','dirty','worktreeState','customFiltersCount','customFiltersHash','customFilterDrivers','manifestHash','contentHash','totalFiles','rootCounts','mechanicalUnitTarget','mechanicalUnitCap','units','unitsHash','trackedSymlinks','submodules','deletedTracked','sparse','shallow','partialClone','graftsPresent','alternatesPresent','ignoreCase','caseCollisionCount','caseCollisions','lfsPointers','lfsPointerCount','lfsPointersTruncated','unsupportedPaths','range','rangeBase','rangeHead','changedFiles','changedFilesTruncated','changedFilesHash','changedFilesCount','rangeFiles','rangeFilesTruncated','rangeEvidenceTruncated'];
// Keys are sorted at every level so the workflow, which recomputes this hash
// over the attestation it was handed, does not depend on key order surviving
// the trip through the model that passes it along.
const canon=x=>Array.isArray(x)?x.map(canon):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,canon(x[k])])):x;
out.stateHash=crypto.createHash('sha256').update(JSON.stringify(STATE_FIELDS.map(k=>[k,canon(out[k]??null)]))).digest('hex');
if(fingerprintRunId){emit({version:4,runId,repoRoot,revision,worktreeState,manifestHash:out.manifestHash,contentHash,stateHash:out.stateHash,outputPathSafe:out.outputPathSafe});process.exit(0)}
// Windows PowerShell 5.1 `Set-Content -Encoding utf8` prepends a BOM.
if(comparePath){const before=JSON.parse(fs.readFileSync(path.resolve(comparePath),'utf8').replace(/^﻿/,'')),mismatches=STATE_FIELDS.filter(k=>JSON.stringify(before?.[k]??null)!==JSON.stringify(out?.[k]??null));emit({ok:mismatches.length===0,mismatches,beforeRunId:before?.runId||null,currentRunId:out.runId,current:out});process.exitCode=mismatches.length?2:0}else emit(out);
