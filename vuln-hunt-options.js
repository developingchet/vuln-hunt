#!/usr/bin/env node
'use strict';
// The options the vuln-hunt workflow accepts, the presets built from them, and
// the parser /vuln-hunt:scan uses to turn its arguments into workflow args.
// vuln-hunt.js keeps its own validator, because a workflow script cannot read
// files; tests/options.js checks that both accept and refuse the same values,
// and that README.md shows the tables printed here.
//
//   --resolve        read /vuln-hunt:scan's arguments from stdin and print the
//                    resolved workflow args as one line of JSON (exit 2 when
//                    the arguments are refused)
//   --list           print every option, the presets and the argument forms
//   --table          print the options table README.md carries
//   --presets-table  print the presets table README.md carries
//   --schema         print the options, presets and stages as JSON
const fs=require('fs');

const STAGES=['default','inventory','freshness','recon','hunt','continuation','salvage','sweep','verify','verifyReachability','verifyImpact','verifyDefenses','adjudicate','variants','repro','validate','report'];
const CONTAINMENTS=['sandbox-runtime','container','vm','cloud-session'];
// Keep both patterns identical to RUN_ID_RE and RANGE_RE in vuln-hunt.js.
const RUN_ID_RE=/^(?!.*\.$)(?!(?:con|prn|aux|nul|com\d|lpt\d)(?:\.|$))[A-Za-z0-9._-]{1,96}$/i;
const RANGE_RE=/^[A-Za-z0-9][A-Za-z0-9._~^/@:+{}-]*(?:\.{2,3}[A-Za-z0-9][A-Za-z0-9._~^/@:+{}-]*)?$/;
const STRICT_ONLY='Not accepted by `/vuln-hunt:scan`, whose scans are always strict and attested.';

// kind decides how a value is parsed and checked; values, def and effect are
// the text of the options table. nullable options accept null as "not set".
// scan:false marks an option /vuln-hunt:scan sets itself or that has no
// effect in its strict, attested scans; scanNote says which.
const OPTIONS=[
  {name:'attestation',kind:'object',nullable:true,scan:false,scanNote:'/vuln-hunt:scan embeds the attestation in the generated run script',values:'helper output',def:'none',effect:'The attestation; required by `strictProvenance` and `range`. `/vuln-hunt:scan` embeds it in a generated run script instead of passing it here.'},
  {name:'strictProvenance',kind:'boolean',scan:false,scanNote:'/vuln-hunt:scan always runs with strictProvenance',values:'`true`, `false`',def:'`false`',effect:'Refuse anything short of an attested, clean, fully hydrated checkout. `/vuln-hunt:scan` always sets it.'},
  {name:'range',kind:'range',nullable:true,values:'`A..B`, `A...B`, `REF`',def:'none',effect:'Review a change instead of the whole tree.'},
  {name:'hunters',kind:'integer',min:2,max:6,also:['auto'],values:'2–6, `"auto"`',def:'4',effect:'Most hunter portfolios recon may create.'},
  {name:'candidateCap',kind:'integer',min:1,max:6,values:'1–6',def:'3',effect:'Most candidates per hunter; a hunter that hits it is listed in `candidateSaturation`.'},
  {name:'maxConcurrentAgents',kind:'integer',min:1,max:256,values:'1–256',def:'runtime\'s own limit',effect:'Ceiling on agents this one run dispatches at once, across every stage, panels and retries included. Admission is first-in-first-out, and a failed agent releases its slot.'},
  {name:'policyDocs',kind:'paths',max:8,nullable:true,values:'1–8 paths',def:'none',effect:'Repository security-policy documents to read as untrusted evidence; each must have been attested with `--policy-doc`. An attested document left out here is listed in `policyDocsAttestedInactive`.'},
  {name:'salvage',kind:'boolean',values:'`true`, `false`',def:'`true`',effect:'Revisit units a hunter did not reach, at or above `salvageRisk`.'},
  {name:'salvageRisk',kind:'enum',choices:['high','medium','all'],values:'`"high"`, `"medium"`, `"all"`',def:'`"high"`',effect:'Lowest unit risk salvage covers.'},
  {name:'sweep',kind:'boolean',values:'`true`, `false`',def:'`true`',effect:'Look for bugs across portfolio boundaries; never upgrades unit coverage.'},
  {name:'adjudicate',kind:'boolean',values:'`true`, `false`',def:'`true`',effect:'Send split panels to a fresh adjudicator.'},
  {name:'saturationContinuation',kind:'boolean',values:'`true`, `false`',def:'`false`',effect:'Give hunters that hit `candidateCap` one more pass for other roots.'},
  {name:'variants',kind:'boolean',values:'`true`, `false`',def:'`false`',effect:'List other affected sites of verified roots.'},
  {name:'mode',kind:'enum',choices:['static','dynamic'],values:'`"static"`, `"dynamic"`',def:'`"static"`',effect:'`"dynamic"` adds contained reproduction.'},
  {name:'containment',kind:'enum',choices:CONTAINMENTS,values:'`"sandbox-runtime"`, `"container"`, `"vm"`, `"cloud-session"`',def:'none',effect:'The externally enforced containment of the whole session, which dynamic mode requires; see [Isolation](#isolation).'},
  {name:'network',kind:'boolean',values:'`true`, `false`',def:'none',effect:'Whether the session can reach the network; dynamic mode requires `false`.'},
  {name:'credentials',kind:'boolean',values:'`true`, `false`',def:'none',effect:'Whether the session holds credentials; dynamic mode requires `false`.'},
  {name:'reproEnvironment',kind:'repro',nullable:true,values:'object, see [Reproduction environment](#reproduction-environment)',def:'none',effect:'A typed descriptor of the pre-built execution environment, so dynamic scans need no hand-edited workflow script.'},
  {name:'reproMinSeverity',kind:'enum',choices:['critical','high','medium','low'],values:'`"critical"`, `"high"`, `"medium"`, `"low"`',def:'none',effect:'Reproduce only verified findings at or above this severity, by the verifiers\' own severity opinions.'},
  {name:'models',kind:'stageMap',values:'per-stage map',def:'see below',effect:'Model per stage.'},
  {name:'efforts',kind:'stageMap',values:'per-stage map',def:'see below',effect:'Effort per stage.'},
  {name:'allowSparse',kind:'boolean',scan:false,scanNote:'allowSparse only applies to scans that are not strict',values:'`true`, `false`',def:'`false`',effect:`Accept a sparse checkout in a scan that is not strict. ${STRICT_ONLY}`},
  {name:'allowLfsPointers',kind:'boolean',scan:false,scanNote:'allowLfsPointers only applies to scans that are not strict',values:'`true`, `false`',def:'`false`',effect:`Accept LFS pointers in a scan that is not strict. ${STRICT_ONLY}`},
  {name:'runId',kind:'runId',scan:false,scanNote:'an attested scan takes its runId from the attestation',values:'string, not ending in a dot, not a Windows device name',def:'derived',effect:`Run folder name when there is no attestation; an attestation's own \`runId\` always wins. ${STRICT_ONLY}`},
  {name:'tag',kind:'string',nullable:true,values:'string',def:'none',effect:'A free-form label copied into the result.'},
];
const PRESETS={
  quick:{use:'A fast first look: two hunters with fewer candidates each, and no salvage or cross-portfolio sweep.',options:{hunters:2,candidateCap:2,salvage:false,sweep:false}},
  standard:{use:'The workflow defaults.',options:{}},
  deep:{use:'The most thorough and slowest: six hunters with more candidates each, salvage of every unreached unit, a continuation pass and variant analysis.',options:{hunters:6,candidateCap:5,salvageRisk:'all',saturationContinuation:true,variants:true}},
};
const BY_NAME=new Map(OPTIONS.map(o=>[o.name,o]));
const BY_LOWER=new Map(OPTIONS.map(o=>[o.name.toLowerCase(),o]));
const MAX_ARGS_LENGTH=65536;
// How reproEnvironment.<field>=<text> is parsed; the checks are the
// workflow's own (reproEnvError mirrors reproEnvSchema in vuln-hunt.js).
const REPRO_FIELDS={backend:'string',image:'string',sourceLocation:'string',workingDirectory:'string',artifactsDir:'string',instructions:'string',runtimeCapabilities:'list',testEntrypoints:'entrypoints',verifiedReady:'boolean',timeoutMs:'integer',resourceLimits:'json'};

const has=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
const isObj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const rangeOk=r=>{if(typeof r!=='string'||!RANGE_RE.test(r))return false;const m=/^(.*?)(\.{2,3})(.*)$/s.exec(r);return !m||(Boolean(m[1])&&Boolean(m[3])&&!m[3].startsWith('.')&&!m[3].includes('..'))};
// Mirrors safePathLength in vuln-hunt.js.
const docPathOk=p=>typeof p==='string'&&p.length>0&&p.length<=4096&&!p.includes('\\')&&!/[\0\r\n]/.test(p)&&!/^([\\/]|[A-Za-z]:[\\/])/.test(p)&&!p.split('/').includes('..');
const location=v=>typeof v==='string'&&v.length>0&&v.length<=512&&!/[\0\r\n]/.test(v);

function reproEnvError(x){
  const set=k=>has(x,k)&&x[k]!==null;
  if(!isObj(x))return'reproEnvironment must be an object describing the pre-built execution environment';
  if(!['container','vm'].includes(x.backend))return'reproEnvironment.backend must be "container" or "vm"';
  if(x.backend==='container'&&!(typeof x.image==='string'&&/^[\S]{1,512}$/.test(x.image)))return'reproEnvironment.image must be an immutable image identifier (digest or tag), 1-512 characters';
  for(const k of ['sourceLocation','workingDirectory','artifactsDir'])if(set(k)&&!location(x[k]))return`reproEnvironment.${k} must be a 1-512 character location string without control characters`;
  if(set('runtimeCapabilities')&&(!Array.isArray(x.runtimeCapabilities)||x.runtimeCapabilities.length>8||!x.runtimeCapabilities.every(v=>typeof v==='string'&&v.length>0&&v.length<=64)))return'reproEnvironment.runtimeCapabilities must be an array of at most 8 short runtime names';
  if(set('testEntrypoints')&&(!Array.isArray(x.testEntrypoints)||x.testEntrypoints.length>8||!x.testEntrypoints.every(location)))return'reproEnvironment.testEntrypoints must be an array of at most 8 command strings without control characters';
  if(set('instructions')&&!(typeof x.instructions==='string'&&x.instructions.length>0&&x.instructions.length<=4000))return'reproEnvironment.instructions must be a string of at most 4000 characters';
  if(set('verifiedReady')&&typeof x.verifiedReady!=='boolean')return'reproEnvironment.verifiedReady must be true or false';
  if(set('timeoutMs')&&!(Number.isInteger(x.timeoutMs)&&x.timeoutMs>=1000&&x.timeoutMs<=3600000))return'reproEnvironment.timeoutMs must be an integer between 1000 and 3600000';
  if(set('resourceLimits')){const r=x.resourceLimits;if(!isObj(r))return'reproEnvironment.resourceLimits must be an object';for(const k of ['cpu','memory','pids'])if(has(r,k)&&r[k]!==null&&!(typeof r[k]==='string'&&r[k].length>0&&r[k].length<=64))return`reproEnvironment.resourceLimits.${k} must be a short string`}
  return null;
}

// Returns null when value is acceptable for opt, otherwise the reason.
function checkValue(opt,value){
  if(value===null)return opt.nullable?null:`${opt.name} cannot be null`;
  switch(opt.kind){
    case 'boolean':return typeof value==='boolean'?null:`${opt.name} must be true or false`;
    case 'integer':return (opt.also||[]).includes(value)||(Number.isInteger(value)&&value>=opt.min&&value<=opt.max)?null:`${opt.name} must be an integer from ${opt.min} to ${opt.max}${opt.also?`, or ${opt.also.map(x=>JSON.stringify(x)).join(', ')}`:''}`;
    case 'enum':return opt.choices.includes(value)?null:`${opt.name} must be one of ${opt.choices.map(x=>JSON.stringify(x)).join(', ')}`;
    case 'string':return typeof value==='string'?null:`${opt.name} must be a string`;
    case 'runId':return typeof value==='string'&&RUN_ID_RE.test(value)?null:`${opt.name} must be 1-96 letters, digits, dots, underscores or hyphens, must not end in a dot, and must not be a Windows device name`;
    case 'range':return rangeOk(value)?null:`${opt.name} must be REF, A..B or A...B with normal Git refs`;
    case 'paths':{
      if(!Array.isArray(value)||!value.length||value.length>opt.max||!value.every(docPathOk))return`${opt.name} must be a list of 1-${opt.max} repository-relative paths`;
      const seen=new Set();for(const p of value){const k=p.toLowerCase();if(seen.has(k))return`${opt.name} names the same document twice`;seen.add(k)}
      return null;
    }
    case 'stageMap':{
      if(!isObj(value))return`${opt.name} must be an object keyed by stage`;
      const bad=Object.keys(value).filter(s=>!STAGES.includes(s)||typeof value[s]!=='string'||!value[s]);
      return bad.length?`${opt.name} has unknown stages or empty values: ${bad.join(', ')}; stages are ${STAGES.join(', ')}`:null;
    }
    case 'repro':return reproEnvError(value);
    case 'object':return isObj(value)?null:`${opt.name} must be an object`;
    default:return`${opt.name} has no known kind`;
  }
}

// Splits the argument text at whitespace outside quotes and outside JSON, so
// a JSON object or a quoted value with spaces stays one token. Quotes and
// brackets open only at the start of a token or right after option=, so an
// apostrophe or a brace inside a word (it's, HEAD@{1}, tag=a='b) is an
// ordinary character.
function tokenize(raw){
  const tokens=[];let cur='',depth=0,quote=null,esc=false;
  const opening=()=>depth>0||cur===''||/^(?:--)?[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)?=$/.test(cur);
  for(const ch of raw){
    if(quote){cur+=ch;if(quote==='"'&&esc)esc=false;else if(quote==='"'&&ch==='\\')esc=true;else if(ch===quote)quote=null;continue}
    if((ch==='"'||(ch==='\''&&depth===0))&&opening()){quote=ch;cur+=ch;continue}
    if((ch==='{'||ch==='[')&&opening()){depth++;cur+=ch;continue}
    if((ch==='}'||ch===']')&&depth>0){depth--;cur+=ch;continue}
    if(/\s/.test(ch)&&depth===0){if(cur){tokens.push(cur);cur=''}continue}
    cur+=ch;
  }
  if(quote||depth)return{tokens:[],error:'the arguments have an unclosed quote or bracket'};
  if(cur)tokens.push(cur);
  return{tokens,error:null};
}

const unquote=t=>{
  if(t.length>=2&&t.startsWith('\'')&&t.endsWith('\''))return{value:t.slice(1,-1)};
  if(t.startsWith('"')){try{const v=JSON.parse(t);return typeof v==='string'?{value:v}:{error:'not a string'}}catch{return{error:'not a valid quoted string'}}}
  return{value:t};
};
const BOOLEAN_WORDS={true:true,yes:true,on:true,1:true,false:false,no:false,off:false,0:false};
const parseBoolean=(name,s)=>{const k=s.toLowerCase();return has(BOOLEAN_WORDS,k)?{value:BOOLEAN_WORDS[k]}:{error:`${name} must be true or false`}};
const parseJson=(name,text)=>{try{return{value:JSON.parse(text)}}catch{return{error:`${name}: the value is not valid JSON; quote text that starts with [ or {, as ${name}="[text]"`}}};

// Parses the text after key= for opt. A value that starts with { or [ is JSON.
function parseText(opt,text){
  if(/^[{[]/.test(text))return parseJson(opt.name,text);
  const u=unquote(text);if(u.error)return{error:`${opt.name}: ${u.error}`};
  const s=u.value;
  switch(opt.kind){
    case 'boolean':return parseBoolean(opt.name,s);
    case 'integer':return (opt.also||[]).includes(s.toLowerCase())?{value:s.toLowerCase()}:/^\d{1,9}$/.test(s)?{value:Number(s)}:{error:checkValue(opt,s)};
    case 'enum':{const c=opt.choices.find(x=>x.toLowerCase()===s.toLowerCase());return c?{value:c}:{error:checkValue(opt,s)}}
    case 'paths':return{value:s.split(',').map(x=>x.trim()).filter(Boolean)};
    case 'stageMap':case 'repro':case 'object':return{error:`${opt.name} takes a JSON object, or one field at a time as ${opt.name}.<field>=<value>`};
    default:return{value:s};
  }
}
// Parses the text after name.field= : a stage takes a model or effort name,
// and a reproEnvironment field is parsed by its own type.
function parseField(opt,field,text){
  const label=`${opt.name}.${field}`,json=/^[{[]/.test(text);
  if(opt.kind==='repro'&&!has(REPRO_FIELDS,field))return{error:`reproEnvironment has no field ${JSON.stringify(field)}; fields are ${Object.keys(REPRO_FIELDS).join(', ')}`};
  const u=json?parseJson(label,text):unquote(text);
  if(u.error)return{error:json?u.error:`${label}: ${u.error}`};
  if(opt.kind==='stageMap'||json)return u;
  const kind=REPRO_FIELDS[field],s=u.value;
  switch(kind){
    case 'boolean':return parseBoolean(`${opt.name}.${field}`,s);
    case 'integer':return /^\d{1,9}$/.test(s)?{value:Number(s)}:{error:`${opt.name}.${field} must be a whole number`};
    case 'list':return{value:s.split(',').map(x=>x.trim()).filter(Boolean)};
    case 'entrypoints':return{value:[s]};
    case 'json':return{error:`${opt.name}.${field} takes a JSON object`};
    default:return{value:s};
  }
}

// Edit distance, for suggesting the option or preset a misspelt word meant.
function distance(a,b){
  let prev=Array.from({length:b.length+1},(_,j)=>j);
  for(let i=1;i<=a.length;i++){const row=[i];for(let j=1;j<=b.length;j++)row[j]=Math.min(prev[j]+1,row[j-1]+1,prev[j-1]+(a[i-1]===b[j-1]?0:1));prev=row}
  return prev[b.length];
}
const WORDS=[...OPTIONS.map(o=>o.name),...Object.keys(PRESETS)];
// A suggestion needs a word of at least minLength letters within max edits.
const nearest=(t,max=2,minLength=4)=>{const w=t.toLowerCase().replace(/^(?:--)?(?:no-)?/,'');if(w.length<minLength)return null;const best=WORDS.map(x=>[x,distance(w,x.toLowerCase())]).sort((a,b)=>a[1]-b[1])[0];return best&&best[1]>0&&best[1]<=max?best[0]:null};

// One resolution in progress: what the arguments set, and what was wrong.
function newState(){return{errors:[],unrecognized:[],given:Object.create(null),preset:null,help:false}}
function setGiven(st,opt,value){
  if(opt.scan===false){st.errors.push(`${opt.name} cannot be set here: ${opt.scanNote}`);return}
  if(has(st.given,opt.name)){
    const cur=st.given[opt.name],mergeable=['stageMap','repro'].includes(opt.kind)&&isObj(cur)&&isObj(value);
    const clash=mergeable?Object.keys(value).find(k=>has(cur,k)):null;
    if(!mergeable||clash){st.errors.push(`${opt.name}${clash?`.${clash}`:''} is given more than once`);return}
    st.given[opt.name]={...cur,...value};return;
  }
  st.given[opt.name]=value;
}
function setPreset(st,name){
  const k=String(name).toLowerCase();
  if(!has(PRESETS,k)){st.errors.push(`unknown preset ${JSON.stringify(String(name))}; presets are ${Object.keys(PRESETS).join(', ')}`);return}
  if(st.preset!==null&&st.preset!==k){st.errors.push(`only one preset can be given, not both ${st.preset} and ${k}`);return}
  st.preset=k;
}
function unrecognized(st,t,why){st.unrecognized.push(t);const near=nearest(t);st.errors.push(`unrecognized argument ${JSON.stringify(t)}${why?`: ${why}`:near?`; did you mean ${near}?`:''}`)}

function applyJson(st,t){
  let o;try{o=JSON.parse(t)}catch{st.errors.push('the JSON options object is not valid JSON');return}
  if(!isObj(o)){st.errors.push('the JSON options must be one object');return}
  for(const k of Object.keys(o)){
    if(k.toLowerCase()==='preset'){setPreset(st,o[k]);continue}
    const opt=BY_LOWER.get(k.toLowerCase());if(!opt){st.errors.push(`unknown option ${JSON.stringify(k)}`);continue}
    setGiven(st,opt,o[k]);
  }
}
function applyKeyValue(st,key,field,text){
  if(key.toLowerCase()==='preset'&&!field){setPreset(st,unquote(text).value??text);return}
  const opt=BY_LOWER.get(key.toLowerCase());if(!opt){const near=nearest(key);st.errors.push(`unknown option ${JSON.stringify(key)}${near?`; did you mean ${near}?`:''}`);return}
  if(field&&!['stageMap','repro'].includes(opt.kind)){st.errors.push(`${opt.name} has no fields; set it as ${opt.name}=<value>`);return}
  const r=field?parseField(opt,field,text):parseText(opt,text);
  if(r.error){st.errors.push(r.error);return}
  setGiven(st,opt,field?{[field]:r.value}:r.value);
}
// A bare word: help, a preset, a true/false option (no- turns it off), or a
// range. A bare ref is a range only as the first argument or when it names
// two ends, so the words of a sentence are reported rather than taken as refs;
// a first argument one letter away from an option or preset is taken as a
// typing mistake, and any ref can still be given as range=REF.
function applyWord(st,raw,i,tokens){
  let t=raw;
  if(/^["']/.test(t)){const u=unquote(t);if(u.error){unrecognized(st,raw);return}t=u.value}
  if(/^(?:help|--help|-h|\?)$/i.test(t)){st.help=true;return}
  if(has(PRESETS,t.toLowerCase())){setPreset(st,t);return}
  const flag=/^(?:--)?(no-)?([A-Za-z][A-Za-z0-9]*)$/i.exec(t),flagOpt=flag&&BY_LOWER.get(flag[2].toLowerCase());
  if(flagOpt&&flagOpt.kind==='boolean'){setGiven(st,flagOpt,!flag[1]);return}
  const asRef=i===0&&rangeOk(t)?`, or range=${t} to review the ref ${t}`:'';
  if(flagOpt&&flag[1]){unrecognized(st,raw,`only a true/false option takes no-; ${flagOpt.name} takes a value`);return}
  if(flagOpt){unrecognized(st,raw,`${flagOpt.name} needs a value: write ${flagOpt.name}=<value>${asRef}`);return}
  const next=tokens[i+1]&&BY_LOWER.get(tokens[i+1].toLowerCase());
  if(/^(?:no|not|without)$/i.test(t)&&next&&next.kind==='boolean'){unrecognized(st,raw,`write no-${next.name} to turn ${next.name} off`);return}
  if(!rangeOk(t)){unrecognized(st,raw);return}
  if(has(st.given,'range')){unrecognized(st,raw,'a range is already given');return}
  const typo=i===0&&!t.includes('..')?nearest(t,1,5):null;
  if(typo){unrecognized(st,raw,`did you mean ${typo}? To review the ref ${t}, write range=${t}`);return}
  if(i===0||t.includes('..')){setGiven(st,BY_NAME.get('range'),t);return}
  unrecognized(st,raw,`a single ref is read as a range only as the first argument; write range=${t} anywhere else`);
}

function resolve(raw){
  if(typeof raw!=='string'||raw.length>MAX_ARGS_LENGTH)return finish({...newState(),errors:[`the arguments must be text of at most ${MAX_ARGS_LENGTH} characters`]});
  const st=newState(),{tokens,error}=tokenize(raw.trim());if(error)st.errors.push(error);
  for(const [i,t] of tokens.entries()){
    const kv=/^(?:--)?([A-Za-z][A-Za-z0-9]*)(?:\.([A-Za-z][A-Za-z0-9]*))?=(.*)$/s.exec(t);
    if(t.startsWith('{'))applyJson(st,t);
    else if(kv)applyKeyValue(st,kv[1],kv[2],kv[3]);
    else applyWord(st,t,i,tokens);
  }
  const effective={...(st.preset?PRESETS[st.preset].options:{}),...st.given};
  for(const k of Object.keys(effective)){const e=checkValue(BY_NAME.get(k),effective[k]);if(e)st.errors.push(e)}
  if(effective.mode==='dynamic'&&!(CONTAINMENTS.includes(effective.containment)&&effective.network===false&&effective.credentials===false))st.errors.push('dynamic mode requires an externally enforced whole-session containment assertion: containment must be sandbox-runtime, container, vm or cloud-session, with network=false and credentials=false');
  return finish({...st,effective});
}

const shellQuote=s=>`'${String(s).replace(/'/g,'\'\\\'\'')}'`;
function finish({errors,unrecognized:words=[],preset=null,help=false,given={},effective={}}){
  const ok=errors.length===0;
  if(!ok)return{version:1,ok,help,errors,unrecognized:words,preset,range:null,args:null,emitRunArgs:null,table:null};
  // Null means not set: the workflow then applies its own default.
  const set=Object.fromEntries(Object.entries(effective).filter(([,v])=>v!==null));
  const range=set.range||null,policyDocs=set.policyDocs||[];
  const args={strictProvenance:true,...set};
  const emitRunArgs=['--emit-run',...(range?['--range',shellQuote(range)]:[]),...policyDocs.flatMap(p=>['--policy-doc',shellQuote(p)])].join(' ');
  const rows=[['scope',range?`change ${range}`:'whole repository',range&&has(given,'range')?'given':''],['preset',preset||'none (workflow defaults)','']];
  for(const [k,v] of Object.entries(set))if(k!=='range')rows.push([k,JSON.stringify(v),has(given,k)?'given':`preset ${preset}`]);
  const table=['| Setting | Value | From |','|---|---|---|',...rows.map(r=>`| ${r.map(cell).join(' | ')} |`)].join('\n')+'\n\nEvery other option keeps its default; `/vuln-hunt:options` lists them.';
  return{version:1,ok,help,errors,unrecognized:words,preset,range,args,emitRunArgs,table};
}

// A Markdown table cell: backslashes first, so an escaped pipe cannot be
// unescaped by a backslash before it.
const cell=s=>String(s).replace(/\\/g,'\\\\').replace(/\|/g,'\\|').replace(/[\r\n]+/g,' ');
function optionsTable(){
  return['| Option | Values | Default | Effect |','|---|---|---|---|',...OPTIONS.map(o=>`| \`${o.name}\` | ${o.values} | ${o.def} | ${o.effect} |`)].join('\n');
}
function presetsTable(){
  const sets=o=>Object.keys(o).length?Object.entries(o).map(([k,v])=>`\`${k}=${typeof v==='string'?v:JSON.stringify(v)}\``).join(', '):'nothing';
  return['| Preset | Sets | Use |','|---|---|---|',...Object.entries(PRESETS).map(([name,p])=>`| \`${name}\` | ${sets(p.options)} | ${p.use} |`)].join('\n');
}
function listText(){
  return[
    '## Passing options to /vuln-hunt:scan','',
    'Options given explicitly win over a preset. A range of two ends can go anywhere; a single ref (`REF`) is read',
    'as a range only as the first argument, or anywhere as `range=REF`.','',
    '- a Git range to review a change: `main...HEAD`, `A..B` or `REF`',
    '- a preset: `quick`, `standard` or `deep`',
    '- `option=value`, such as `hunters=6`, `salvageRisk=all` or `policyDocs=SECURITY.md,docs/threats.md`',
    '- a true/false option by name, or with `no-` to turn it off: `variants`, `no-sweep`',
    '- one field of a map: `models.hunt=opus`, `efforts.verify=xhigh`, `reproEnvironment.backend=vm`',
    '- a JSON object: `{"hunters":5,"variants":true}`',
    '- a value with spaces, or text that starts with [ or {, in quotes: `tag="nightly run"`',
    '- `help`, anywhere, to print this list instead of scanning','',
    'Run `/vuln-hunt:scan` with no arguments to choose the scope, depth and concurrency from a few questions; a',
    'session that cannot ask questions, such as `claude -p`, runs the default strict scan instead.','',
    '## Presets','',presetsTable(),'',
    '## Options','',optionsTable(),'',
    `Stages for \`models\` and \`efforts\`: ${STAGES.map(s=>`\`${s}\``).join(', ')}.`,
    `Fields of \`reproEnvironment\`: ${Object.keys(REPRO_FIELDS).map(s=>`\`${s}\``).join(', ')}; see [Reproduction environment](https://github.com/developingchet/vuln-hunt#reproduction-environment).`,
  ].join('\n');
}

function main(argv){
  const out=s=>process.stdout.write(s.endsWith('\n')?s:`${s}\n`);
  switch(argv[0]){
    case '--resolve':{
      if(argv.length>1)throw new Error('--resolve reads the arguments from stdin and takes no other arguments');
      const r=resolve(fs.readFileSync(0,'utf8'));out(JSON.stringify(r));return r.ok?0:2;
    }
    case '--list':out(listText());return 0;
    case '--table':out(optionsTable());return 0;
    case '--presets-table':out(presetsTable());return 0;
    case '--schema':out(JSON.stringify({version:1,options:OPTIONS,presets:PRESETS,stages:STAGES,reproFields:REPRO_FIELDS}));return 0;
    default:throw new Error('usage: vuln-hunt-options.js --resolve | --list | --table | --presets-table | --schema');
  }
}
module.exports={OPTIONS,PRESETS,STAGES,CONTAINMENTS,REPRO_FIELDS,RUN_ID_RE,RANGE_RE,checkValue,tokenize,resolve,optionsTable,presetsTable,listText};
if(require.main===module){
  try{process.exitCode=main(process.argv.slice(2))}catch(e){process.stderr.write(`vuln-hunt-options: ${e.message}\n`);process.exitCode=1}
}
