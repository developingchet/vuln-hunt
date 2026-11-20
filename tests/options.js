'use strict';
// Tests for vuln-hunt-options.js: argument resolution for /vuln-hunt:scan,
// agreement with the workflow's own validator, and the tables README.md shows.
// Run by tests/run.js; also runnable on its own.
const fs=require('fs'),path=require('path');
const {spawnSync}=require('child_process');
const root=path.resolve(__dirname,'..'),modulePath=path.join(root,'vuln-hunt-options.js'),workflow=path.join(root,'vuln-hunt.js');
const O=require(modulePath);

function check(name,cond,detail){if(!cond)throw new Error(`${name}: ${typeof detail==='function'?detail():detail??''}`);console.log(`${name}: PASS`)}
const args=raw=>O.resolve(raw);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sorted=xs=>[...xs].sort();

function workflowSource(){return fs.readFileSync(workflow,'utf8')}
function literal(src,re,what){const m=re.exec(src);if(!m)throw new Error(`${what} not found in vuln-hunt.js`);return m[1]}

function schemaTests(){
  const src=workflowSource();
  const list=name=>JSON.parse(literal(src,new RegExp(`const ${name}=(\\[[^\\]]*\\])`),name));
  check('options-schema-names-the-workflow-options',same(sorted(list('ARG_KEYS')),sorted(O.OPTIONS.map(o=>o.name))),()=>`${list('ARG_KEYS')} vs ${O.OPTIONS.map(o=>o.name)}`);
  check('options-schema-booleans-match-the-workflow',same(sorted(list('BOOL_ARGS')),sorted(O.OPTIONS.filter(o=>o.kind==='boolean').map(o=>o.name))));
  check('options-schema-stages-match-the-workflow',same(list('STAGE_KEYS'),O.STAGES));
  const containments=JSON.parse(literal(src,/const containments=new Set\((\[[^\]]*\])\)/,'containments'));
  check('options-schema-containments-match-the-workflow',same(containments,O.CONTAINMENTS));
  check('options-run-id-pattern-matches-the-workflow',literal(src,/const RUN_ID_RE=(\/.*\/i?);/,'RUN_ID_RE')===String(O.RUN_ID_RE));
  check('options-range-pattern-matches-the-workflow',literal(src,/const RANGE_RE=(\/.*\/);/,'RANGE_RE')===String(O.RANGE_RE));
  for(const [name,p] of Object.entries(O.PRESETS)){
    const bad=Object.entries(p.options).map(([k,v])=>{const opt=O.OPTIONS.find(o=>o.name===k);return !opt?`${k} unknown`:opt.scan===false?`${k} not settable`:O.checkValue(opt,v)}).filter(Boolean);
    check(`preset-${name}-holds-valid-scan-options`,!bad.length,()=>bad.join('; '));
  }
}

// Values each option kind is probed with; the workflow and the schema must
// accept and refuse exactly the same ones.
function probes(opt){
  const common=[null,'x',1.5,-1,0,true,{},[]];
  switch(opt.kind){
    case 'boolean':return[...common,false,'true',1];
    case 'integer':return[...common,opt.min,opt.max,opt.min-1,opt.max+1,...(opt.also||[]),'auto','4'];
    case 'enum':return[...common,...opt.choices,opt.choices[0].toUpperCase(),'nope'];
    case 'string':return[...common,'a','',' spaced '];
    case 'runId':return[...common,'run-1','con','com1.txt','a.','..','-a_b.c',''];
    case 'paths':return[...common,['SECURITY.md'],['docs/a.md','docs/b.md'],['a.md','A.md'],['../x'],['/x'],['C:/x'],['a\\b'],Array.from({length:9},(_,i)=>`d${i}.md`),[''],[1]];
    case 'stageMap':return[...common,{hunt:'opus'},{default:'sonnet',verifyImpact:'high'},{nope:'x'},{hunt:''},{hunt:1}];
    // The workflow checks reproEnvironment's fields itself, so only whole
    // values whose shape both sides judge alike are probed.
    case 'object':return opt.name==='reproEnvironment'?[null,'x',1,true,[],{backend:'vm'}]:[...common,{version:5}];
    case 'range':return[null,'main','main...HEAD','a..b','HEAD@{1}..HEAD','a..b..c','-x','a b','',1,{}];
    default:throw new Error(`no probes for ${opt.kind}`);
  }
}
async function agreementTests(){
  const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
  const runRaw=new AsyncFunction('args','agent','parallel','pipeline','phase','log',workflowSource().replace(/^export const meta=.*?\};\s*/s,''));
  const settle=f=>Promise.resolve().then(f).catch(()=>null),parallel=t=>Promise.all(t.map(settle)),pipeline=(xs,f)=>Promise.all(xs.map((x,i)=>settle(()=>f(x,i)))),phase=()=>{},log=()=>{};
  // Option errors are the ones argError reports, and the range pattern check
  // that follows it; any later refusal is about the run, not the value.
  const refused=r=>/^(invalid workflow args|range must be)/.test(String(r&&r.error||''));
  const disagreements=[];
  for(const opt of O.OPTIONS)for(const value of probes(opt)){
    const schemaOk=O.checkValue(opt,value)===null;
    const r=await runRaw({[opt.name]:value},async()=>null,parallel,pipeline,phase,log);
    if(schemaOk===refused(r))disagreements.push(`${opt.name}=${JSON.stringify(value)}: schema ${schemaOk?'accepts':'refuses'}, workflow ${refused(r)?'refuses':'accepts'} (${r&&r.error})`);
  }
  check('options-schema-and-workflow-accept-the-same-values',!disagreements.length,()=>disagreements.join('\n'));
}

function resolveTests(){
  let r=args('');
  check('resolve-no-arguments-is-a-default-strict-scan',r.ok&&same(r.args,{strictProvenance:true})&&r.emitRunArgs==='--emit-run'&&r.range===null);
  r=args('main...HEAD deep hunters=3 variants=false');
  check('resolve-given-options-override-the-preset',r.ok&&r.preset==='deep'&&r.args.hunters===3&&r.args.variants===false&&r.args.candidateCap===5&&r.args.salvageRisk==='all'&&r.args.range==='main...HEAD'&&r.emitRunArgs==='--emit-run --range \'main...HEAD\''&&/\| hunters \| 3 \| given \|/.test(r.table)&&/\| candidateCap \| 5 \| preset deep \|/.test(r.table),()=>JSON.stringify(r));
  r=args('{"hunters":5, "variants":true} no-sweep tag="nightly run" salvageRisk=MEDIUM maxConcurrentAgents=8');
  check('resolve-mixes-json-flags-and-key-values',r.ok&&same(r.args,{strictProvenance:true,hunters:5,variants:true,sweep:false,tag:'nightly run',salvageRisk:'medium',maxConcurrentAgents:8}),()=>JSON.stringify(r));
  r=args('models.hunt=opus models.verify=sonnet efforts.verify=xhigh hunters=auto adjudicate=no');
  check('resolve-builds-stage-maps-field-by-field',r.ok&&same(r.args.models,{hunt:'opus',verify:'sonnet'})&&same(r.args.efforts,{verify:'xhigh'})&&r.args.hunters==='auto'&&r.args.adjudicate===false,()=>JSON.stringify(r));
  r=args('policyDocs=SECURITY.md,docs/it\'s.md');
  check('resolve-quotes-policy-documents-for-the-shell',r.ok&&same(r.args.policyDocs,['SECURITY.md','docs/it\'s.md'])&&r.emitRunArgs==='--emit-run --policy-doc \'SECURITY.md\' --policy-doc \'docs/it\'\\\'\'s.md\'',()=>JSON.stringify(r));
  r=args('reproEnvironment.backend=container reproEnvironment.image=img@sha256:abc reproEnvironment.timeoutMs=60000 mode=dynamic containment=vm network=false credentials=false');
  check('resolve-builds-object-fields-and-accepts-contained-dynamic-mode',r.ok&&same(r.args.reproEnvironment,{backend:'container',image:'img@sha256:abc',timeoutMs:60000})&&r.args.mode==='dynamic',()=>JSON.stringify(r));
  r=args('mode=dynamic containment=vm');
  check('resolve-refuses-uncontained-dynamic-mode',!r.ok&&r.args===null&&r.errors.some(e=>/dynamic mode requires/.test(e)));
  for(const [name,raw,pattern] of [
    ['resolve-refuses-two-presets','deep quick',/only one preset/],
    ['resolve-refuses-an-unknown-preset','preset=fast',/unknown preset "fast"/],
    ['resolve-refuses-an-unknown-option','huntres=4',/unknown option "huntres"/],
    ['resolve-refuses-a-repeated-option','hunters=3 {"hunters":4}',/hunters is given more than once/],
    ['resolve-refuses-a-repeated-stage','models.hunt=a models.hunt=b',/models.hunt is given more than once/],
    ['resolve-refuses-out-of-range-values','hunters=9',/hunters must be an integer from 2 to 6/],
    ['resolve-refuses-the-attestation','{"attestation":{}}',/attestation cannot be set here/],
    ['resolve-refuses-strict-provenance','strictProvenance=false',/strictProvenance cannot be set here/],
    ['resolve-refuses-run-id','runId=r1',/runId cannot be set here/],
    ['resolve-refuses-non-strict-overrides','allowSparse',/allowSparse cannot be set here/],
    ['resolve-refuses-a-map-without-json','models=opus',/models takes a JSON object/],
    ['resolve-refuses-a-field-of-a-scalar','hunters.max=3',/hunters has no fields/],
    ['resolve-refuses-invalid-json','{"hunters":}',/not valid JSON/],
    ['resolve-refuses-an-unclosed-quote','tag="open',/unclosed quote/],
    ['resolve-refuses-a-malformed-range','a..b..c',/unrecognized argument "a..b..c"/],
    ['resolve-refuses-a-null-boolean','{"variants":null}',/variants cannot be null/],
  ]){const x=args(raw);check(name,!x.ok&&x.args===null&&x.errors.some(e=>pattern.test(e)),()=>JSON.stringify(x.errors))}
  r=args('please run a deep scan with variants');
  check('resolve-reports-the-words-of-a-sentence',!r.ok&&same(r.unrecognized,['run','a','scan','with']),()=>JSON.stringify(r));
  r=args('tag="a\\\\|b|c"');
  const row=r.ok&&r.table.split('\n').find(l=>l.startsWith('| tag |'));
  check('resolve-table-escapes-backslashes-and-pipes',r.ok&&r.args.tag==='a\\|b|c'&&row==='| tag | "a\\\\\\\\\\|b\\|c" | given |',()=>`${JSON.stringify(r.args)} ${row}`);
  r=args('help');
  check('resolve-recognizes-help',r.help===true);
  r=args('{"tag":null,"policyDocs":null}');
  check('resolve-treats-null-as-not-set',r.ok&&same(r.args,{strictProvenance:true}),()=>JSON.stringify(r));
  r=args('x'.repeat(70000));
  check('resolve-bounds-the-argument-text',!r.ok&&/at most 65536/.test(r.errors[0]));
}

function cliTests(){
  const run=(argv,input)=>spawnSync(process.execPath,[modulePath,...argv],{input,encoding:'utf8'});
  let r=run(['--resolve'],'main...HEAD quick\n');
  const j=r.status===0?JSON.parse(r.stdout):null;
  check('cli-resolve-reads-stdin',j&&j.ok&&j.preset==='quick'&&j.range==='main...HEAD',()=>`${r.status} ${r.stdout}${r.stderr}`);
  r=run(['--resolve'],'hunters=1');
  check('cli-resolve-exits-2-on-refused-arguments',r.status===2&&JSON.parse(r.stdout).ok===false,()=>`${r.status} ${r.stdout}`);
  r=run(['--resolve','hunters=4'],'');
  check('cli-resolve-takes-no-arguments',r.status===1&&/reads the arguments from stdin/.test(r.stderr));
  r=run(['--list']);
  check('cli-list-names-every-option-and-preset',r.status===0&&O.OPTIONS.every(o=>r.stdout.includes(`\`${o.name}\``))&&Object.keys(O.PRESETS).every(p=>r.stdout.includes(`\`${p}\``)));
  r=run(['--schema']);
  check('cli-schema-is-json',r.status===0&&JSON.parse(r.stdout).options.length===O.OPTIONS.length);
  r=run(['--bogus']);
  check('cli-refuses-unknown-modes',r.status===1&&/usage/.test(r.stderr));
}

function docTests(){
  const readme=fs.readFileSync(path.join(root,'README.md'),'utf8');
  const block=name=>{const m=new RegExp(`<!-- ${name}:start -->\\n([\\s\\S]*?)\\n<!-- ${name}:end -->`).exec(readme);return m?m[1]:null};
  check('readme-options-table-is-generated',block('vuln-hunt-options')===O.optionsTable(),'regenerate it with node vuln-hunt-options.js --table');
  check('readme-presets-table-is-generated',block('vuln-hunt-presets')===O.presetsTable(),'regenerate it with node vuln-hunt-options.js --presets-table');
  const scan=fs.readFileSync(path.join(root,'skills','scan','SKILL.md'),'utf8'),opts=fs.readFileSync(path.join(root,'skills','options','SKILL.md'),'utf8');
  check('scan-skill-resolves-arguments-with-the-module',scan.includes('"${CLAUDE_PLUGIN_ROOT}/vuln-hunt-options.js" --resolve')&&scan.includes('  - Bash(node "${CLAUDE_PLUGIN_ROOT}/vuln-hunt-options.js":*)')&&/^name: scan$/m.test(scan));
  check('scan-skill-offers-every-preset',Object.keys(O.PRESETS).every(p=>scan.includes(`\`${p}\``)));
  check('options-skill-prints-the-list',opts.includes('"${CLAUDE_PLUGIN_ROOT}/vuln-hunt-options.js" --list')&&/^name: options$/m.test(opts));
  const installer=fs.readFileSync(path.join(root,'Install-VulnHunt.ps1'),'utf8');
  check('installer-ships-the-options-module',/Join-Path \$PSScriptRoot 'vuln-hunt-options\.js'/.test(installer)&&/Copy-Item -LiteralPath \$optionsSrc/.test(installer));
}

async function optionsTests(){schemaTests();await agreementTests();resolveTests();cliTests();docTests()}
module.exports={optionsTests};
if(require.main===module)optionsTests().then(()=>console.log('OPTIONS TESTS PASSED')).catch(e=>{console.error(e.stack||e);process.exit(1)});
