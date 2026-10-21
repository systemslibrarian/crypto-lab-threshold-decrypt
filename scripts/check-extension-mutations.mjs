// Concrete source mutations: baseline, built mutant, named failure, exact restoration.
import {readFileSync,writeFileSync,rmSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const cases=[
  {
    "name": "M1 verifier skips the challenge-sum check",
    "file": "src/election.ts",
    "anchor": "const challengeMatches=modN(cs[0]+cs[1])===await challenge(Y,ballot,proof.branches,ctx);",
    "replacement": "const challengeMatches=true || modN(cs[0]+cs[1])===await challenge(Y,ballot,proof.branches,ctx);",
    "test": "Exhibit 6: invalid vote 2"
  },
  {
    "name": "M2 voter index omitted from Fiat-Shamir transcript",
    "file": "src/election.ts",
    "anchor": "ctx.electionId,ctx.voterIndex,encodePoint(G)",
    "replacement": "ctx.electionId,encodePoint(G)",
    "test": "Exhibit 6: voter-index replay"
  },
  {
    "name": "M3 bounded search starts at G instead of infinity",
    "file": "src/election.ts",
    "anchor": "let candidate=ZERO;",
    "replacement": "let candidate=G;",
    "test": "Exhibit 6: zero and out-of-range"
  },
  {
    "name": "M4 invalid ballots summed before proof filtering",
    "file": "src/election.ts",
    "anchor": "aggregate:addBallots(accepted.map(e=>e.ballot))",
    "replacement": "aggregate:addBallots(entries.map(e=>e.ballot))",
    "test": "Exhibit 6: invalid vote 2"
  },
  {
    "name": "receipt negative claim removed",
    "file": "src/electionPanel.ts",
    "anchor": "export const ELECTION_NEGATIVE = 'A valid 0-or-1 proof shows the ballot is well formed. It does not stop a voter from proving how she voted: revealing r lets anyone check c1 = rG and c2 \u2212 vG = rY, so this construction is not receipt-free.';",
    "replacement": "export const ELECTION_NEGATIVE = '';",
    "test": "Exhibit 6: honest tally and receipt"
  },
  {
    "name": "receipt fixture second public equation fails",
    "file": "src/electionPanel.ts",
    "anchor": "second:decodePoint(ballot.c2Hex).subtract",
    "replacement": "second:!decodePoint(ballot.c2Hex).subtract",
    "test": "Exhibit 6: honest tally and receipt"
  }
];
const run=(command,args,extra={})=>{if(command==='npm'&&args[0]==='run'&&args[1]==='build')rmSync('dist',{recursive:true,force:true});const r=spawnSync(command,args,{encoding:'utf8',timeout:120000,env:{...process.env,CI:'1',...extra}});return {status:r.status,output:(r.stdout??'')+'\n'+(r.stderr??'')};};
function requirePass(r,label){if(r.status!==0)throw new Error(label+'\n'+r.output);}
// Hash the emitted entry and its referenced files. An unreferenced old artifact
// is not evidence of what a browser loaded; the owning test also checks module URLs.
const digest=data=>createHash('sha256').update(data).digest('hex');
function emitted(){const html=readFileSync('dist/index.html','utf8');const names=[...new Set([...html.matchAll(/\/assets\/([^"'\s]+\.(?:js|css))/g)].map(m=>m[1]))].sort();if(!names.some(n=>n.endsWith('.js')))throw new Error('No emitted JavaScript entry');return names;}
function assets(){return Object.fromEntries(emitted().filter(f=>f.endsWith('.js')).map(f=>[f,digest(readFileSync('dist/assets/'+f))]));}
const hash=()=>digest(JSON.stringify({'index.html':digest(readFileSync('dist/index.html')),...Object.fromEntries(emitted().map(f=>['assets/'+f,digest(readFileSync('dist/assets/'+f))]))}));
function owning(e){return run('npx',['playwright','test',...(process.env.PLAYWRIGHT_CONFIG?['--config',process.env.PLAYWRIGHT_CONFIG]:[]),'--project=chromium','e2e/claims.spec.ts','--grep',e.test,'--retries=0'],{MUTATION_ASSETS:JSON.stringify(assets())});}
const records=[];
for(const e of cases){
 const source=readFileSync(e.file,'utf8');if(source.split(e.anchor).length!==2)throw new Error(e.name+': ambiguous anchor');
 requirePass(run('npm',['run','build']),e.name+' baseline build');const baseline=hash(),before=owning(e);requirePass(before,e.name+' baseline test');if(!/1 passed/.test(before.output))throw new Error('Owning test did not run exactly once');
 let mutant='',sourceDiff='',failure,restoredGreen=false;
 try{
  writeFileSync(e.file,source.replace(e.anchor,e.replacement));sourceDiff=run('git',['diff','--',e.file]).output.trim();if(!sourceDiff)throw new Error('No source patch');
  requirePass(run('npm',['run','build']),e.name+' mutant build');mutant=hash();if(mutant===baseline)throw new Error('Mutation did not change build');failure=owning(e);
 }finally{
  writeFileSync(e.file,source);requirePass(run('npm',['run','build']),e.name+' restore build');if(hash()!==baseline)throw new Error('Build not byte-exact restored');
  const restored=owning(e);requirePass(restored,e.name+' restored test');restoredGreen=/1 passed/.test(restored.output);if(hash()!==baseline||readFileSync(e.file,'utf8')!==source)throw new Error('Restored owner changed source or build');
 }
 const assertionFailure=failure.status!==0&&/AssertionError|Error: expect\(|expect\(received\)|expect\(locator\)\.[A-Za-z]+\(expected\) failed/.test(failure.output)&&failure.output.includes(e.test)&&!failure.output.includes('MUTATION_ASSET_MISMATCH')&&!failure.output.includes('Process from config.webServer');
 if(!assertionFailure||!restoredGreen)throw new Error(e.name+' did not fail a named assertion\n'+failure.output);
 records.push({name:e.name,sourceDiff,baseline,mutant,owningTest:e.test,unit:!!e.unit,baselinePassed:true,mutantBuilt:true,assertionFailure,retries:0,servedAssetGuard:!e.unit,loadedModuleGuard:true,restoredGreen,restoredHash:hash(),failureEvidence:failure.output.slice(0,4500)});
 writeFileSync('mutation-evidence.json',JSON.stringify(records,null,2)+'\n');
 console.log(e.name+': killed; exact build restored; owning test green');
}
writeFileSync('mutation-evidence.json',JSON.stringify(records,null,2)+'\n');
