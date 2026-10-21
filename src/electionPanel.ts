import { p256 } from '@noble/curves/nist.js';
import { encryptVote, proveZeroOrOne, simulateInvalidProof, verifyZeroOrOne, checkAndSum, openTotal, mul, decodePoint, type CastBallot, type OrChecks, type Ballot } from './election';
import type { DkgResult } from './threshold';
export const ELECTION_NEGATIVE = 'A valid 0-or-1 proof shows the ballot is well formed. It does not stop a voter from proving how she voted: revealing r lets anyone check c1 = rG and c2 − vG = rY, so this construction is not receipt-free.';
export interface ElectionState {
  votes:number[];requireProof:boolean;entries:CastBallot[];randomness:bigint[];checks:OrChecks[];aggregate:Ballot|null;
  accepted:number[];authorities:Set<number>;opened:Awaited<ReturnType<typeof openTotal>>|null;
  receipt:{index:number;vote:number;r:string;first:boolean;second:boolean}|null;
  status:string;busy:boolean;revision:number;detailsOpen:boolean;
}
export const initialElection=():ElectionState=>({votes:[1,0,1,0,1,0,1],requireProof:true,entries:[],randomness:[],checks:[],aggregate:null,accepted:[],authorities:new Set(),opened:null,receipt:null,status:'Run distributed key generation in Exhibit 1 to begin.',busy:false,revision:0,detailsOpen:false});
const esc=(s:unknown)=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const verdict=(ok:boolean,text:string)=>`<span class="meta ${ok?'good':'bad'}">${ok?'✓':'✕'} ${esc(text)}</span>`;
export function electionMarkup(s:ElectionState,dkg:DkgResult|null):string {
  const result=s.opened,expected=s.votes.filter(v=>v===0||v===1).reduce<number>((a,b)=>a+b,0);
  const actual=result?.tally?.value,wrong=actual!==null&&actual!==undefined&&actual!==expected;
  const invalidIncluded=s.accepted.some(i=>!s.checks[i]?.valid);
  const receipt=s.receipt,quorum=s.authorities.size;
  const trace={groupPublicKey:dkg?.groupPublicKeyHex,publicShares:dkg?.partyShares.map(p=>({id:p.id,publicShareHex:p.publicShareHex})),entries:s.entries,checks:s.checks,accepted:s.accepted,aggregate:s.aggregate,opened:s.opened,receipt:s.receipt};
  return `<section id="election" class="panel ${dkg?'':'locked'}" aria-labelledby="election-title">
 <h2 id="election-title">Exhibit 6 — Election Tally</h2>
 <p>Encrypt each yes or no vote, add the encrypted ballots, and ask a quorum to open only the total. No individual ballot is decrypted. A dishonest voter can sneak in two votes or cancel a yes unless the ballot box checks a proof that each encrypted value is zero or one.</p>
 <label class="election-toggle"><input id="election-proof" type="checkbox" ${s.requireProof?'checked':''}> Check every 0-or-1 proof before summing (recommended)</label>
 <p id="election-mode" class="meta ${s.requireProof?'good':'bad'}">${s.requireProof?'Proof checking ON — reject invalid ballots before adding.':'BROKEN BALLOT BOX — sums encrypted votes without requiring a validity proof.'}</p>
 <div class="election-voters" role="group" aria-label="Seven voters">
 ${s.votes.map((v,i)=>`<div class="card"><label for="election-vote-${i}">Voter ${i+1}</label><select id="election-vote-${i}" data-voter="${i}">${[[0,'No: 0'],[1,'Yes: 1'],[2,'Over-vote: 2'],[-1,'Cancel a yes: −1']].map(([value,label])=>`<option value="${value}" ${v===value?'selected':''}>${label}</option>`).join('')}</select><p id="election-proof-${i}" class="meta ${s.checks[i]?.valid?'good':''}" data-state="${!s.checks[i]?'pending':s.checks[i].valid?'pass':'fail'}">${!s.checks[i]?'Not cast':s.checks[i].valid?'✓ Valid 0-or-1 proof':'✕ Proof rejected: '+esc(s.checks[i].reason)}</p>${s.checks[i]?`<p class="meta">Equations: ${[...s.checks[i].firstEquations,...s.checks[i].secondEquations].map(v=>v?'✓':'✕').join(' ')}; challenge sum: ${s.checks[i].challengeMatches?'✓':'✕'}</p>`:''}</div>`).join('')}
 </div>
 <div class="actions"><button id="election-cast" ${!dkg||s.busy?'disabled':''}>Cast all</button><button id="election-tally" ${!s.entries.length||s.busy?'disabled':''}>Tally encrypted ballots</button><button id="election-replay" class="ghost" ${!s.entries.length||s.busy?'disabled':''}>Replay voter 1's ballot as voter 2</button></div>
 <p id="election-status" role="status" aria-live="polite">${esc(s.status)}</p>
 ${s.aggregate?`<div id="election-sum" class="card"><h3>Add ciphertexts, keep ballots closed</h3><p id="election-accepted">${s.accepted.length} of ${s.votes.length} ballots included: ${s.accepted.map(i=>'V'+(i+1)).join(' + ')||'none'}.</p><p>First components add to C1; second components add to C2. The random masks add too, so the total stays encrypted.</p><p class="mono">C1 = ${esc(s.aggregate.c1Hex)}<br>C2 = ${esc(s.aggregate.c2Hex)}</p></div>`:''}
 <div class="chooser" role="group" aria-label="Election tally authorities">${(dkg?.partyShares??[]).map(p=>`<button class="chip ${s.authorities.has(p.id)?'picked':''}" data-election-party="${p.id}" aria-pressed="${s.authorities.has(p.id)}" ${!s.aggregate||s.busy?'disabled':''}>P${p.id}</button>`).join('')}</div>
 ${dkg&&s.aggregate?`<div class="quorum ${quorum>=dkg.threshold?'met':''}"><div class="quorum-bar" role="progressbar" aria-label="Election quorum" aria-valuemin="0" aria-valuemax="${dkg.threshold}" aria-valuenow="${Math.min(quorum,dkg.threshold)}"><span style="width:${Math.min(100,quorum/dkg.threshold*100)}%"></span></div><span class="quorum-label">${quorum} selected · need ${dkg.threshold}</span></div>`:''}
 <div class="actions"><button id="election-open" ${!s.aggregate||s.busy?'disabled':''}>Open the total</button><button id="election-receipt" class="ghost" ${!result?.tally||actual===null||s.busy?'disabled':''}>Show my receipt</button></div>
 ${result?`<div id="election-partials">${result.partials.map((p,i)=>`<p id="election-partial-${p.participantId}" data-state="${result.checks[i].valid?'pass':'fail'}">${verdict(result.checks[i].valid,'P'+p.participantId+' partial: challenge '+result.checks[i].challengeMatches+', first equation '+result.checks[i].firstEquation+', second equation '+result.checks[i].secondEquation)}</p>`).join('')}</div>`:''}
 ${result?.refusal?`<div id="election-result" class="result bad" role="status"><strong>Below threshold — cannot open the total</strong><p>${esc(result.refusal)}</p></div>`:result?.tally?`<div id="election-result" class="result ${actual!==null&&!wrong&&!invalidIncluded?'good':'bad'}" role="status"><strong>${actual===null?'NO TALLY IN RANGE':wrong?'TALLY DECRYPTED — AND WRONG':invalidIncluded?'INVALID BALLOTS COUNTED — numerical cancellation hid the failure':'TOTAL VERIFIED — ballots stayed closed'}</strong><p>Tally: <output id="election-total">${actual===null?'no tally in range':actual}</output>; search bound [0, ${s.votes.length}]; <span id="election-search-steps">${result.tally.steps}</span> point comparisons starting at 0G.</p><p id="election-honest-sum">Honest 0/1 inputs sum to ${expected}. ${wrong?'An invalid vote changed the total, even though the partial-decryption proofs pass.':invalidIncluded?'Invalid votes happened to cancel numerically. A matching number does not make those ballots valid.':'Only the accepted ballot total was opened.'}</p><p class="mono">C2 − combined partials = ${esc(result.point)}${result.point==='00'?' (point at infinity, 0G)':''}</p></div>`:''}
 ${receipt?`<div id="election-receipt-result" class="result ${receipt.first&&receipt.second?'bad':'good'}" role="status"><strong>${receipt.first&&receipt.second?'VALID BALLOT — AND A RECEIPT FOR SALE':'RECEIPT REJECTED'}</strong><p>Voter ${receipt.index+1} reveals vote ${receipt.vote} and randomness r = <span class="mono">${receipt.r}</span>.</p><p id="receipt-first" data-state="${receipt.first?'pass':'fail'}">${verdict(receipt.first,'Public check c1 = rG')}</p><p id="receipt-second" data-state="${receipt.second?'pass':'fail'}">${verdict(receipt.second,'Public check c2 − vG = rY')}</p>${receipt.first&&receipt.second?`<p id="election-negative">${ELECTION_NEGATIVE}</p>`:''}</div>`:''}
 <details id="election-details" ${s.detailsOpen?'open':''}><summary>Inspect ballots, full OR proofs and aggregate partials</summary><pre id="election-trace" tabindex="0" role="region" aria-label="Election cryptographic transcript">${esc(JSON.stringify(trace,null,2))}</pre></details>
 <p class="meta">Helios-style voting uses proofs about the encrypted vote itself. The hash here binds the election, voter, public key, ballot and all commitments: <a href="https://www.iacr.org/archive/asiacrypt2012/76580619/76580619.pdf">Bernhard–Pereira–Warinschi (2012)</a> explain why omitting the statement is dangerous. The <a href="https://crypto.ethz.ch/publications/files/CrGeSc97b.pdf">Cramer–Gennaro–Schoenmakers election scheme (1997, pp. 103–118)</a> uses disjunctive validity proofs and threshold tallying.</p>
 <p class="meta">Compare <a href="https://systemslibrarian.github.io/crypto-lab-paillier-gate/">Paillier Gate</a>: one key holder and a MAC against an outsider. This exhibit addresses a dishonest voter and uses a quorum. Also see <a href="https://systemslibrarian.github.io/crypto-lab-frozen-heart/">Frozen Heart</a> for incomplete Fiat–Shamir transcripts.</p>
 <p class="meta">Not implemented: voter eligibility/authentication, receipt-freeness or coercion resistance, <a href="https://systemslibrarian.github.io/crypto-lab-elgamal-plain/">mix-nets</a>, multi-candidate ballots, or an end-to-end verifiable voting system as a whole. Fresh local teaching keys and votes are never persisted. Do not use this demo to run a real election.</p>
 </section>`;
}
export function bindElection(s:ElectionState,getDkg:()=>DkgResult|null,render:()=>void,isCurrent:()=>boolean):void {
  const retire=(clearBallots=false)=>{s.revision++;s.busy=false;s.aggregate=null;s.accepted=[];s.opened=null;s.receipt=null;if(clearBallots){s.entries=[];s.checks=[];s.randomness=[];}s.status='Previous election verdict retired. '+(clearBallots?'Cast the current votes.':'Tally the current ballots.');};
  document.querySelectorAll<HTMLSelectElement>('[data-voter]').forEach(input=>input.addEventListener('change',()=>{const i=Number(input.dataset.voter),v=Number(input.value);if(v===s.votes[i])return;s.votes[i]=v;retire(true);render();}));
  document.querySelector<HTMLInputElement>('#election-proof')?.addEventListener('change',event=>{const checked=(event.target as HTMLInputElement).checked;if(checked===s.requireProof)return;s.requireProof=checked;retire();render();});
  document.querySelector<HTMLDetailsElement>('#election-details')?.addEventListener('toggle',event=>{s.detailsOpen=(event.target as HTMLDetailsElement).open;});
  document.querySelectorAll<HTMLButtonElement>('[data-election-party]').forEach(button=>button.addEventListener('click',()=>{const id=Number(button.dataset.electionParty);s.authorities.has(id)?s.authorities.delete(id):s.authorities.add(id);s.opened=null;s.receipt=null;s.status='Authority selection changed; previous opening retired.';render();}));
  async function act(action:'cast'|'tally'|'open'|'replay'|'receipt') {
    const dkg=getDkg();if(!dkg||s.busy)return;const token=++s.revision;s.busy=true;s.receipt=null;if(action!=='receipt')s.opened=null;if(action==='cast'||action==='replay'){s.aggregate=null;s.accepted=[];}s.status='Computing real P-256 proofs…';render();
    const current=()=>isCurrent()&&token===s.revision;
    try{
      if(action==='cast'){
        s.aggregate=null;s.opened=null;s.entries=[];s.checks=[];s.randomness=[];
        const electionId=crypto.randomUUID(),votes=[...s.votes],entries:CastBallot[]=[],rs:bigint[]=[],checks:OrChecks[]=[];
        for(let i=0;i<votes.length;i++){const {ballot,r}=encryptVote(dkg.groupPublicKeyHex,votes[i]),context={electionId,voterIndex:i};const proof=votes[i]===0||votes[i]===1?await proveZeroOrOne(dkg.groupPublicKeyHex,ballot,votes[i],r,context):simulateInvalidProof(dkg.groupPublicKeyHex,ballot);entries.push({ballot,proof,context});rs.push(r);checks.push(await verifyZeroOrOne(dkg.groupPublicKeyHex,ballot,proof,context));}
        if(!current())return;s.entries=entries;s.randomness=rs;s.checks=checks;s.authorities=new Set(dkg.partyShares.slice(0,dkg.threshold).map(p=>p.id));s.status='Ballots cast. Invalid voters submit simulated proof equations whose challenge sum fails. Tally to apply the ballot-box policy.';
      }else if(action==='tally'){
        s.opened=null;const sum=await checkAndSum(dkg.groupPublicKeyHex,s.entries,s.requireProof);if(!current())return;s.checks=sum.checks;s.aggregate=sum.aggregate;s.accepted=sum.accepted.map(e=>e.context.voterIndex);s.status=`${s.accepted.length} ballots summed; ${s.entries.length-s.accepted.length} rejected before adding.`;
      }else if(action==='open'){
        const opened=await openTotal(dkg,s.aggregate!,[...s.authorities],s.votes.length);if(!current())return;s.opened=opened;s.status=opened.refusal??(opened.tally!.value===null?'No tally in range; the bound was not widened or clamped.':'Only the aggregate was opened; every contributing partial passed its proof.');
      }else if(action==='replay'){
        const copied=structuredClone(s.entries[0]);copied.context={...copied.context,voterIndex:1};s.entries[1]=copied;s.randomness[1]=s.randomness[0];s.aggregate=null;s.opened=null;s.accepted=[];
        const checks=await Promise.all(s.entries.map(e=>verifyZeroOrOne(dkg.groupPublicKeyHex,e.ballot,e.proof,e.context)));if(!current())return;s.checks=checks;s.status='Voter 1’s exact ballot and proof replayed as voter 2. The changed voter index must fail the challenge-sum check.';
      }else{
        const index=s.accepted.find(i=>s.checks[i].valid&&(s.votes[i]===0||s.votes[i]===1));if(index===undefined)throw Error('Choose an accepted honest ballot before revealing a receipt.');
        const ballot=s.entries[index].ballot,r=s.randomness[index],v=s.votes[index];s.receipt={index,vote:v,r:r.toString(16).padStart(64,'0'),first:mul(p256.Point.BASE,r).equals(decodePoint(ballot.c1Hex)),second:decodePoint(ballot.c2Hex).subtract(mul(p256.Point.BASE,BigInt(v))).equals(mul(decodePoint(dkg.groupPublicKeyHex),r))};
        s.status='Receipt checked publicly from the revealed randomness; no ballot decryption was requested.';
      }
    }catch(error){if(current())s.status=error instanceof Error?error.message:String(error);}
    finally{if(current()){s.busy=false;render();}}
  }
  for(const action of ['cast','tally','open','replay','receipt'] as const)document.getElementById('election-'+action)?.addEventListener('click',()=>{void act(action);});
}
