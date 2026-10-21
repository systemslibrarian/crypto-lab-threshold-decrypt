/** Exponential ElGamal and CDS disjunctive Chaum–Pedersen over P-256.
 * Only the aggregate is threshold-decrypted. This is not a complete voting system. */
import { p256 } from '@noble/curves/nist.js';
import { P256_GROUP_ORDER, modN, randomScalar, createPartialDecryptionWithProof, checkPartialDecryption, type PartialDecryption, type ChaumPedersenChecks } from './elgamal';
import { combinePartialDecryptions, type DkgResult } from './threshold';
export type Point = InstanceType<typeof p256.Point>;
const G=p256.Point.BASE,ZERO=p256.Point.ZERO;
export const encodePoint=(p:Point):string=>p.equals(ZERO)?'00':p.toHex(true);
export const decodePoint=(s:string):Point=>s==='00'?ZERO:p256.Point.fromHex(s);
export const mul=(p:Point,s:bigint):Point=>modN(s)===0n?ZERO:p.multiply(modN(s));
const scalarHex=(n:bigint)=>modN(n).toString(16).padStart(64,'0');
const parseScalar=(s:string)=>{if(!/^[0-9a-f]{64}$/.test(s))throw Error('Malformed scalar');const n=BigInt('0x'+s);if(n>=P256_GROUP_ORDER)throw Error('Noncanonical scalar');return n;};
export interface Ballot { c1Hex:string;c2Hex:string }
export interface ElectionContext { electionId:string;voterIndex:number }
export interface OrBranch { aHex:string;bHex:string;cHex:string;zHex:string }
export interface OrProof { branches:[OrBranch,OrBranch] }
export interface OrChecks { challengeMatches:boolean;firstEquations:[boolean,boolean];secondEquations:[boolean,boolean];valid:boolean;reason:string }
export interface CastBallot { ballot:Ballot;proof:OrProof;context:ElectionContext }
function statement(Y:string,ballot:Ballot){const publicKey=decodePoint(Y),c1=decodePoint(ballot.c1Hex),c2=decodePoint(ballot.c2Hex);if(publicKey.equals(ZERO)||c1.equals(ZERO))throw Error('Public key and individual ballot c1 must not be infinity');return{publicKey,c1,c2};}
async function challenge(Y:string,ballot:Ballot,branches:[OrBranch,OrBranch],ctx:ElectionContext):Promise<bigint>{
  if(!ctx.electionId||ctx.electionId.length>128||!Number.isSafeInteger(ctx.voterIndex)||ctx.voterIndex<0)throw Error('Invalid election context');
  // Canonical JSON array: unambiguous lengths, complete statement, and both
  // commitments for both branches. Never hash only the prover's commitments.
  const transcript=['threshold-decrypt-cds-or-v1',ctx.electionId,ctx.voterIndex,encodePoint(G),encodePoint(decodePoint(Y)),encodePoint(decodePoint(ballot.c1Hex)),encodePoint(decodePoint(ballot.c2Hex)),...branches.flatMap(b=>[encodePoint(decodePoint(b.aHex)),encodePoint(decodePoint(b.bHex))])];
  const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(transcript))));
  return modN(BigInt('0x'+Array.from(hash,b=>b.toString(16).padStart(2,'0')).join('')));
}
export function encryptVote(Y:string,v:number,r=randomScalar()):{ballot:Ballot;r:bigint}{
  if(!Number.isSafeInteger(v)||r<=0n||r>=P256_GROUP_ORDER)throw Error('Invalid vote or randomness');
  const publicKey=decodePoint(Y);if(publicKey.equals(ZERO))throw Error('Invalid group key');
  return{ballot:{c1Hex:encodePoint(mul(G,r)),c2Hex:encodePoint(mul(G,BigInt(v)).add(mul(publicKey,r)))},r};
}
function simulatedBranch(Y:Point,c1:Point,target:Point):OrBranch{
  const c=randomScalar(),z=randomScalar();return{aHex:encodePoint(mul(G,z).subtract(mul(c1,c))),bHex:encodePoint(mul(Y,z).subtract(mul(target,c))),cHex:scalarHex(c),zHex:scalarHex(z)};
}
export async function proveZeroOrOne(Y:string,ballot:Ballot,v:number,r:bigint,ctx:ElectionContext):Promise<OrProof>{
  if(v!==0&&v!==1)throw Error('Only 0 or 1 has an honest ballot proof');
  const s=statement(Y,ballot);
  if(!mul(G,r).equals(s.c1)||!mul(G,BigInt(v)).add(mul(s.publicKey,r)).equals(s.c2))throw Error('Witness does not match ballot');
  const falseIndex=1-v,w=randomScalar(),fake=simulatedBranch(s.publicKey,s.c1,s.c2.subtract(mul(G,BigInt(falseIndex))));
  const real:OrBranch={aHex:encodePoint(mul(G,w)),bHex:encodePoint(mul(s.publicKey,w)),cHex:scalarHex(0n),zHex:scalarHex(0n)};
  const branches:[OrBranch,OrBranch]=v===0?[real,fake]:[fake,real];
  const c=modN(await challenge(Y,ballot,branches,ctx)-parseScalar(fake.cHex));real.cHex=scalarHex(c);real.zHex=scalarHex(w+c*r);
  return{branches};
}
/** Teaching forgery: both equations can be simulated, but the challenge sum
 * will not match the full-statement hash. No ballot validity is asserted here. */
export function simulateInvalidProof(Y:string,ballot:Ballot):OrProof{
  const s=statement(Y,ballot);return{branches:[simulatedBranch(s.publicKey,s.c1,s.c2),simulatedBranch(s.publicKey,s.c1,s.c2.subtract(G))]};
}
export async function verifyZeroOrOne(Y:string,ballot:Ballot,proof:OrProof,ctx:ElectionContext):Promise<OrChecks>{
  try{
    const s=statement(Y,ballot);if(proof.branches.length!==2)throw Error('Expected two OR branches');
    const cs=proof.branches.map(b=>parseScalar(b.cHex));const firstEquations:[boolean,boolean]=[false,false],secondEquations:[boolean,boolean]=[false,false];
    for(let i=0;i<2;i++){const b=proof.branches[i],z=parseScalar(b.zHex);firstEquations[i]=mul(G,z).equals(decodePoint(b.aHex).add(mul(s.c1,cs[i])));secondEquations[i]=mul(s.publicKey,z).equals(decodePoint(b.bHex).add(mul(s.c2.subtract(mul(G,BigInt(i))),cs[i])));}
    const challengeMatches=modN(cs[0]+cs[1])===await challenge(Y,ballot,proof.branches,ctx);
    const valid=challengeMatches&&firstEquations.every(Boolean)&&secondEquations.every(Boolean);
    return{challengeMatches,firstEquations,secondEquations,valid,reason:!challengeMatches?'challenge-sum check failed':!valid?'OR-proof equation failed':'all five checks pass'};
  }catch(error){return{challengeMatches:false,firstEquations:[false,false],secondEquations:[false,false],valid:false,reason:error instanceof Error?error.message:String(error)};}
}
export function addBallots(ballots:Ballot[]):Ballot{
  return{c1Hex:encodePoint(ballots.reduce((p,b)=>p.add(decodePoint(b.c1Hex)),ZERO)),c2Hex:encodePoint(ballots.reduce((p,b)=>p.add(decodePoint(b.c2Hex)),ZERO))};
}
export async function checkAndSum(Y:string,entries:CastBallot[],requireProof=true){
  const checks=await Promise.all(entries.map(e=>verifyZeroOrOne(Y,e.ballot,e.proof,e.context)));
  const accepted=entries.filter((_,i)=>!requireProof||checks[i].valid);
  return{checks,accepted,aggregate:addBallots(accepted.map(e=>e.ballot))};
}
export function recoverSmallTally(point:Point,max:number):{value:number|null;steps:number}{
  if(!Number.isSafeInteger(max)||max<0||max>1000)throw Error('Invalid bounded-search limit');
  let candidate=ZERO;
  for(let i=0;i<=max;i++){if(candidate.equals(point))return{value:i,steps:i+1};candidate=candidate.add(G);}
  return{value:null,steps:max+1};
}
export async function openTotal(dkg:DkgResult,aggregate:Ballot,partyIds:number[],max:number){
  if(aggregate.c1Hex==='00')throw Error('Aggregate c1 is infinity: recast fresh ballots before requesting partials.');
  if(new Set(partyIds).size!==partyIds.length)throw Error('Duplicate authority');
  const partials:PartialDecryption[]=[],checks:ChaumPedersenChecks[]=[];
  for(const id of partyIds){const party=dkg.partyShares.find(p=>p.id===id);if(!party)throw Error('Unknown authority');const partial=await createPartialDecryptionWithProof(id,party.privateShare,party.publicShareHex,aggregate.c1Hex);partials.push(partial);checks.push(await checkPartialDecryption(party.publicShareHex,aggregate.c1Hex,partial));}
  const valid=partials.filter((_,i)=>checks[i].valid);
  if(valid.length<dkg.threshold)return{partials,checks,refusal:`need at least ${dkg.threshold} partial decryptions`,combined:null as string|null,point:null as string|null,tally:null as ReturnType<typeof recoverSmallTally>|null};
  const combined=combinePartialDecryptions(valid,dkg.threshold),point=decodePoint(aggregate.c2Hex).subtract(decodePoint(combined));
  return{partials,checks,refusal:null as string|null,combined,point:encodePoint(point),tally:recoverSmallTally(point,max)};
}
// [extension] point: multi-candidate ballots need one 0/1 proof per option
// PLUS a sum-to-one proof. Benaloh casting audits need a separate challenge flow.
