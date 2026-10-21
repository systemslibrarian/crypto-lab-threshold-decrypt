/// <reference types="node" />
import { expect, test } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import { createHash } from 'node:crypto';
import { encryptVote, proveZeroOrOne, verifyZeroOrOne, simulateInvalidProof, checkAndSum, addBallots, recoverSmallTally, openTotal, decodePoint, encodePoint } from './election';
import { runDistributedKeyGeneration } from './threshold';

// Independent verifier: direct noble points and Node SHA-256, no app hash,
// scalar, point-encoding or verification helpers supply the expected result.
const G=p256.Point.BASE,Z=p256.Point.ZERO,Q=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const mod=(x:bigint)=>(x%Q+Q)%Q;
const point=(s:string)=>s==='00'?Z:p256.Point.fromHex(s);
const enc=(p:InstanceType<typeof p256.Point>)=>p.equals(Z)?'00':p.toHex(true);
const times=(p:InstanceType<typeof p256.Point>,n:bigint)=>mod(n)===0n?Z:p.multiply(mod(n));
function independentlyVerify(Y:string,b:{c1Hex:string;c2Hex:string},proof:{branches:{aHex:string;bHex:string;cHex:string;zHex:string}[]},ctx:{electionId:string;voterIndex:number}){
  const branches=proof.branches;if(branches.length!==2)return false;
  const transcript=['threshold-decrypt-cds-or-v1',ctx.electionId,ctx.voterIndex,enc(G),enc(point(Y)),enc(point(b.c1Hex)),enc(point(b.c2Hex)),...branches.flatMap(a=>[enc(point(a.aHex)),enc(point(a.bHex))])];
  const hash=mod(BigInt('0x'+createHash('sha256').update(JSON.stringify(transcript)).digest('hex')));
  const cs=branches.map(a=>BigInt('0x'+a.cHex));
  if(cs.some(c=>c>=Q)||mod(cs[0]+cs[1])!==hash)return false;
  return branches.every((a,i)=>{const z=BigInt('0x'+a.zHex),c=cs[i];return z<Q&&times(G,z).equals(point(a.aHex).add(times(point(b.c1Hex),c)))&&times(point(Y),z).equals(point(a.bHex).add(times(point(b.c2Hex).subtract(times(G,BigInt(i))),c)));});
}
const Y=G.multiply(12345n).toHex(true),ctx={electionId:'election-unit',voterIndex:1};
for(const v of [0,1])test(`honest vote ${v}: all five OR checks agree with independent verifier`,async()=>{
  for(let i=0;i<20;i++){const {ballot,r}=encryptVote(Y,v);const proof=await proveZeroOrOne(Y,ballot,v,r,ctx),checks=await verifyZeroOrOne(Y,ballot,proof,ctx);expect(checks.valid).toBe(true);expect(checks.challengeMatches).toBe(true);expect(checks.firstEquations).toEqual([true,true]);expect(checks.secondEquations).toEqual([true,true]);expect(independentlyVerify(Y,ballot,proof,ctx)).toBe(checks.valid);}
},30_000);
for(const v of [2,-1])test(`invalid vote ${v}: honest prover refuses; fully simulated forgery fails challenge`,async()=>{
  const {ballot,r}=encryptVote(Y,v);await expect(proveZeroOrOne(Y,ballot,v,r,ctx)).rejects.toThrow('Only 0 or 1');
  const fake=simulateInvalidProof(Y,ballot),checks=await verifyZeroOrOne(Y,ballot,fake,ctx);expect(checks.firstEquations).toEqual([true,true]);expect(checks.secondEquations).toEqual([true,true]);expect(checks.challengeMatches).toBe(false);expect(checks.valid).toBe(false);expect(independentlyVerify(Y,ballot,fake,ctx)).toBe(false);
});
test('voter-index and election-id replay fail the challenge-sum check',async()=>{
  const {ballot,r}=encryptVote(Y,1),proof=await proveZeroOrOne(Y,ballot,1,r,ctx);
  for(const other of [{...ctx,voterIndex:2},{...ctx,electionId:'other-election'}]){const c=await verifyZeroOrOne(Y,ballot,proof,other);expect(c.challengeMatches).toBe(false);expect(c.valid).toBe(false);expect(independentlyVerify(Y,ballot,proof,other)).toBe(false);}
});
test('all-zero tally includes infinity, and bounded search never clamps out-of-range totals',()=>{
  expect(recoverSmallTally(Z,7)).toEqual({value:0,steps:1});expect(recoverSmallTally(G.multiply(7n),7)).toEqual({value:7,steps:8});expect(recoverSmallTally(G.multiply(8n),7)).toEqual({value:null,steps:8});expect(recoverSmallTally(G.negate(),7)).toEqual({value:null,steps:8});
  expect(encodePoint(Z)).toBe('00');expect(decodePoint('00').equals(Z)).toBe(true);
});
test('random threshold elections open only the aggregate and equal the plaintext sum',async()=>{
  for(let run=0;run<20;run++){
    const dkg=runDistributedKeyGeneration({participants:5,threshold:3}),votes=Array.from({length:7},()=>run===0?0:crypto.getRandomValues(new Uint8Array(1))[0]%2),entries=[];
    for(let i=0;i<votes.length;i++){const {ballot,r}=encryptVote(dkg.groupPublicKeyHex,votes[i]),context={electionId:'random-'+run,voterIndex:i};entries.push({ballot,proof:await proveZeroOrOne(dkg.groupPublicKeyHex,ballot,votes[i],r,context),context});}
    const sum=await checkAndSum(dkg.groupPublicKeyHex,entries),opened=await openTotal(dkg,sum.aggregate,[1,3,5],7);expect(sum.accepted.length).toBe(7);expect(opened.checks.every(c=>c.valid)).toBe(true);expect(opened.tally!.value).toBe(votes.reduce((a,b)=>a+b,0));
    for(const entry of entries)expect(independentlyVerify(dkg.groupPublicKeyHex,entry.ballot,entry.proof,entry.context)).toBe(true);
    const direct=point(sum.aggregate.c2Hex).subtract(point(opened.combined!));expect(direct.equals(times(G,BigInt(votes.reduce((a,b)=>a+b,0))))).toBe(true);
  }
},60_000);
test('proof checking removes the over-voter before summing; broken mode counts it',async()=>{
  const dkg=runDistributedKeyGeneration({participants:3,threshold:2}),votes=[1,2,0],entries=[];
  for(let i=0;i<votes.length;i++){const {ballot,r}=encryptVote(dkg.groupPublicKeyHex,votes[i]),context={...ctx,voterIndex:i};entries.push({ballot,proof:votes[i]===2?simulateInvalidProof(dkg.groupPublicKeyHex,ballot):await proveZeroOrOne(dkg.groupPublicKeyHex,ballot,votes[i],r,context),context});}
  const good=await checkAndSum(dkg.groupPublicKeyHex,entries,true),bad=await checkAndSum(dkg.groupPublicKeyHex,entries,false);expect(good.accepted).toHaveLength(2);expect(bad.accepted).toHaveLength(3);
  expect((await openTotal(dkg,good.aggregate,[1,2],3)).tally!.value).toBe(1);expect((await openTotal(dkg,bad.aggregate,[1,2],3)).tally!.value).toBe(3);
  expect((await openTotal(dkg,good.aggregate,[1],3)).refusal).toContain('need at least 2');
});
test('receipt uses the original randomness and only public equations',async()=>{
  const {ballot,r}=encryptVote(Y,1),proof=await proveZeroOrOne(Y,ballot,1,r,ctx);expect(independentlyVerify(Y,ballot,proof,ctx)).toBe(true);
  expect(times(G,r).equals(point(ballot.c1Hex))).toBe(true);expect(point(ballot.c2Hex).subtract(G).equals(times(point(Y),r))).toBe(true);expect(point(ballot.c2Hex).equals(times(point(Y),r))).toBe(false);
});
test('zero-valued proof targets, noncanonical scalars and malformed points fail closed',async()=>{
  const {ballot,r}=encryptVote(enc(G),0,1n),proof=await proveZeroOrOne(enc(G),ballot,0,r,ctx);expect((await verifyZeroOrOne(enc(G),ballot,proof,ctx)).valid).toBe(true);
  const noncanonical=structuredClone(proof);noncanonical.branches[0].cHex=Q.toString(16);expect((await verifyZeroOrOne(enc(G),ballot,noncanonical,ctx)).valid).toBe(false);
  expect((await verifyZeroOrOne(Y,{...ballot,c1Hex:'zz'},proof,ctx)).valid).toBe(false);expect(()=>addBallots([{c1Hex:'zz',c2Hex:'00'}])).toThrow();
});
