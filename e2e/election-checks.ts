import { expect, test, type Page } from '@playwright/test';
import { p256 } from '@noble/curves/nist.js';
import { createHash } from 'node:crypto';
// No app implementation imports: expectations are derived from public bytes.
const G=p256.Point.BASE,Z=p256.Point.ZERO,Q=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
type Point=InstanceType<typeof p256.Point>;
type Ballot={c1Hex:string;c2Hex:string};
type Entry={ballot:Ballot;context:{electionId:string;voterIndex:number};proof:{branches:{aHex:string;bHex:string;cHex:string;zHex:string}[]}};
type Partial={participantId:number;sharePointHex:string;proof:{a1Hex:string;a2Hex:string;challengeHex:string;responseHex:string}};
type Checks={challengeMatches:boolean;firstEquations:boolean[];secondEquations:boolean[];valid:boolean};
type Trace={groupPublicKey:string;publicShares:{id:number;publicShareHex:string}[];entries:Entry[];checks:Checks[];accepted:number[];aggregate:Ballot|null;opened:null|{partials:Partial[];checks:{challengeMatches:boolean;firstEquation:boolean;secondEquation:boolean;valid:boolean}[];combined:string|null;point:string|null;tally:{value:number|null;steps:number}|null;refusal:string|null};receipt:null|{index:number;vote:number;r:string;first:boolean;second:boolean}};
const mod=(x:bigint)=>(x%Q+Q)%Q;
const point=(h:string)=>h==='00'?Z:p256.Point.fromHex(h);
const enc=(p:Point)=>p.equals(Z)?'00':p.toHex(true);
const times=(p:Point,n:bigint)=>mod(n)===0n?Z:p.multiply(mod(n));
const scalar=(h:string)=>{expect(h).toMatch(/^[0-9a-f]{64}$/);const n=BigInt('0x'+h);expect(n<Q).toBe(true);return n;};
const hash=(s:string|Buffer)=>mod(BigInt('0x'+createHash('sha256').update(s).digest('hex')));
function invert(n:bigint){let [a,b,x,y]=[mod(n),Q,1n,0n];while(b){const q=a/b;[a,b]=[b,a%b];[x,y]=[y,x-q*y];}expect(a).toBe(1n);return mod(x);}
function lambda(id:number,ids:number[]){return ids.filter(i=>i!==id).reduce((a,j)=>mod(a*BigInt(-j)*invert(BigInt(id-j))),1n);}
function verify(Y:string,e:Entry):Checks{
  const b=e.ballot,branches=e.proof.branches;expect(branches).toHaveLength(2);
  const transcript=['threshold-decrypt-cds-or-v1',e.context.electionId,e.context.voterIndex,enc(G),enc(point(Y)),enc(point(b.c1Hex)),enc(point(b.c2Hex)),...branches.flatMap(x=>[enc(point(x.aHex)),enc(point(x.bHex))])];
  const c=branches.map(x=>scalar(x.cHex)),z=branches.map(x=>scalar(x.zHex));
  const challengeMatches=mod(c[0]+c[1])===hash(JSON.stringify(transcript));
  const firstEquations=branches.map((x,i)=>times(G,z[i]).equals(point(x.aHex).add(times(point(b.c1Hex),c[i]))));
  const secondEquations=branches.map((x,i)=>times(point(Y),z[i]).equals(point(x.bHex).add(times(point(b.c2Hex).subtract(times(G,BigInt(i))),c[i]))));
  return{challengeMatches,firstEquations,secondEquations,valid:challengeMatches&&firstEquations.every(Boolean)&&secondEquations.every(Boolean)};
}
export async function trace(page:Page):Promise<Trace>{return JSON.parse(await page.locator('#election-trace').textContent()??'{}');}
async function assertBallots(page:Page){
  const t=await trace(page);expect(t.entries).toHaveLength(7);
  for(let i=0;i<t.entries.length;i++){const actual=verify(t.groupPublicKey,t.entries[i]);expect(t.checks[i]).toMatchObject(actual);await expect(page.locator('#election-proof-'+i)).toHaveAttribute('data-state',actual.valid?'pass':'fail');}
  return t;
}
async function assertTally(page:Page,value:number|null){
  const t=await assertBallots(page),on=await page.locator('#election-proof').isChecked();
  const included=t.entries.filter((e)=>!on||verify(t.groupPublicKey,e).valid);expect(t.accepted).toEqual(included.map(e=>e.context.voterIndex));
  const aggregate={c1Hex:enc(included.reduce((a,e)=>a.add(point(e.ballot.c1Hex)),Z)),c2Hex:enc(included.reduce((a,e)=>a.add(point(e.ballot.c2Hex)),Z))};expect(t.aggregate).toEqual(aggregate);
  const opened=t.opened!;expect(opened.refusal).toBeNull();expect(opened.partials.length).toBeGreaterThanOrEqual(2);
  for(let i=0;i<opened.partials.length;i++){
    const part=opened.partials[i],proof=part.proof,Y=point(t.publicShares.find(p=>p.id===part.participantId)!.publicShareHex),C1=point(aggregate.c1Hex),D=point(part.sharePointHex),A=point(proof.a1Hex),B=point(proof.a2Hex),c=scalar(proof.challengeHex),s=scalar(proof.responseHex);
    const computed=hash(Buffer.concat([G,Y,C1,D,A,B].map(p=>Buffer.from(p.toBytes(true)))));
    const checks={challengeMatches:c===computed,firstEquation:times(G,s).equals(A.add(times(Y,c))),secondEquation:times(C1,s).equals(B.add(times(D,c))),valid:true};expect(checks).toEqual({challengeMatches:true,firstEquation:true,secondEquation:true,valid:true});expect(opened.checks[i]).toEqual(checks);await expect(page.locator('#election-partial-'+part.participantId)).toHaveAttribute('data-state','pass');
  }
  const ids=opened.partials.map(p=>p.participantId),combined=opened.partials.reduce((sum,p)=>sum.add(times(point(p.sharePointHex),lambda(p.participantId,ids))),Z);expect(enc(combined)).toBe(opened.combined);
  const total=point(aggregate.c2Hex).subtract(combined);expect(enc(total)).toBe(opened.point);
  const bounded=Array.from({length:8},(_,i)=>times(G,BigInt(i))).findIndex(p=>p.equals(total));expect(bounded===-1?null:bounded).toBe(value);expect(opened.tally).toEqual({value,steps:value===null?8:value+1});
  await expect(page.locator('#election-total')).toHaveText(value===null?'no tally in range':String(value));await expect(page.locator('#election-search-steps')).toHaveText(String(value===null?8:value+1));return t;
}
async function cast(page:Page){await page.locator('#election-cast').click();await expect(page.locator('#election-tally')).toBeEnabled({timeout:30_000});}
async function tallyOpen(page:Page){await page.locator('#election-tally').click();await expect(page.locator('#election-open')).toBeEnabled();await page.locator('#election-open').click();await expect(page.locator('#election-result')).toBeVisible();}
async function setup(page:Page){await page.locator('#run-dkg').click();await expect(page.locator('#election-cast')).toBeEnabled();}
export function electionTests(){
 test.afterEach(async({page})=>{if(process.env.MUTATION_ASSETS){const expected=JSON.parse(process.env.MUTATION_ASSETS);const loaded=await page.locator('script[type=module][src]').evaluateAll(es=>es.map(e=>new URL((e as HTMLScriptElement).src).pathname.split('/').at(-1)).sort());expect(loaded,'MUTATION_ASSET_MISMATCH loaded modules').toEqual(Object.keys(expected).sort());}if(process.env.MUTATION_ASSETS)for(const [name,hash] of Object.entries(JSON.parse(process.env.MUTATION_ASSETS))){const response=await page.request.get('assets/'+name);expect(response.ok(),'MUTATION_ASSET_MISMATCH').toBe(true);expect(createHash('sha256').update(await response.body()).digest('hex'),'MUTATION_ASSET_MISMATCH').toBe(hash);}});
 test('Exhibit 6: honest tally and receipt negative fixture have independently verified public equations',async({page})=>{
  await expect(page.locator('#election-proof')).toBeChecked();await setup(page);await cast(page);await tallyOpen(page);
  const values=await page.locator('[data-voter]').evaluateAll(es=>es.map(e=>Number((e as HTMLSelectElement).value)));const sum=values.reduce((a,b)=>a+b,0);await assertTally(page,sum);await expect(page.locator('#election-result')).toHaveClass(/good/);
  await page.locator('#election-receipt').click();const t=await trace(page),r=t.receipt!;const b=t.entries[r.index].ballot,randomness=scalar(r.r);expect(verify(t.groupPublicKey,t.entries[r.index]).valid).toBe(true);expect(times(G,randomness).equals(point(b.c1Hex))).toBe(true);expect(point(b.c2Hex).subtract(times(G,BigInt(r.vote))).equals(times(point(t.groupPublicKey),randomness))).toBe(true);
  await expect(page.locator('#receipt-first')).toHaveAttribute('data-state','pass');await expect(page.locator('#receipt-second')).toHaveAttribute('data-state','pass');await expect(page.locator('#election-receipt-result')).toContainText('VALID BALLOT — AND A RECEIPT FOR SALE');await expect(page.locator('#election-negative')).toHaveText('A valid 0-or-1 proof shows the ballot is well formed. It does not stop a voter from proving how she voted: revealing r lets anyone check c1 = rG and c2 − vG = rY, so this construction is not receipt-free.');await expect(page.locator('#election-negative')).toBeVisible();
 });
 for(const vote of [2,-1])test(`Exhibit 6: invalid vote ${vote} is counted in broken mode and rejected before the protected sum`,async({page})=>{
  await setup(page);await page.locator('#election-vote-1').selectOption(String(vote));await page.locator('#election-proof').uncheck();await cast(page);await assertBallots(page);await expect(page.locator('#election-proof-1')).toHaveAttribute('data-state','fail');await expect(page.locator('#election-proof-1')).toContainText('challenge-sum');await tallyOpen(page);await assertTally(page,4+vote);await expect(page.locator('#election-result')).toContainText('TALLY DECRYPTED — AND WRONG');await expect(page.locator('#election-result')).toHaveClass(/bad/);
  await page.locator('#election-proof').check();await expect(page.locator('#election-result')).toHaveCount(0);await tallyOpen(page);await assertTally(page,4);await expect(page.locator('#election-accepted')).toContainText('6 of 7');await expect(page.locator('#election-accepted')).not.toContainText('V2');await expect(page.locator('#election-result')).toHaveClass(/good/);
 });
 test('Exhibit 6: invalid votes remain an alarm when they cancel numerically',async({page})=>{
  await setup(page);for(const [i,v] of [2,-1,-1,0,0,0,0].entries())await page.locator('#election-vote-'+i).selectOption(String(v));await page.locator('#election-proof').uncheck();await cast(page);await tallyOpen(page);await assertTally(page,0);await expect(page.locator('#election-result')).toHaveClass(/bad/);await expect(page.locator('#election-result')).toContainText('INVALID BALLOTS COUNTED');await expect(page.locator('#election-result')).toContainText('happened to cancel numerically');
  await page.locator('#election-proof').check();await tallyOpen(page);await assertTally(page,0);await expect(page.locator('#election-accepted')).toContainText('4 of 7');await expect(page.locator('#election-result')).toHaveClass(/good/);
 });
 test('Exhibit 6: voter-index replay fails the full-statement challenge',async({page})=>{
  await setup(page);await cast(page);const before=await trace(page);await page.locator('#election-replay').click();await expect(page.locator('#election-tally')).toBeEnabled();const after=await assertBallots(page);expect(after.entries[1].ballot).toEqual(before.entries[0].ballot);expect(after.entries[1].proof).toEqual(before.entries[0].proof);expect(after.entries[1].context.voterIndex).toBe(1);expect(after.checks[1].firstEquations).toEqual([true,true]);expect(after.checks[1].secondEquations).toEqual([true,true]);expect(after.checks[1].challengeMatches).toBe(false);await expect(page.locator('#election-proof-1')).toHaveAttribute('data-state','fail');await expect(page.locator('#election-proof-1')).toContainText('challenge-sum');
 });
 test('Exhibit 6: zero and out-of-range totals use the exact bounded search',async({page})=>{
  await setup(page);for(let i=0;i<7;i++)await page.locator('#election-vote-'+i).selectOption('0');await cast(page);await tallyOpen(page);const zero=await assertTally(page,0);expect(zero.opened!.point).toBe('00');await expect(page.locator('#election-result')).toContainText('point at infinity');
  for(let i=0;i<7;i++)await page.locator('#election-vote-'+i).selectOption('1');await page.locator('#election-vote-0').selectOption('2');await page.locator('#election-proof').uncheck();await cast(page);await tallyOpen(page);await assertTally(page,null);await expect(page.locator('#election-result')).toContainText('NO TALLY IN RANGE');
 });
 test('Exhibit 6: below-threshold refusal and every dependent verdict retire on real edits',async({page})=>{
  await setup(page);await cast(page);await tallyOpen(page);await page.locator('#election-receipt').click();const before=await trace(page);await page.locator('#election-vote-0').dispatchEvent('change');await page.locator('#election-proof').dispatchEvent('change');expect(await trace(page)).toEqual(before);
  const chips=page.locator('[data-election-party][aria-pressed="true"]');await chips.first().click();await expect(page.locator('#election-result')).toHaveCount(0);await expect(page.locator('#election-receipt-result')).toHaveCount(0);await page.locator('#election-open').click();await expect(page.locator('#election-result')).toContainText('need at least');expect((await trace(page)).opened!.tally).toBeNull();
  await page.locator('#election-vote-0').selectOption('0');await expect(page.locator('#election-result')).toHaveCount(0);await expect(page.locator('#election-tally')).toBeDisabled();expect((await trace(page)).entries).toEqual([]);await cast(page);await page.locator('#threshold').fill('2');await expect(page.locator('#election-cast')).toBeDisabled();expect((await trace(page)).entries).toEqual([]);await setup(page);await cast(page);const oldKey=(await trace(page)).groupPublicKey;await page.locator('#run-dkg').click();expect((await trace(page)).groupPublicKey).not.toBe(oldKey);expect((await trace(page)).entries).toEqual([]);
 });
 test('Exhibit 6: late digest completion cannot restore an election after key regeneration',async({page})=>{
  await setup(page);await page.evaluate(()=>{const original=crypto.subtle.digest.bind(crypto.subtle);(window as any).digestRelease=[];crypto.subtle.digest=(async(...args:any[])=>{await new Promise<void>(resolve=>(window as any).digestRelease.push(resolve));return (original as any)(...args);}) as any;});await page.locator('#election-cast').click();await expect(page.locator('#election-cast')).toBeDisabled();await page.locator('#run-dkg').click();const newKey=(await trace(page)).groupPublicKey;
  await page.evaluate(async()=>{for(let i=0;i<30;i++){(window as any).digestRelease.splice(0).forEach((f:()=>void)=>f());await new Promise(r=>setTimeout(r,20));}});const t=await trace(page);expect(t.groupPublicKey).toBe(newKey);expect(t.entries).toEqual([]);expect(t.aggregate).toBeNull();await expect(page.locator('#election-tally')).toBeDisabled();
 });
}
