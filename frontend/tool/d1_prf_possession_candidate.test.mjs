import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {derivePrfWrappingKey} from './d1_prf_possession_candidate.mjs';

const enc = new TextEncoder();
const origin = 'https://patient.example';
const rpId = 'patient.example';
const id = Uint8Array.of(1,2,3,4);
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const sha = async bytes => new Uint8Array(await webcrypto.subtle.digest('SHA-256',bytes));
const der = raw => {
  const integer = bytes => {
    let x = Array.from(bytes);
    while(x.length>1 && x[0]===0)x.shift();
    if(x[0]&128)x.unshift(0);
    return [2,x.length,...x];
  };
  const r=integer(raw.slice(0,32)),s=integer(raw.slice(32));
  return Uint8Array.of(48,r.length+s.length,...r,...s);
};
class FixtureCredential {
  constructor(rawId,response,prf){Object.assign(this,{rawId,response,prf});}
  getClientExtensionResults(){return this.prf===null?{}:{prf:this.prf};}
}

async function fixture(t,options={}) {
  const saved = new Map();
  const install = (name,value) => {
    saved.set(name,Object.getOwnPropertyDescriptor(globalThis,name));
    Object.defineProperty(globalThis,name,{value,configurable:true,writable:true});
  };
  t.after(()=>{for(const [name,descriptor] of saved){
    if(descriptor)Object.defineProperty(globalThis,name,descriptor);
    else delete globalThis[name];
  }});
  const pair=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const spki=await webcrypto.subtle.exportKey('spki',pair.publicKey);
  const credential={version:1,credentialId:b64(id),publicKeySpki:b64(spki),origin,rpId,signCount:4};
  const state={pending:true,commits:0,requests:0,output:null,salts:[],challenges:[]};
  install('crypto',webcrypto);install('isSecureContext',true);
  install('location',{origin,hostname:rpId});install('PublicKeyCredential',FixtureCredential);
  install('navigator',{credentials:{get:async ({publicKey:p})=>{
    state.requests++;
    assert.equal(p.userVerification,'required');
    assert.equal(p.rpId,rpId);
    assert.deepEqual(p.allowCredentials[0].id,id);
    assert.equal(p.extensions.prf.eval.first.length,32);
    state.salts.push(b64(p.extensions.prf.eval.first));
    state.challenges.push(b64(p.challenge));
    const client=enc.encode(JSON.stringify({
      type:'webauthn.get',origin:options.wrongOrigin?'https://foreign.example':origin,
      challenge:b64(options.wrongChallenge?Uint8Array.of(1):p.challenge),
      crossOrigin:options.crossOrigin??false,
    }));
    const auth=new Uint8Array(37);
    auth.set(await sha(enc.encode(options.wrongRp?'foreign.example':rpId)));
    auth[32]=options.noUv?1:5;
    new DataView(auth.buffer).setUint32(33,options.counter??5);
    const payload=new Uint8Array(69);
    payload.set(auth);payload.set(await sha(client),37);
    const signature=der(new Uint8Array(await webcrypto.subtle.sign(
      {name:'ECDSA',hash:'SHA-256'},pair.privateKey,payload)));
    if(options.badSignature)signature[signature.length-1]^=1;
    const bytes=new Uint8Array(options.prfLength??32).fill(37);
    state.output=bytes;
    const prf=options.missingPrf?null:{enabled:options.enabled??true,results:{first:bytes.buffer}};
    if(options.cancelAssertion)state.pending=false;
    return new FixtureCredential(options.wrongId?Uint8Array.of(9):id,
      {clientDataJSON:client,authenticatorData:auth,signature},prf);
  }}});
  return {state,credential,derive: (owner=900001)=>derivePrfWrappingKey({
    credential,owner,isPending:()=>state.pending,
    commitCounter:async(stored,count)=>{
      assert.equal(stored.credentialId,credential.credentialId);
      assert.equal(count,5);
      state.commits++;
      if(options.cancelCommit)state.pending=false;
      return !options.failCommit;
    },
  })};
}
const refused = /D1_PRF_POSSESSION_REFUSED/;
test('PRF key is nonextractable, stable per owner, different across owners, fresh assertion',async t=>{
  const f=await fixture(t);
  const key=await f.derive();
  assert.equal(key.extractable,false);
  assert.deepEqual(key.usages,['wrapKey','unwrapKey']);
  assert.equal(key.algorithm.name,'AES-KW');
  await assert.rejects(webcrypto.subtle.exportKey('raw',key));
  assert.ok(f.state.output.every(x=>x===0));
  const data=await webcrypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
  const wrapped=await webcrypto.subtle.wrapKey('raw',data,key,'AES-KW');
  const same=await f.derive();
  const unwrapped=await webcrypto.subtle.unwrapKey('raw',wrapped,same,'AES-KW',
    {name:'AES-GCM'},false,['encrypt','decrypt']);
  assert.equal(unwrapped.extractable,false);
  const other=await f.derive(900002);
  await assert.rejects(webcrypto.subtle.unwrapKey('raw',wrapped,other,'AES-KW',
    {name:'AES-GCM'},false,['encrypt','decrypt']));
  assert.equal(f.state.salts[0],f.state.salts[1]);
  assert.notEqual(f.state.salts[1],f.state.salts[2]);
  assert.notEqual(f.state.challenges[0],f.state.challenges[1]);
  assert.equal(f.state.commits,3);
});
for(const [label,options] of [
  ['missing PRF',{missingPrf:true}],['disabled PRF',{enabled:false}],
  ['malformed PRF',{prfLength:31}],['wrong credential',{wrongId:true}],
  ['wrong origin',{wrongOrigin:true}],['cross origin',{crossOrigin:true}],
  ['wrong challenge',{wrongChallenge:true}],['wrong RP',{wrongRp:true}],
  ['missing UV',{noUv:true}],['bad signature',{badSignature:true}],
  ['counter rollback',{counter:4}],['cancelled assertion',{cancelAssertion:true}],
  ['failed counter commit',{failCommit:true}],['cancelled counter commit',{cancelCommit:true}],
]){
  test('refuses '+label,async t=>{
    const f=await fixture(t,options);
    await assert.rejects(f.derive(),refused);
    assert.equal(f.state.commits,options.failCommit||options.cancelCommit?1:0);
    if(!options.missingPrf)assert.ok(f.state.output.every(x=>x===0));
  });
}
test('retired acquisition never calls authenticator',async t=>{
  const f=await fixture(t);f.state.pending=false;
  await assert.rejects(f.derive(),refused);
  assert.equal(f.state.requests,0);assert.equal(f.state.commits,0);
});
