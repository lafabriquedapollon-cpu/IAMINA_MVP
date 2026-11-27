// Isolated bridge: no global install unless explicitly requested by a probe.
// Key remains in a private WeakMap; token is empty, unforgeable by value,
// realm-local, and cannot return/export a CryptoKey. B2b must add the trusted
// vault operation in this module, not a public raw-key accessor.
import {derivePrfWithDurableCounter} from './d1_prf_counter_candidate.mjs';
import {createPrfVault} from './d1_prf_vault_candidate.mjs';

export function createPrfBridge({fixtureProvision=false}={}) {
  const keys = new WeakMap();
  const require = value => {if(!value) throw new Error('D1_PRF_POSSESSION_REFUSED');};
  const isLive = token => !!token && typeof token === 'object' && keys.has(token);
  const revoke = token => {if(isLive(token)) keys.delete(token);};
  async function acquire(credentialJson, owner, isPending) {
    let token;
    try {
      require(typeof isPending==='function' && isPending()===true);
      const credential=JSON.parse(credentialJson);
      const key=await derivePrfWithDurableCounter({credential,owner,isPending});
      require(isPending()===true && key instanceof CryptoKey &&
        !key.extractable && key.algorithm.name==='AES-KW');
      token=Object.freeze(Object.create(null));
      keys.set(token,{key,owner,binding:JSON.stringify([credential.credentialId,
        credential.publicKeySpki,credential.rpId,credential.origin]),used:false});
      require(isPending()===true);
      return token;
    } catch (_) {
      if(token) revoke(token);
      throw new Error('D1_PRF_POSSESSION_REFUSED');
    }
  }
  const vault=createPrfVault({lookup:token=>keys.get(token),fixtureProvision});
  return Object.freeze({acquire,isLive,revoke,...vault});
}
export function installPrfBridge({fixtureProvision=false}={}) {
  if(Object.hasOwn(globalThis,'iaminaD1PrfBridge'))
    throw new Error('D1_PRF_POSSESSION_REFUSED');
  const {provisionFixture,...port}=createPrfBridge({fixtureProvision});
  Object.defineProperty(globalThis,'iaminaD1PrfBridge',{
    value:Object.freeze(port),writable:false,configurable:false,
  });
  // Fixture provisioning is returned to the trusted test harness only.
  return provisionFixture;
}
