// Isolated bridge: no global install unless explicitly requested by a probe.
// Key remains in a private WeakMap; token is empty, unforgeable by value,
// realm-local, and cannot return/export a CryptoKey. B2b must add the trusted
// vault operation in this module, not a public raw-key accessor.
import {derivePrfWithDurableCounter} from './d1_prf_counter_candidate.mjs';

export function createPrfBridge() {
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
      keys.set(token,key);
      require(isPending()===true);
      return token;
    } catch (_) {
      if(token) revoke(token);
      throw new Error('D1_PRF_POSSESSION_REFUSED');
    }
  }
  return Object.freeze({acquire,isLive,revoke});
}
export function installPrfBridge() {
  if(Object.hasOwn(globalThis,'iaminaD1PrfBridge'))
    throw new Error('D1_PRF_POSSESSION_REFUSED');
  Object.defineProperty(globalThis,'iaminaD1PrfBridge',{
    value:createPrfBridge(),writable:false,configurable:false,
  });
}
