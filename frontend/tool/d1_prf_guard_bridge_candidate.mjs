// Isolated bridge: no global install unless explicitly requested by a probe.
// Key remains in a private WeakMap; token is empty, unforgeable by value,
// realm-local, and cannot return/export a CryptoKey. B2b must add the trusted
// vault operation in this module, not a public raw-key accessor.
import {derivePrfWithDurableCounter} from './d1_prf_counter_candidate.mjs';
import {createPrfVault} from './d1_prf_vault_candidate.mjs';

export function createPrfBridge({fixtureAuthority=null}={}) {
  const keys = new WeakMap();
  const retired = new WeakMap();
  const require = value => {if(!value) throw new Error('D1_PRF_POSSESSION_REFUSED');};
  const isLive = token => !!token && typeof token === 'object' && !!keys.get(token)?.key;
  const revoke = token => {
    const entry=keys.get(token);
    if(!entry)return;
    keys.delete(token);
    entry.key=null;
    retired.set(token,entry);
    vault.revokeEntry(entry);
  };
  async function acquire(credentialJson, owner, isPending, acquisitionId=null) {
    let token;
    try {
      require(typeof isPending==='function' && isPending()===true &&
        (acquisitionId==null || (typeof acquisitionId==='string'&&/^[0-9a-f]{64}$/.test(acquisitionId))));
      const credential=JSON.parse(credentialJson);
      const key=await derivePrfWithDurableCounter({credential,owner,isPending});
      require(isPending()===true && key instanceof CryptoKey &&
        !key.extractable && key.algorithm.name==='AES-KW');
      token=Object.freeze(Object.create(null));
      keys.set(token,{key,owner,binding:JSON.stringify([credential.credentialId,
        credential.publicKeySpki,credential.rpId,credential.origin]),acquisitionId,used:false});
      require(isPending()===true);
      return token;
    } catch (_) {
      if(token) revoke(token);
      throw new Error('D1_PRF_POSSESSION_REFUSED');
    }
  }
  const vault=createPrfVault({lookup:token=>keys.get(token),fixtureAuthority});
  const waitRevocation=async token=>{
    const entry=retired.get(token);
    require(entry);
    return vault.waitRevocation(entry);
  };
  const {revokeEntry,waitRevocation:internalWait,...port}=vault;
  return Object.freeze({acquire,isLive,revoke,waitRevocation,...port});
}
export function installPrfBridge({fixtureAuthority=null}={}) {
  if(Object.hasOwn(globalThis,'iaminaD1PrfBridge'))
    throw new Error('D1_PRF_POSSESSION_REFUSED');
  const {provisionFixture,...port}=createPrfBridge({fixtureAuthority});
  Object.defineProperty(globalThis,'iaminaD1PrfBridge',{
    value:Object.freeze(port),writable:false,configurable:false,
  });
  // Fixture provisioning is returned to the trusted test harness only.
  return provisionFixture;
}
