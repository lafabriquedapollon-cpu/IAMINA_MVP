// CONV-03B2a.2 — isolated possession candidate, never loaded by main.
// The caller must be a trusted internal coordinator with a pending D1
// acquisition and a credential from the verified AppLock store.
// No protection against compromised same-origin JS. No enrollment, persistence,
// patient data, fallback secret, or network egress. A physical PRF authenticator
// and durable counter commit are not proven by the Node fixture.
const toBase64Url = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
};

const fromBase64Url = (value) => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
};

const randomBytes = (length) => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
};

const concat = (...arrays) => {
  const length = arrays.reduce((sum, array) => sum + array.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const array of arrays) {
    output.set(array, offset);
    offset += array.length;
  }
  return output;
};

const bytesEqual = (a, b) => {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i += 1) mismatch |= a[i] ^ b[i];
  return mismatch === 0;
};

const sha256 = async (bytes) =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

const readUint32 = (bytes, offset) =>
  ((bytes[offset] << 24) |
    (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) |
    bytes[offset + 3]) >>> 0;

const assertClientData = (clientDataJson, expectedType, expectedChallenge) => {
  const bytes = new Uint8Array(clientDataJson);
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch (_) {
    throw new Error('client_data_invalid');
  }
  if (parsed.type !== expectedType) throw new Error('client_type_mismatch');
  if (parsed.challenge !== toBase64Url(expectedChallenge)) {
    throw new Error('challenge_mismatch');
  }
  if (parsed.origin !== location.origin || (parsed.crossOrigin !== undefined && parsed.crossOrigin !== false)) throw new Error('origin_mismatch');
  return bytes;
};

const inspectAuthenticatorData = async (authenticatorData, rpId) => {
  const bytes = new Uint8Array(authenticatorData);
  if (bytes.length < 37) throw new Error('authenticator_data_short');

  const expectedRpHash = await sha256(new TextEncoder().encode(rpId));
  if (!bytesEqual(bytes.slice(0, 32), expectedRpHash)) {
    throw new Error('rp_id_hash_mismatch');
  }

  const flags = bytes[32];
  const userPresent = (flags & 0x01) !== 0;
  const userVerified = (flags & 0x04) !== 0;
  if (!userPresent) throw new Error('user_presence_missing');
  if (!userVerified) throw new Error('user_verification_missing');

  return {
    bytes,
    signCount: readUint32(bytes, 33),
  };
};

const readDerLength = (bytes, cursor) => {
  if (cursor.index >= bytes.length) throw new Error('signature_der_invalid');
  const first = bytes[cursor.index++];
  if ((first & 0x80) === 0) return first;
  const count = first & 0x7f;
  if (count === 0 || count > 2 || cursor.index + count > bytes.length) {
    throw new Error('signature_der_invalid');
  }
  let value = 0;
  for (let i = 0; i < count; i += 1) value = (value << 8) | bytes[cursor.index++];
  return value;
};

const normalizeDerInteger = (bytes) => {
  let value = bytes;
  while (value.length > 32 && value[0] === 0) value = value.slice(1);
  if (value.length > 32) throw new Error('signature_der_invalid');
  const output = new Uint8Array(32);
  output.set(value, 32 - value.length);
  return output;
};

const derEcdsaToRaw = (signature) => {
  const bytes = new Uint8Array(signature);
  const cursor = { index: 0 };
  if (bytes[cursor.index++] !== 0x30) throw new Error('signature_der_invalid');
  const sequenceLength = readDerLength(bytes, cursor);
  if (cursor.index + sequenceLength !== bytes.length) {
    throw new Error('signature_der_invalid');
  }

  if (bytes[cursor.index++] !== 0x02) throw new Error('signature_der_invalid');
  const rLength = readDerLength(bytes, cursor);
  const rEnd = cursor.index + rLength;
  if (rEnd > bytes.length) throw new Error('signature_der_invalid');
  const r = normalizeDerInteger(bytes.slice(cursor.index, rEnd));
  cursor.index = rEnd;

  if (bytes[cursor.index++] !== 0x02) throw new Error('signature_der_invalid');
  const sLength = readDerLength(bytes, cursor);
  const sEnd = cursor.index + sLength;
  if (sEnd !== bytes.length) throw new Error('signature_der_invalid');
  const s = normalizeDerInteger(bytes.slice(cursor.index, sEnd));

  return concat(r, s);
};


const utf8 = new TextEncoder();
const require = (condition, code) => { if (!condition) throw new Error(code); };
const canonical = value => {
  require(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value), 'credential_invalid');
  const bytes = fromBase64Url(value);
  require(bytes.length > 0 && toBase64Url(bytes) === value, 'credential_invalid');
  return bytes;
};

// This key domain is intentionally distinct from every legacy/portable vault.
// Stable across acquisitions of the same owner, origin and credential.
// Never include a session epoch or a random challenge in the key domain.
export async function derivePrfWrappingKey({credential,owner,isPending,commitCounter}) {
  let raw;
  const pending = () => require(typeof isPending === 'function' &&
    isPending() === true, 'admission_retired');
  try {
    pending();
    require(globalThis.isSecureContext === true && globalThis.crypto?.subtle &&
      globalThis.PublicKeyCredential && globalThis.navigator?.credentials &&
      typeof commitCounter === 'function', 'prf_unavailable');
    require(Number.isSafeInteger(owner) && owner > 0 &&
      credential?.version === 1 && credential.origin === location.origin &&
      credential.rpId === location.hostname &&
      Number.isSafeInteger(credential.signCount) && credential.signCount >= 0 &&
      credential.signCount <= 0xffffffff, 'credential_invalid');
    // Copy the trusted record before any await.
    const stored = Object.freeze({...credential});
    const id = canonical(stored.credentialId);
    const spki = canonical(stored.publicKeySpki);
    const domain = utf8.encode(JSON.stringify([
      'IAMINA-D1-PRF-WRAP-V1', owner, stored.origin, stored.rpId, stored.credentialId,
    ]));
    const salt = await sha256(domain);
    pending();
    const challenge = randomBytes(32);
    const assertion = await navigator.credentials.get({publicKey:{
      challenge, rpId: stored.rpId,
      allowCredentials:[{type:'public-key',id,transports:['internal']}],
      userVerification:'required', timeout:30000,
      extensions:{prf:{eval:{first:salt}}},
    }});
    // Obtain the extension buffer only to discard/wipe on all paths.
    require(assertion instanceof PublicKeyCredential, 'assertion_invalid');
    const output = assertion.getClientExtensionResults()?.prf;
    if (output?.results?.first instanceof ArrayBuffer) {
      raw = new Uint8Array(output.results.first);
    }
    pending();
    require(bytesEqual(new Uint8Array(assertion.rawId),id), 'credential_id_mismatch');
    const response = assertion.response;
    const client = assertClientData(response.clientDataJSON,'webauthn.get',challenge);
    const auth = await inspectAuthenticatorData(response.authenticatorData,stored.rpId);
    pending();
    const clientHash = await sha256(client);
    pending();
    const publicKey = await crypto.subtle.importKey('spki',spki,
      {name:'ECDSA',namedCurve:'P-256'},false,['verify']);
    pending();
    const verified = await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},
      publicKey,derEcdsaToRaw(response.signature),concat(auth.bytes,clientHash));
    pending();
    require(verified,'signature_invalid');
    require(!(stored.signCount>0 && auth.signCount>0 &&
      auth.signCount<=stored.signCount),'signature_counter_rollback');
    require(output?.enabled !== false && raw?.length === 32,'prf_unavailable');
    const material = await crypto.subtle.importKey('raw',raw,'HKDF',false,['deriveKey']);
    raw.fill(0);
    pending();
    const wrappingKey = await crypto.subtle.deriveKey({
      name:'HKDF',hash:'SHA-256',salt,
      info:utf8.encode('IAMINA-D1-PRF-AES-KW-256-V1'),
    },material,{name:'AES-KW',length:256},false,['wrapKey','unwrapKey']);
    pending();
    // The actual backend must implement a credential-bound durable CAS, not
    // merely acknowledge the counter. Never release the key before that ACK.
    require(await commitCounter(stored,auth.signCount) === true,'counter_commit_failed');
    pending();
    return wrappingKey;
  } catch (_) {
    // Never expose extension bytes or arbitrary browser errors to the caller.
    throw new Error('D1_PRF_POSSESSION_REFUSED');
  } finally {
    raw?.fill(0);
  }
}
