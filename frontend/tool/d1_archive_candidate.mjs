// D1 synthetic recovery candidate. No production storage, key custody,
// identity proof, migration, or vault-opening integration is provided here.
// Format: 8-byte magic/version, 16-byte salt, 12-byte IV, AES-GCM ciphertext+tag.
// The caller must supply the independently verified owner scope; it is not stored.
const MAGIC = new Uint8Array([73, 65, 77, 73, 78, 65, 1, 0]);
const HEADER = 36;
const TAG = 16;
const MAX_BYTES = 32 * 1024 * 1024;
const ITERATIONS = 600000;
const encoder = new TextEncoder();

function bytes(value, min, max) {
  if (!(value instanceof Uint8Array) || value.length < min || value.length > max) {
    throw new Error('Invalid archive input');
  }
  return new Uint8Array(value);
}

function ownerBytes(scope) {
  if (typeof scope !== 'string' || scope.length > 64 ||
      !/^(amina_vault_v1_native_[1-9][0-9]*|amina_vault_v1_device_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15})$/.test(scope)) {
    throw new Error('Explicit patient vault scope required');
  }
  return encoder.encode(scope);
}

function concatenate(...parts) {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

async function derive(secret, salt) {
  if (typeof secret !== 'string' || secret.length > 1024 ||
      Array.from(secret).length < 16) throw new Error('Recovery secret required');
  const input = encoder.encode(secret);
  try {
    const material = await crypto.subtle.importKey('raw', input, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      {name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS},
      material, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
  } finally {
    input.fill(0);
  }
}

export async function sealArchive(plaintext, secret, ownerScope) {
  const owner = ownerBytes(ownerScope);
  const data = bytes(plaintext, 1, MAX_BYTES);
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const header = concatenate(MAGIC, salt, iv);
    const key = await derive(secret, salt);
    const encrypted = await crypto.subtle.encrypt(
      {name: 'AES-GCM', iv, additionalData: concatenate(header, owner), tagLength: 128},
      key, data);
    return concatenate(header, new Uint8Array(encrypted));
  } finally {
    data.fill(0);
  }
}

export async function openArchive(archive, secret, expectedOwnerScope) {
  const owner = ownerBytes(expectedOwnerScope);
  const data = bytes(archive, HEADER + TAG + 1, HEADER + TAG + MAX_BYTES);
  if (!MAGIC.every((value, index) => data[index] === value)) {
    throw new Error('Unsupported archive format');
  }
  const header = data.slice(0, HEADER);
  const salt = header.slice(8, 24);
  const iv = header.slice(24, HEADER);
  try {
    const key = await derive(secret, salt);
    const plaintext = await crypto.subtle.decrypt(
      {name: 'AES-GCM', iv, additionalData: concatenate(header, owner), tagLength: 128},
      key, data.slice(HEADER));
    return new Uint8Array(plaintext);
  } catch {
    throw new Error('Archive authentication failed');
  }
}
