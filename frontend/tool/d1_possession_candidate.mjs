// D1-I5B possession experiment only. No production enrollment or auth.
// A portable secret must be held outside this application. Never persist it.
// No claim that a syntactically valid imported secret has 256 bits of entropy.
export function generatePossessionSecret() {
  if (!globalThis.isSecureContext || !globalThis.crypto?.getRandomValues ||
      !globalThis.crypto?.subtle) throw new Error('Secure cryptography unavailable');
  const raw = crypto.getRandomValues(new Uint8Array(32));
  try {
    return Array.from(raw, x => x.toString(16).padStart(2, '0')).join('');
  } finally {
    raw.fill(0);
  }
}

export function requirePossessionSecret(value) {
  if (typeof value !== 'string' || value.length !== 64 ||
      !/^[0-9a-f]{64}$/.test(value)) throw new Error('Invalid possession secret');
  return value;
}
