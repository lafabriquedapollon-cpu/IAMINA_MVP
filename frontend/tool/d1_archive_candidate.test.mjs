import assert from 'node:assert/strict';
import {test} from 'node:test';
import {webcrypto} from 'node:crypto';
import {sealArchive, openArchive} from './d1_archive_candidate.mjs';
globalThis.crypto ??= webcrypto;
const owner = 'amina_vault_v1_native_101';
const other = 'amina_vault_v1_native_202';
const secret = 'synthetic-long-recovery-secret';
const plain = new TextEncoder().encode('synthetic-sqlite-bytes-only');

test('round trip, random salt and nonce, caller input not mutated', async () => {
  const before = plain.slice();
  const a = await sealArchive(plain, secret, owner);
  const b = await sealArchive(plain, secret, owner);
  assert.notDeepEqual(a, b);
  assert.deepEqual(plain, before);
  assert.deepEqual(await openArchive(a, secret, owner), before);
  assert.equal(a.length, 36 + 16 + plain.length);
  assert.equal(Buffer.from(a).includes(Buffer.from(plain)), false);
});

test('wrong secret and wrong independently supplied owner fail closed', async () => {
  const a = await sealArchive(plain, secret, owner);
  await assert.rejects(openArchive(a, 'different-long-recovery-secret', owner), /authentication failed/);
  await assert.rejects(openArchive(a, secret, other), /authentication failed/);
});

test('tampered header, salt, nonce, ciphertext and tag fail closed', async () => {
  const a = await sealArchive(plain, secret, owner);
  for (const i of [0, 8, 24, 36, a.length - 1]) {
    const changed = a.slice();
    changed[i] ^= 1;
    await assert.rejects(openArchive(changed, secret, owner));
  }
  await assert.rejects(openArchive(a.slice(0, -1), secret, owner));
});

test('no legacy, audit, invalid scope, empty or weak secret', async () => {
  for (const scope of ['amina', 'amina_vault_v1_audit', 'amina_vault_v1_native_0', '', 'other']) {
    await assert.rejects(sealArchive(plain, secret, scope));
  }
  await assert.rejects(sealArchive(new Uint8Array(0), secret, owner));
  await assert.rejects(sealArchive(plain, 'short', owner));
  await assert.rejects(openArchive(new Uint8Array(20), secret, owner));
});

test('valid device UUID namespace is distinct from native account', async () => {
  const scope = 'amina_vault_v1_device_12345678123441238123123456789abc';
  const a = await sealArchive(plain, secret, scope);
  assert.deepEqual(await openArchive(a, secret, scope), plain);
  await assert.rejects(openArchive(a, secret, owner));
});
