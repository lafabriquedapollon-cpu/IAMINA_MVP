// D1-I1: synthetic-only encrypted checkpoint transport. Not a patient vault.
import {sealArchive, openArchive} from './d1_archive_candidate.mjs';

const DB = 'iamina-d1-runtime-probe-v1';
const TABLE = 'checkpoints';
const MAX = 32 * 1024 * 1024 - 4;
const owners = new Set(['amina_vault_v1_native_900001', 'amina_vault_v1_native_900002']);

function requireOwner(owner) {
  if (!owners.has(owner)) throw new Error('Synthetic owner required');
}
function sameBytes(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array &&
    a.length === b.length && a.every((v, i) => v === b[i]);
}
function validateRecord(record) {
  if (!record || !Number.isSafeInteger(record.revision) ||
      record.revision < 1 || record.revision > 0xffffffff ||
      !(record.archive instanceof Uint8Array)) throw new Error('Invalid checkpoint record');
}
async function connect() {
  if (!isSecureContext || !globalThis.indexedDB || !globalThis.crypto?.subtle)
    throw new Error('Secure durable storage unavailable');
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(TABLE);
    req.onsuccess = () => {
      const db = req.result;
      db.onversionchange = () => db.close();
      resolve(db);
    };
    req.onerror = () => reject(new Error('Checkpoint store unavailable'));
    req.onblocked = () => reject(new Error('Checkpoint store blocked'));
  });
}
async function readRecord(owner) {
  const db = await connect();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(TABLE, 'readonly');
      const req = tx.objectStore(TABLE).get(owner);
      tx.oncomplete = () => resolve(req.result ?? null);
      tx.onabort = () => reject(new Error('Checkpoint read failed'));
    });
  } finally { db.close(); }
}
async function decode(record, owner, secret) {
  validateRecord(record);
  const payload = await openArchive(record.archive, secret, owner);
  try {
    if (payload.length <= 4 || new DataView(payload.buffer, payload.byteOffset, 4).getUint32(0) !== record.revision)
      throw new Error('Checkpoint revision authentication failed');
    return payload.slice(4);
  } finally { payload.fill(0); }
}
// Missing is an explicit state, never interpreted as authorization to overwrite.
export async function readCheckpoint(owner, secret) {
  requireOwner(owner);
  const record = await readRecord(owner);
  if (record === null) return null;
  const bytes = await decode(record, owner, secret);
  return {revision: record.revision, archive: record.archive, bytes};
}
export async function commitCheckpoint(owner, secret, expected, bytes, {signal, onStaged} = {}) {
  signal?.throwIfAborted();
  requireOwner(owner);
  if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > MAX)
    throw new Error('Invalid checkpoint bytes');
  let revision = 1;
  if (expected !== null) {
    validateRecord(expected);
    // Snapshot the CAS token before the first await.
    expected = {revision: expected.revision, archive: expected.archive.slice()};
    const old = await decode(expected, owner, secret);
    old.fill(0);
    signal?.throwIfAborted();
    if (expected.revision === 0xffffffff) throw new Error('Revision exhausted');
    revision = expected.revision + 1;
  }
  const payload = new Uint8Array(bytes.length + 4);
  new DataView(payload.buffer).setUint32(0, revision);
  payload.set(bytes, 4);
  let archive;
  try { archive = await sealArchive(payload, secret, owner); }
  finally { payload.fill(0); }
  signal?.throwIfAborted();
  const db = await connect();
  try {
    signal?.throwIfAborted();
    // No await inside the transaction. Read/compare/replace are atomic across
    // tabs for this origin. Success is returned only on transaction completion.
    await new Promise((resolve, reject) => {
      const tx = db.transaction(TABLE, 'readwrite', {durability: 'strict'});
      if (tx.durability !== 'strict') {
        tx.abort();
        reject(new Error('Strict checkpoint durability unavailable'));
        return;
      }
      const objectStore = tx.objectStore(TABLE);
      let conflict = false;
      const abort = () => { try { tx.abort(); } catch { /* already completed */ } };
      const cleanup = () => signal?.removeEventListener('abort', abort);
      tx.oncomplete = () => { cleanup(); resolve(); };
      tx.onabort = () => {
        cleanup();
        reject(new Error(signal?.aborted ? 'Session retired' :
          conflict ? 'Checkpoint conflict' : 'Checkpoint commit failed'));
      };
      signal?.addEventListener('abort', abort, {once: true});
      if (signal?.aborted) { abort(); return; }
      const req = objectStore.get(owner);
      req.onsuccess = () => {
        if (signal?.aborted) { abort(); return; }
        const current = req.result ?? null;
        const matches = expected === null ? current === null :
          current !== null && current.revision === expected.revision &&
          sameBytes(current.archive, expected.archive);
        if (!matches) { conflict = true; tx.abort(); return; }
        const put = objectStore.put({revision, archive}, owner);
        // Synthetic fault injection only: observe staged request, before commit.
        if (onStaged) put.onsuccess = () => {
          try { onStaged(); } catch { abort(); }
        };
      };
    });
    return {revision, archive};
  } finally { db.close(); }
}
