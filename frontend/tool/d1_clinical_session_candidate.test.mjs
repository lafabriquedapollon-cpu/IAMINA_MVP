import test from 'node:test';
import assert from 'node:assert/strict';
import {createClinicalSession} from './d1_clinical_session_candidate.mjs';

const names = ['readJournal','readGlucose','insertGlucose','editGlucose','deleteGlucose','readEvidence','insertEvidence','readTreatment','writeTreatment'];
function fixture() {
  let active = true;
  const calls = [];
  const ops = Object.fromEntries(names.map(name => [name, async (...args) => {
    calls.push([name, ...args]);
    return {revision: 1};
  }]));
  ops.retire = async () => { active = false; calls.push(['retire']); return true; };
  return {ops, calls, active: () => active, lock: () => {active = false;}};
}

test('frozen null-prototype facade exposes only clinical operations', async () => {
  const f = fixture(), session = createClinicalSession(f.ops, f.active);
  assert.deepEqual(Object.keys(session), [...names, 'retire']);
  assert.equal(Object.getPrototypeOf(session), null);
  assert.equal(Object.isFrozen(session), true);
  for (const name of ['inspect','auditSnapshot','mutate','key','database','bytes','constructor','revocationStatus']) {
    assert.equal(session[name], undefined);
  }
  const vectors = [
    ['readJournal', 1, 100, 200, 2, 0], ['readGlucose','uuid'],
    ['insertGlucose', 1, 'uuid', 100, 'mg/dL', 100],
    ['editGlucose', 1, 'uuid', 120, 'mg/dL', 100],
    ['deleteGlucose', 1, 'uuid'], ['readEvidence','uuid'],
    ['insertEvidence', 1, 'uuid', 7.83, 'mmol/L', 100], ['readTreatment'],
    ['writeTreatment', 1, 'declared', ['insulin']],
  ];
  for (const [name, ...args] of vectors) {
    assert.deepEqual(await session[name](...args), {revision:1});
  }
  assert.deepEqual(f.calls, vectors);
});

test('extra test hooks never reach operations and retire the handle', async () => {
  const f = fixture(), session = createClinicalSession(f.ops, f.active);
  await assert.rejects(session.readJournal(1, 100, 200, 2, 0, {beforeReturn(){throw Error('hook');}}), /Invalid clinical port arguments/);
  assert.deepEqual(f.calls, [['retire']]);
  await assert.rejects(session.readTreatment(), /Bound authority retired/);
});

test('late completion after explicit retirement cannot release a result', async () => {
  const f = fixture();
  let resolve;
  f.ops.readTreatment = () => new Promise(r => {resolve = r;});
  const session = createClinicalSession(f.ops, f.active);
  const pending = session.readTreatment();
  await session.retire();
  resolve({declaration:'private'});
  await assert.rejects(pending, /Bound authority retired/);
});

test('external lock before or during operation rejects and never revives', async () => {
  const f = fixture();
  let resolve;
  f.ops.readGlucose = () => new Promise(r => {resolve = r;});
  const session = createClinicalSession(f.ops, f.active);
  const pending = session.readGlucose('uuid');
  f.lock();
  resolve({measurement:'private'});
  await assert.rejects(pending, /Bound authority retired/);
  await assert.rejects(session.readGlucose('uuid'), /Bound authority retired/);
  assert.throws(() => createClinicalSession(f.ops, f.active), /Bound authority retired/);
});

test('failure to retire durably cannot re-enable the local handle', async () => {
  const f = fixture();
  f.ops.retire = async () => {throw Error('Durable revocation unconfirmed');};
  const session = createClinicalSession(f.ops, f.active);
  await assert.rejects(session.retire(), /Durable revocation unconfirmed/);
  await assert.rejects(session.readTreatment(), /Durable revocation unconfirmed/);
  assert.deepEqual(f.calls, []);
});

test('concurrent and repeated retire calls share one durable acknowledgement', async () => {
  const f = fixture();
  let resolve, attempts = 0;
  f.ops.retire = () => {
    attempts++;
    return new Promise(r => {resolve = r;});
  };
  const session = createClinicalSession(f.ops, f.active);
  const a = session.retire();
  const b = session.retire();
  const rejected = assert.rejects(session.readTreatment(), /Bound authority retired/);
  assert.equal(a, b);
  assert.equal(attempts, 1);
  resolve(true);
  assert.equal(await a, true);
  await rejected;
  assert.equal(await session.retire(), true);
  assert.equal(attempts, 1);
  assert.deepEqual(f.calls, []);
});

test('failed durable retirement can retry without reopening any clinical port', async () => {
  const f = fixture();
  let attempts = 0;
  f.ops.retire = () => {
    if (++attempts === 1) throw Error('Durable revocation unconfirmed');
    return Promise.resolve(true);
  };
  const session = createClinicalSession(f.ops, f.active);
  await assert.rejects(session.retire(), /Durable revocation unconfirmed/);
  assert.equal(await session.retire(), true);
  await assert.rejects(session.readGlucose('uuid'), /Bound authority retired/);
  assert.equal(attempts, 2);
  assert.deepEqual(f.calls, []);
});
