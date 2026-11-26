// D1-I2: synthetic-only durable mutation boundary. Not wired to clinical UI.
// Hooks are only deterministic test barriers. Never treat staging as an ACK.
import {readCheckpoint, commitCheckpoint} from './d1_checkpoint_candidate.mjs';

const owners = new Set([900001, 900002]);
const operationPattern = /^[a-z0-9-]{8,64}$/;

export class SyntheticMutationSession {
  #owner; #scope; #secret; #abort = new AbortController(); #busy = false;
  constructor(owner, secret) {
    if (!owners.has(owner) || typeof secret !== 'string' || secret.length < 16)
      throw new Error('Synthetic admission required');
    this.#owner = owner;
    this.#scope = 'amina_vault_v1_native_' + owner;
    this.#secret = secret;
  }
  retire() {
    this.#abort.abort(new Error('Session retired'));
    this.#secret = null;
  }
  #check() { this.#abort.signal.throwIfAborted(); }
  async mutate(operation, hooks = {}) {
    this.#check();
    if (!operationPattern.test(operation) || typeof operation !== 'string')
      throw new Error('Invalid operation ID');
    if (this.#busy) throw new Error('Mutation already pending');
    this.#busy = true;
    let prior, next;
    const secret = this.#secret;
    const id = 'd1-i1-' + this.#owner + '-op-' + operation;
    try {
      prior = await readCheckpoint(this.#scope, secret);
      this.#check();
      if (!prior) throw new Error('Checkpoint missing: no implicit enrollment');
      const before = JSON.parse(await window.d1Inspect(prior.bytes, this.#owner));
      this.#check();
      if (before.ids.includes(id)) {
        return {operation, revision: prior.revision, replay: true};
      }
      next = await window.d1Mutate(prior.bytes, this.#owner, operation);
      this.#check();
      const after = JSON.parse(await window.d1Inspect(next, this.#owner));
      this.#check();
      if (after.rows !== before.rows + 1 || !after.ids.includes(id) ||
          !before.ids.every(old => after.ids.includes(old)))
        throw new Error('Mutation invariant failed');
      if (hooks.afterPrepare) await hooks.afterPrepare();
      this.#check();
      const committed = await commitCheckpoint(this.#scope, secret, prior, next,
        {signal: this.#abort.signal, onStaged: hooks.onStaged});
      // A transaction may already have committed when a session is retired.
      // Do not publish its ACK to that scope. Replay by stable operation ID.
      this.#check();
      if (hooks.beforeAck) await hooks.beforeAck();
      this.#check();
      return {operation, revision: committed.revision, replay: false};
    } finally {
      prior?.bytes.fill(0);
      next?.fill(0);
      this.#busy = false;
    }
  }
}
