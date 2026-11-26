// Internal candidate facade. Its caller must already have a bound lease.
// Not an authority or security boundary against compromised origin JS.
// No DB, keys, full audit, generic mutation, or injection hooks are exposed.
export function createClinicalSession(operations, isActive) {
  let retired = false;
  let retirement = null;
  const retire = () => {
    // Local authority is lost synchronously, even if durable CAS fails.
    retired = true;
    if (retirement === null) {
      try {
        retirement = Promise.resolve(operations.retire());
      } catch (error) {
        retirement = Promise.reject(error);
      }
      retirement = retirement.catch(error => {
        retirement = null;
        throw error;
      });
    }
    return retirement;
  };
  const check = () => {
    if (retired || isActive() !== true) {
      throw new Error('Bound authority retired');
    }
  };
  const perform = async (name, arity, args) => {
    try {
      check();
      if (args.length !== arity) throw new Error('Invalid clinical port arguments');
      const result = await operations[name](...args);
      // Do not release a result after a locally observed retirement.
      check();
      return result;
    } catch (error) {
      await retire();
      throw error;
    }
  };
  check();
  return Object.freeze(Object.assign(Object.create(null), {
    readJournal: (...args) => perform('readJournal', 5, args),
    readGlucose: (...args) => perform('readGlucose', 1, args),
    insertGlucose: (...args) => perform('insertGlucose', 5, args),
    editGlucose: (...args) => perform('editGlucose', 5, args),
    deleteGlucose: (...args) => perform('deleteGlucose', 2, args),
    readEvidence: (...args) => perform('readEvidence', 1, args),
    insertEvidence: (...args) => perform('insertEvidence', 5, args),
    readTreatment: (...args) => perform('readTreatment', 0, args),
    writeTreatment: (...args) => perform('writeTreatment', 3, args),
    retire,
  }));
}
