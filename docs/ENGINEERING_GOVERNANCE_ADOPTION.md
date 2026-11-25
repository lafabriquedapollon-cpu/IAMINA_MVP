# Engineering governance adoption

IAmina explicitly adopts the central engineering-governance baseline:

- version: `1.0.0`
- exact source commit: `4c0ed295cc095fc5e7f9d0ddde3b1af95ac8dba9`
- adoption manifest: `.governance/adoption.json`

## Precedence

The central doctrine is a minimum engineering baseline. Existing IAmina governance remains authoritative wherever it is stricter or domain-specific, including:

- the canonical forward authority of `docs/ROADMAP.md`;
- the patient-companion authority ceiling and prohibition on diagnosis, prescription, dose advice, treatment optimization/change, or autonomous medical instruction;
- deterministic clinical and emergency logic remaining authoritative over generative models;
- privacy, consent, outbound AI/media egress, payload-minimization, processor and real-patient gates;
- the local-first patient-runtime boundary and the distinction between development/certification infrastructure and patient production;
- the Builder → applicable FUE (or justified FUE_NA and technical proofs) → adversarial and fresh Release Certification/Perfection Pass chain;
- exact-head evidence, double scoring, critical-dimension minimums, caps, and the mandatory Perfection Pass.

This adoption does not authorize release, deployment, real-patient processing, external-provider activation, database/schema/data mutation, merge, or any irreversible action. It does not alter the current roadmap priority or unlock gated work.

**Owner-authorized local governance amendment — 2026-11-25:** the generic independent Reviewer gate and executor-identity scoring restriction are superseded locally by the FUE and fresh-evidence protocol in `AGENTS.md` and `docs/QUALITY_SCORING_POLICY.md`, for all decisions and LOTs. This is an explicit local exception to any incompatible central generic-review requirement; it does not change the pinned central doctrine itself or imply upstream approval. All safety, risk-specialist, legal/human, exact-HEAD, release and deployment gates remain mandatory where applicable. Source: the [canonical Notion roadmap](https://app.notion.com/p/3df77c66336281f5b308ec17f7f0a63b).

Future doctrine upgrades require a new immutable version and exact source SHA. Moving references such as `main` or `latest` are not valid governance pins.
