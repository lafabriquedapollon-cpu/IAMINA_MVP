# IAmina — Quality Scoring & Verification Policy

This file is the canonical scoring policy for material execution steps, LOT verification and release certification.

## Scope

A **material step** is any implementation, remediation, migration, UI/UX change, security/privacy/data change, clinical-claim change, or other step whose failure could materially affect the LOT outcome.

Every material step MUST be scored twice after evidence is available:

- `EXECUTION_SCORE /10` — score of the implemented result against its explicit goal, acceptance criteria and evidence.
- `ADVERSARIAL_SCORE /10` — score from a deliberately critical review that tries to falsify the Builder's result, identify regressions, missing proof, weak assumptions and hidden failure modes.

The retained score is never an average:

`RETAINED_SCORE = min(EXECUTION_SCORE, ADVERSARIAL_SCORE, all applicable caps, every critical-dimension score)`

For a LOT containing multiple material steps, the LOT score is the **lowest retained material-step score**, never an average across steps.

## Mandatory discrepancy investigation

If `abs(EXECUTION_SCORE - ADVERSARIAL_SCORE) > 0.5`, the discrepancy MUST be investigated before verification. The investigation must identify why the two evaluations differ, remediate or justify the discrepancy, rerun affected evidence, and rescore.

A LOT cannot become `VERIFIED` while such a discrepancy remains unresolved.

## Score discipline

- `10.0/10` is exceptional: complete evidence, every required binary gate green and no known realistically improvable in-scope weakness.
- Any retained score `>= 9.5/10` requires exhaustive applicable FUE (or strictly justified `FUE_NA`), all exact-HEAD technical/risk gates green, documented adversarial counter-tests and a separate fresh confirmation pass, with no open material weakness.
- Executor identity alone imposes no score cap; never infer a higher score from removal of the generic independent-review gate.
- A required test that is red, or required proof that is absent/stale, caps the retained score at `7.9/10`.
- A demonstrated regression caps the retained score at `6.9/10` until the regression is remediated and the affected evidence is rerun.
- A blocking security, privacy, data-integrity, or clinical-claim finding caps the retained score at `5.9/10` and the status MUST be `BLOCKED` until resolved.
- For UI/UX work, if there is no real `Target ↔ Render` comparison at the required identical viewports/states, the **visual-fidelity dimension** is capped at `7.5/10`.
- No strong average may hide a weak critical dimension. Every critical dimension is scored explicitly and participates in the `min(...)` retained-score rule.

Caps stack by taking the lowest applicable cap.

## FUE as required binary gate for every decision and LOT

Every decision and LOT must run a **case-adaptive FUE (FIRST USER EXPERIENCE)** covering **all affected user journeys and features**. A technical-only LOT may record `FUE_NA` only with a specific justification that no user journey is affected; all required technical and risk proofs must still pass. Build the required journey matrix from that decision's actual actions, user states and risks, not from a universal script: use relevant entry/return states, affected real-Web viewports (390×844 / 768×1024 / 1280×900), FR/AR RTL, keyboard/navigation, positive-negative-recovery states, and permission/persistence/offline/account checks **where applicable**. **the cross-account isolation check is a targeted W02-style owner/session-isolation security regression, never a default FUE prerequisite**; run or reuse it only when cross-owner boundaries are affected or existing evidence fails to cover the risk. Mark excluded cases N/A with justification, not PASS. Record `LOT feature → journey → expected → observed → evidence → PASS/FAIL/NOT_RUN`. **100% required PASS** is a binary gate for `VERIFIED`; any missing, failed or not-run required case means `FUE_NO_GO` regardless of CI.

FUE replaces the generic independent Reviewer gate for every LOT. The Builder may execute FUE; perform separate adversarial and fresh confirmation passes. Existing risk-specific reviews, clinical/security/privacy/data/linguistic approvals and human gates remain mandatory when applicable. No FUE or score substitutes for them.

## Binary gates

Scores never override binary gates. A LOT may be `VERIFIED` only when:

1. every required binary gate is green on the exact applicable HEAD/evidence set (**including full applicable FUE or justified FUE_NA**);
2. no unresolved BLOCKER or MAJOR finding remains;
3. every material step has both required scores;
4. all score discrepancies `> 0.5` have been investigated and resolved;
5. the LOT retained score is at least `9.0/10`;
6. the mandatory final Perfection Pass has completed.

A LOT below `9.0/10` is `NOT_VERIFIED` even if all binary gates are green.

## Mandatory Perfection Pass

A score at or above `9.0/10` does **not** close a LOT by itself. Before `VERIFIED`, perform one final **Perfection Pass**:

1. list the remaining weaknesses, rough edges, uncertainties and non-blocking findings;
2. identify which are realistically improvable inside the approved scope;
3. fix every materially improvable in-scope weakness;
4. rerun all evidence affected by those fixes on the new exact HEAD;
5. repeat Execution + Adversarial scoring under this policy;
6. document any residual issue that is genuinely non-improvable, externally blocked, or explicitly out of scope.

Example: a LOT at `9.2/10` still requires the Perfection Pass. It is not `VERIFIED` until the pass is complete and the final retained score remains `>= 9.0/10` with all binary gates green.

## Required reporting format

For every material step:

```text
Goal:
Success criterion:
Evidence:
Critical dimensions:
EXECUTION_SCORE: x.x/10
ADVERSARIAL_SCORE: x.x/10
Gap: x.x
Applicable caps: none | ...
RETAINED_SCORE: x.x/10
Status: OPEN | BLOCKED | READY_FOR_PERFECTION_PASS | VERIFIED
Remaining weaknesses:
Next exact action:
```

For LOT closeout, record retained scores, binary gates, **the full applicable FUE feature matrix + verdict or justified FUE_NA with technical proofs**, risk-specialist approvals if required, actual reviewer participation only when relevant, Perfection Pass result, and exact evidence/HEAD.

## Fresh-evidence confirmation

A distinct confirmation pass must re-read the final diff, runtime/rendered evidence, tests and claims without treating Builder conclusions as proof. The same executor may perform it; record actual execution and evidence, never invent independence. Specialist or human approvals required by risk-specific policy are unchanged.
