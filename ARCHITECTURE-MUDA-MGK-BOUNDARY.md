# ARCHITECTURE-MUDA-MGK-BOUNDARY.md

Canonical architecture boundary for **MGK v0.3.0**.

This document defines, for the purposes of the MGK repository, the boundary
between:

1. the MUDA conceptual/formal kernel;
2. the MUDA operational kernel;
3. the wider Malla MUDA conceptual system;
4. the MGK governance kernel (this repository's software);
5. external intelligence systems;
6. actuators/executors;
7. human authority.

It is the canonical reference for what the software claims to implement and
what it explicitly does **not** claim to implement.

---

## 0. Scope and honesty rules

- MGK is an **engineering implementation derived from MUDA concepts**. It is
  not a scientific proof of the full MUDA theory.
- No claim in this document implies that MUDA is scientifically proven in
  full, or that MGK proves universal AI safety, or that any invariant holds
  under every possible threat model.
- Every claim about the software is bounded by the documented threat model
  and the tested corpus of this repository.
- Every concept below is classified with explicit status labels:

  | Label | Meaning |
  |-------|---------|
  | CONCEPTUAL | present as an idea/framework; not a code artifact |
  | FORMALIZED | given a precise formal statement in the repository |
  | OPERATIONALIZED | realized as a running behavior/state in the software |
  | IMPLEMENTED | realized as code |
  | TESTED | covered by an automated, reproducible test in the repository |
  | FALSIFIABLE | admits a deterministic test that could refute the claim |
  | INFERRED | asserted by analogy/resonance, not by direct implementation |
  | NOT_IMPLEMENTED | no code artifact exists in this repository |
  | NOT_INDEPENDENTLY_VALIDATED | no independent experiment/evidence exists |

A single concept may carry several labels (e.g. IMPLEMENTED + TESTED +
FALSIFIABLE). Labels are claims about this repository, not about the MUDA
literature.

---

## 1. Executable invariant

The central executable invariant of MGK is

```
INTELLIGENCE != AUTHORITY        (I != A)
```

encoded operationally as:

```
proposal != authorization != execution
```

A proposal is **data**. A model output is **data**. An LLM response is
**data**. A planner result is **data**. None of those is authority.

Execution authority is issued only by the deterministic MGK control plane:
a narrowly scoped, short-lived, single-use, Ed25519-signed capability, bound
to the exact action/resource/digest/epoch, verified fail-closed, and executed
by the kernel executor after a final epoch re-check.

### Falsifiable engineering hypothesis

```
Compromised Intelligence  does-not-imply  Compromised Authority
```

Precisely: within the documented threat model and the implemented authority
boundary, a compromised planner/intelligence (an attacker who fully controls
proposal generation) does not by itself yield execution authority over
governed side effects.

This is a **falsifiable engineering claim scoped to this implementation**, not
a universal proof. It is tested by the H14 smoke, the proposal-as-data
regression corpus, and the adversarial red-team corpus. Any reproducible
counter-example within the threat model is a security defect to fix.

---

## 2. MUDA conceptual/formal kernel

The conceptual equilibrium framed around `h × K = C0` and the associated
minimal-action / maximal-order equilibrium framing.

- Status: **CONCEPTUAL, NOT_IMPLEMENTED, NOT_INDEPENDENTLY_VALIDATED**.
- This repository contains **no code** implementing `h × K = C0`.
- This repository contains **no experimental evidence** proving it as
  universal physics. MGK does not present it as experimentally proven.
- MGK references MUDA concepts for provenance; it does not claim to implement
  the full equilibrium formalism.
- The arrow/SAXP scoring in this repository uses bounded, deterministic
  integer heuristics (coherence_delta, systemic_pressure, threshold_k,
  sentidino). These are engineering proxies, not measurements of `h × K`.

## 3. MUDA operational kernel

The operational cognitive/decisional kernel centered on:

- Rrep (representational capacity)
- Rlim (limitational/constraint capacity)
- Rcog (cognitive capacity)
- CCI (integrated processing triad)

Status:

- Rrep / Rlim / Rcog / CCI as named MUDA capacities:
  **CONCEPTUAL, NOT_IMPLEMENTED** (no modules with those names exist).
- Conceptual resonance in this repository:
  - `cha.py` computes heuristic metrics named `reptile_integrity`,
    `limbic_resonance`, `cognitive_coherence` — an engineering echo of the
    triad, **INFERRED** analogy, not a claim of implementing Rrep/Rlim/Rcog.
  - `feedback.py` performs bounded weight adjustment — an engineering echo of
    integration, **INFERRED** analogy, not a claim of implementing CCI.
- The three capacities should be understood, in MUDA terms, as a
  non-hierarchical processing triad integrated through CCI. MGK does not
  re-architect that; it only consumes the *output* of such processing as
  **data** (a proposal).

## 4. Wider Malla MUDA

Concepts such as CHA, Arrow, SAXP, Xeito / UCH, Sentidiño, Afouteza, Latexo,
Muda, Feedback, Malla, Fractura de Campo.

| Concept | Status in this repository |
|---------|---------------------------|
| Muda | CONCEPTUAL (source concept; the repository name references it) |
| CHA | IMPLEMENTED + TESTED + FALSIFIABLE (`src/mgk/cha.py`, `CHAProposal.intelligence_only=True` — data only) |
| Arrow | IMPLEMENTED + TESTED + FALSIFIABLE (`src/mgk/arrow.py`, route selection) |
| SAXP | IMPLEMENTED + TESTED + FALSIFIABLE (`src/mgk/saxp.py`, deterministic policy evaluation) |
| Xeito | OPERATIONALIZED (`TEN_XEITO` / `REQUIRE_XEITO` / `NON_TEN_XEITO` decision states in SAXP and the human-gate pipeline) |
| UCH | CONCEPTUAL, NOT_IMPLEMENTED (no dedicated module; human-review state is the operational form of the idea) |
| Sentidiño | OPERATIONALIZED as a bounded integer context field (`sentidino`) in SAXP; wider meaning is CONCEPTUAL |
| Afouteza | CONCEPTUAL, NOT_IMPLEMENTED |
| Latexo | CONCEPTUAL, NOT_IMPLEMENTED |
| Feedback | IMPLEMENTED + TESTED (`src/mgk/feedback.py`, bounded Level-1 weight adjustment; cannot mint or verify capabilities) |
| Malla | CONCEPTUAL as a whole; MGK implements only the governance/authority sub-layer |
| Fractura de Campo | CONCEPTUAL, NOT_IMPLEMENTED |

MGK does **not** silently collapse the whole Malla MUDA into itself. Only the
governance/authority sub-layer is implemented here.

## 5. MGK governance kernel

The deterministic governance / authority layer derived from MUDA concepts.

Components (all IMPLEMENTED + TESTED + FALSIFIABLE unless noted):

| Component | Status |
|-----------|--------|
| Canonical encoding v1 (`src/mgk/canonical.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Ed25519 domain-separated crypto (`src/mgk/crypto.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Capability authority issuance (`src/mgk/authority.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Capability verifier (`src/mgk/verifier.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Executor enforcement (`src/mgk/executor.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Epoch / nonce state (`src/mgk/state.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Audit / failure ledgers (`src/mgk/ledger.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Resource binding / anti-TOCTOU (`src/mgk/resource.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Runtime policy (`runtime/policy.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Decision pipeline / human gate (`runtime/decision.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Runtime web/server (`runtime/web.py`, `runtime/server.py`) | IMPLEMENTED + TESTED |
| Actuator registry (`runtime/sandbox/__init__.py`) | IMPLEMENTED + TESTED + FALSIFIABLE |
| Flight recorder (`runtime/flight.py`) | IMPLEMENTED + TESTED (evidence-only, unsigned checkpoint) |
| Runtime ledger (`runtime/runtime_ledger.py`) | IMPLEMENTED + TESTED (queryable index, not a trust source) |

Core rule preserved and strengthened by v0.3.0:

```
NO GOVERNED SIDE EFFECT WITHOUT VALID AUTHORITY.
```

Controls preserved or strengthened (never weakened) in v0.3.0: scope,
subject, audience, action, resource binding, request digest,
authorization epoch, expiration / TTL, nonce / replay protection, signature
verification, deterministic policy, SAXP binding, fail-closed behavior,
evidence persistence.

Human-review states (`REQUIRE_XEITO`) MUST NOT execute directly.
`NON_TEN_XEITO` / `DENY` MUST NOT execute. Critical uncertainty MUST fail
closed.

### v0.3.0 authority-boundary hardening

`runtime/decision.py` now enforces a **durable human-gate state machine**:

- A human `DENY` is a terminal state for the proposal: a later
  `APPROVE` of the same request is refused (fail-closed) and cannot issue a
  capability or execute a side effect.
- A proposal whose decision is already terminal (`ALLOW` executed, `DENY`, or
  policy-denied) cannot be re-opened through the human gate.
- Only proposals in `REQUIRE_HUMAN` state are actionable through the human
  gate.
- The refusal is recorded as a `HUMAN_GATE_TRANSITION_DENIED` evidence event
  (append-only flight record) and surfaced as a `DENY` decision.

This closes the previously existing "unauthorized human-gate transition"
surface (approve-after-deny execution). It is protected by permanent
discriminating regression tests and by new adversarial red-team probes.

## 6. External intelligence systems

External intelligence (an LLM, a planner, a cognitive kernel, CHA-style
scoring) is **outside** the MGK authority boundary.

- Status: **CONCEPTUAL / OPERATIONALIZED (as an untrusted input source)**.
- The runtime accepts proposals from the `planner` principal as **data**
  through the loopback API, subject to the closed actuator registry and the
  deterministic policy.
- MGK does not host the intelligence; it governs the *effects* the
  intelligence may propose. A compromised intelligence is a compromised
  proposal source, not a compromised authority (see Section 1).

## 7. Actuators / executors

- Status: **IMPLEMENTED + TESTED + FALSIFIABLE**.
- The actuator registry is a closed set of exactly five actions:
  `sandbox.read_file`, `sandbox.write_file`, `sandbox.append_file`,
  `sandbox.create_record`, `sandbox.read_record`.
- Resources are confined to the `files/` and `records/` namespaces of the
  sandbox, bound by descriptor and digest, with O_NOFOLLOW / dir_fd
  anti-TOCTOU enforcement.
- There is **no arbitrary shell actuator, no arbitrary network actuator, no
  unrestricted filesystem actuator, no eval, no exec of untrusted proposal
  data, no proposal-generated code execution.**

## 8. Human authority

- Status: **OPERATIONALIZED + TESTED**.
- `REQUIRE_XEITO` proposals queue for a human decision; `APPROVE` issues and
  executes a fresh capability; `DENY` is terminal and never executes.
- Human gate decisions are evidence-signed (`HUMAN_GATE_DOMAIN`) and
  persisted. The signature is evidence of operator intent; the authority
  boundary itself remains with the kernel.
- The **release** decision (merge, tag, publish) is reserved for human
  authority. The automated pipeline sets `MERGE_AUTHORIZED=FALSE`,
  `TAG_AUTHORIZED=FALSE`, `RELEASE_AUTHORIZED=FALSE`,
  `PACKAGE_PUBLICATION_AUTHORIZED=FALSE`.

## 9. Canonical architecture flow

The following flow is the canonical architectural mapping for v0.3.0. Every
arrow corresponds to a real artifact in this repository (paths in
parentheses). Only the `h × K = C0` equilibrium step is marked CONCEPTUAL and
is not part of the software.

```
external intelligence / CHA                       (cha.py produces data)
        |
        v
proposal                                         (runtime/web.py /api/propose,
                                                  runtime/sandbox validate_request)
        |
        v
Arrow / planning                                 (arrow.py route selection; planner = data)
        |
        v
SAXP / governance evaluation                     (saxp.py -> TEN_XEITO / REQUIRE_XEITO /
                                                  NON_TEN_XEITO; runtime/policy.py context)
        |
        v
MGK capability authority                         (authority.py issue; SAXP gate; resource
                                                  binding; single-use nonce; Ed25519)
        |
        v
verified scoped capability                       (verifier.py verify: schema, scope,
                                                  digest, SAXP evidence, TTL, epoch, nonce)
        |
        v
executor / actuator                              (executor.py execute: epoch re-check,
                                                  bound resource op, output digest;
                                                  sandbox closed registry)
        |
        v
evidence + feedback                              (audit/failure/flight ledgers;
                                                  feedback.py bounded adjustment)
```

CONCEPTUAL step (not in the software, labelled explicitly):

```
h × K = C0 equilibrium framing                   (CONCEPTUAL, NOT_IMPLEMENTED,
                                                  NOT_INDEPENDENTLY_VALIDATED)
```

## 10. Non-claims

MGK v0.3.0 explicitly does not claim:

- MUDA is scientifically proven in full;
- MGK proves universal AI safety;
- H14 (I != A) holds under every possible threat model;
- MGK implements the complete Malla MUDA;
- no vulnerability can exist.

Wherever such a statement would otherwise appear, the repository uses the
bounded wording: *"within the documented threat model and tested corpus."*

---

## 11. Document status

- Version: 0.3.0
- Status: canonical boundary document for MGK v0.3.0
- Bound to candidate commit and tree recorded in `evidence/v0.3.0/FINAL-CANDIDATE.json`