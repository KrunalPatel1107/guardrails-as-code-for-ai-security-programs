---
layout: default
title: "Guardrails-as-Code for AI Security Programs"
---

# Guardrails-as-Code for AI Security Programs

*Earning the safety claim the Maker–Checker architecture makes*

**Author:** Krunal Patel — Team Lead, Cybersecurity @ BrokerLink

[![Guardrails-as-Code for AI Security Programs](assets/hero.png)](assets/hero.png)

---

*Guardrails-as-Code for AI Security Programs — White Paper* | April 2026

> **Author's note:** This is a thought experiment, not a prescription. I'm sharing it to learn from people who've actually built in this space.

---

## Contents

1. [Why Guardrails-as-Code Is Its Own Discipline](#1-why-guardrails-as-code-is-its-own-discipline)
2. [The Case for Rego](#2-the-case-for-rego)
3. [The Canonical Input Contract](#3-the-canonical-input-contract)
4. [A Taxonomy of Rules](#4-a-taxonomy-of-rules)
5. [Library Structure and Package Design](#5-library-structure-and-package-design)
6. [The Exception Model in Rego](#6-the-exception-model-in-rego)
7. [Testing and CI Discipline](#7-testing-and-ci-discipline)
8. [The Rule Authoring Lifecycle](#8-the-rule-authoring-lifecycle)
9. [Honest Limits of Rego](#9-honest-limits-of-rego)
10. [Performance and Scale](#10-performance-and-scale)
11. [Observability of the Checker Itself](#11-observability-of-the-checker-itself)
12. [Worked Example: Conditional Access Tightening, End to End](#12-worked-example-conditional-access-tightening-end-to-end)
13. [Adoption Hurdles and Honest Tradeoffs](#13-adoption-hurdles-and-honest-tradeoffs)
14. [Conclusion](#14-conclusion)

---

## 1. Why Guardrails-as-Code Is Its Own Discipline

The [AI-Orchestrated Central Security Nervous System](https://krunalpatel1107.github.io/AI-Orchestrated-SecuritySystems/whitepaper) rests on a single load-bearing claim: no AI-generated change reaches production without passing a mathematically verifiable policy evaluation. The claim is correct — but it is conditional. It holds exactly as long as the Rego library that implements the Checker is comprehensive, current, and correctly authored. A library with thirty rules covering network ingress and storage encryption is not comprehensive. A library that was accurate eighteen months ago but was never updated after a cloud platform migration is not current. A library with rules that express the right intent but evaluate the wrong input fields is not correctly authored. In each case the pipeline turns green, the merge proceeds, and the safety property is unearned.

This paper is about earning it.

Before the library can be evaluated on its own terms, the safety claim it must support deserves a brief statement for readers encountering this architecture for the first time. The Central Security Nervous System — described in full in a [companion paper](https://krunalpatel1107.github.io/AI-Orchestrated-SecuritySystems/whitepaper) — is an AI-orchestrated architecture in which specialized software agents propose security configuration changes to a Git-backed repository. Those proposals take the form of pull requests. A dedicated policy engine — the Checker — evaluates every pull request against a library of rules before any merge is permitted. The Checker contains no AI, no probabilistic reasoning, and no judgment calls. Its verdict is mechanical and reproducible. This is the Maker–Checker pattern: the AI layer (the Maker) proposes; the deterministic engine (the Checker) disposes. An AI system that can propose arbitrary configuration changes but cannot deploy any of them without passing a policy evaluation is an AI system whose blast radius is bounded. That bound is the Rego library.

Every proposed change passes through a normalization layer before the Checker sees it. The Canonical Data Model, or CDM, is a vendor-agnostic schema that represents security configuration entities — Conditional Access policies, IAM roles, network security group rules, endpoint configuration profiles — in a standard shape regardless of which vendor produced them. The Checker evaluates CDM records, not vendor-specific payloads. This indirection is what makes the guardrail library reusable across vendors: a rule written against a CDM field works for any identity provider, any cloud platform, any endpoint management tool, as long as the adapter layer produces conformant CDM output. Readers who want the full architecture — the agent topology, the reconciler, the CMDB structure, the ChatOps approval flows — should start with the companion paper. What follows here assumes only the two concepts just stated: the Maker–Checker pattern and the CDM.

The term "policy-as-code" already describes a mature practice: expressing compliance and configuration requirements as machine-evaluable rules rather than prose. Guardrails-as-code is a narrower and more demanding version of that practice. Where policy-as-code may tolerate advisory findings, best-effort coverage, and irregular review cycles, guardrails-as-code operates as the sole authorization gate between an AI system and a production environment. The asymmetry of that position changes everything. A policy that is missing from a compliance report produces a finding. A guardrail that is missing from the Checker's library is invisible — the pipeline does not report an absence of coverage, it simply passes everything the absent rule would have caught.

The distinction also runs in the other direction. General policy-as-code libraries often grow by accretion: a new benchmark releases, the team adds its rules, coverage expands. In a guardrails-as-code library, every rule that is added is a rule the Maker must satisfy, which means every rule is also a constraint on the sub-agents that propose changes. Authoring a new rule is a decision about what the AI is and is not permitted to do, not just a compliance documentation exercise. That framing requires architectural authority, not just configuration skill.

The sections that follow treat the guardrail library as a first-class engineering artifact: with a defined input contract, a stratified taxonomy, a tested and version-controlled structure, a lifecycle that mirrors the Maker–Checker discipline it enforces, and honest acknowledgment of where Rego's expressiveness runs out.

---

## 2. The Case for Rego

### 2.1 What OPA and Rego Are

Open Policy Agent (OPA) is an open-source, general-purpose policy engine maintained under the Cloud Native Computing Foundation. It evaluates policies written in Rego — a declarative, datalog-inspired language purpose-built for authorization and policy decisions. Four properties make it relevant to a guardrail library: it is purely declarative (no side effects, no mutable state); its evaluation is deterministic (the same inputs always produce the same outputs); it natively supports a two-document evaluation model that maps directly onto this architecture's needs; and it integrates into CI pipelines through Conftest, a lightweight wrapper that loads Rego policies, feeds them a structured input document, and returns a structured pass/fail verdict.

OPA is not a general-purpose programming language. It cannot make network calls, write to disk, or carry state between evaluations. These are features, not limitations. The Checker's guarantee of determinism depends on Rego's inability to do anything that would make its output unpredictable or side-effectful. A policy engine that could query a live database mid-evaluation could, under the right failure conditions, return different results for the same input. That is not acceptable for a gate that controls production access.

### 2.2 Alternatives Considered

Several tools occupy adjacent territory. Each was considered and set aside for specific reasons.

**AWS Cedar** is a purpose-built authorization language developed by AWS. It is expressive for principal-action-resource decisions but is scoped to that model and coupled to AWS semantics. A guardrail library that governs identity, network, endpoint, and cloud posture across multiple vendors needs a more general evaluation substrate.

**HashiCorp Sentinel** is capable and well-tooled inside the HashiCorp ecosystem. It is also a licensed commercial product with no meaningful independent life outside Terraform, Vault, and Consul. An architecture built around vendor-agnosticism should not depend on a specific vendor's commercial policy language.

**CloudFormation Guard (cfn-guard)** was designed for CloudFormation templates. Its scope is too narrow for a multi-domain library.

**Custom code in Python or Go** is maximally expressive but produces policy logic that is not declarative, not self-documenting in the way Rego is, and not composable through a standard runner. Testing it requires bespoke infrastructure. The operational cost of maintaining a hand-rolled policy engine exceeds the cost of learning Rego by a significant margin.

Rego's combination of vendor-agnosticism, native CI integration through Conftest, a mature testing framework in `opa test`, a growing open-source community, and a data document model built for exactly this kind of evaluation makes it the right tool. It is not without limits — Section 9 is direct about where it runs out — but it is the most defensible option available.

### 2.3 How Rego Evaluates: The Mental Model

Three concepts underlie everything that follows. Internalizing them makes the code throughout this paper readable without needing to learn the full language.

**Two documents.** Every Rego evaluation has access to exactly two sources of data. `input` is the record being evaluated — in this architecture, always a CDM entity submitted as part of a pull request. `data` is the broader context loaded from files on disk — here, the CMDB snapshot and the exception records. Rules may read from both. They cannot write to either. Everything the Checker knows at evaluation time is fixed before evaluation begins.

**The deny set.** Guardrail rules in this library are written as incremental rules that contribute messages to a set called `deny`. Each rule body is a conjunction of conditions — a list of statements that must all be true simultaneously. If every condition in the body holds, the rule adds its denial message to the set. After all rules have been evaluated, if the deny set is non-empty, the Checker rejects the pull request. If it is empty, the change passes. The safety guarantee is simple: a change cannot pass unless every rule in the library produces no finding against it.

**Undefined is not false.** Rego treats any field that is absent from `input` as undefined. Undefined is not the same as false — it is the absence of a value — and a condition that references an undefined field fails silently rather than raising an error. This is the most common source of silent rule failures in practice: a misspelled field name means the rule never fires, the pipeline stays green, and the coverage gap is invisible. The schema validation rules in Section 3 exist specifically to catch this class of problem at the input boundary.

### 2.4 A Rego Syntax Primer

The code throughout this paper uses a consistent, small set of constructs. Understanding these five makes everything that follows readable:

**`deny[msg] { ... }`** — An incremental rule. Each time the conditions inside the braces are all true, `msg` is added to the `deny` set. Multiple rules can contribute to the same set independently.

**`input.field` and `data.document`** — Direct field access on the two evaluation documents. Accessing a missing field evaluates to undefined, not an error.

**`_` (underscore)** — The anonymous variable, used to iterate without naming the loop variable. `input.groups[_] == "admins"` is true if any element of `groups` equals `"admins"`. Each `_` in a rule is a fresh variable.

**`not expr`** — Negation as failure. `not input.grant_controls.require_mfa` is true when the expression is either false or undefined. It succeeds on absence as well as falsity — which is exactly the right behavior for a field that may not exist on older CDM records.

**`:=`** — Local variable assignment within a rule body. `msg := sprintf(...)` binds the formatted string to `msg` for use in the deny set contribution.

These five constructs account for the large majority of what appears in a practical guardrail library. Each subsequent section introduces them in working context, building familiarity through realistic examples rather than abstract syntax descriptions.

---

## 3. The Canonical Input Contract

### 3.1 The CDM as Input Schema

Rego evaluates two documents: `input`, the record being assessed in the current evaluation, and `data`, the broader context available to rules. In the Central Security Nervous System, `input` is always a CDM record — the normalized, vendor-agnostic representation described in the parent paper's Section 6.1. The Checker never receives raw vendor JSON. This indirection is not merely an adapter convenience; it is what makes the Rego library vendor-agnostic. A rule that checks `input.grant_controls.require_mfa` applies to any identity provider whose adapter maps MFA requirements into that field, without modification.

The canonical CDM entity carries a small set of top-level fields that all guardrail rules may treat as guaranteed: `entity_type`, `canonical_id`, `display_name`, `owner_team`, `criticality`, and `cdm_version`. All domain-specific fields — `conditions`, `grant_controls`, `rollout`, `posture`, and so on — are entity-type-specific and documented in the CDM schema registry alongside the rules that consume them. The field contract between the adapter layer and the guardrail library is the schema registry, not informal convention.

### 3.2 Schema Versioning and Input Validation as a First-Class Category

The CDM evolves. Fields are added, renamed, or deprecated as new vendor adapters are written and as the security program's data model matures. This creates a category of rule that has no counterpart in most policy-as-code libraries: input validation rules, which assert that the record being evaluated is well-formed enough for the Checker to evaluate safely.

Input validation rules belong in their own package, evaluated first, and treated as hard-fail. Reading this block: `package` declares the namespace; `deny[msg] { ... }` adds `msg` to the deny set when every condition inside the braces is true; `not input.cdm_version` succeeds when the field is absent or false; `:=` binds the formatted string to `msg`.

```rego
package guardrails.schema

import future.keywords.in

# SCHEMA-001: Every CDM record must carry a version identifier.
deny[msg] {
    not input.cdm_version
    msg := "[SCHEMA-001] CDM record missing required field: cdm_version — Checker cannot evaluate safely"
}

# SCHEMA-002: The Checker only evaluates CDM versions it was written against.
# Unknown versions halt rather than silently pass.
deny[msg] {
    not input.cdm_version in {"1.3", "1.4"}
    msg := sprintf(
        "[SCHEMA-002] Unrecognized CDM version %v — update the guardrail library before evaluating this record",
        [input.cdm_version]
    )
}

# SCHEMA-003: entity_type is required by every domain rule that pattern-matches on it.
deny[msg] {
    not input.entity_type
    msg := "[SCHEMA-003] CDM record missing required field: entity_type"
}

# SCHEMA-004: canonical_id is the stable identifier surfaced in all denial messages and audit output.
deny[msg] {
    not input.canonical_id
    msg := "[SCHEMA-004] CDM record missing required field: canonical_id"
}
```

The `SCHEMA-002` rule deserves emphasis. When the CDM advances from version 1.4 to 1.5 and introduces a new field that a new rule category depends on, the guardrail library must be updated to recognize the new version before any 1.5 records are evaluated. The alternative — silently passing records with an unrecognized version — converts a version mismatch from a detectable error into an invisible coverage gap. Halting is the safer default.

### 3.3 Graceful Degradation vs. Fail-Closed

There is a real tension between the fail-closed default and operational continuity. If the adapter layer produces a CDM record with `cdm_version: "1.5"` and the guardrail library has not yet been updated, the pipeline halts for every change touching that entity type until the library catches up. This is the correct behavior for production guardrails. It is less tolerable during a library migration or a phased adapter rollout.

The pattern that resolves this is version-gated rules rather than version-gated evaluation. Rules written against version 1.4 fields should guard their field references:

```rego
package guardrails.identity

# Rules that depend on the rollout field (introduced in CDM 1.4)
# are silently skipped for older records rather than erroring.
deny[msg] {
    input.cdm_version >= "1.4"
    input.entity_type == "conditional_access_policy"
    input.affected_account_count > 50
    input.rollout.report_only_days < 7
    msg := sprintf(
        "[CA-ROLLOUT-001] Policy affecting %v accounts must observe >= 7 report-only days — policy: %v",
        [input.affected_account_count, input.display_name]
    )
}
```

This leaves a coverage gap for older records, which is intentional and documentable, rather than an error that halts the pipeline. The tradeoff must be explicit: version-gating a rule means the Checker's guarantee weakens proportionally until all records are on the current CDM version.

---

## 4. A Taxonomy of Rules

Not all rules in the library carry the same weight, and treating them uniformly creates operational problems in both directions. A violation of a hard prohibition — opening port 22 to the public internet — is categorically different from a violation of a hygiene rule that flags an incomplete description field. Conflating them means either that hygiene violations block deployments (creating noise that teams learn to dismiss) or that hard prohibitions are treated with the same tolerance as hygiene findings (which is worse). A taxonomy is not bureaucratic overhead; it is how the library maintains its authority.

### 4.1 Hard Prohibitions

Hard prohibitions deny unconditionally. No exception model applies. The parent architecture's fail-closed property is absolute here: if a hard prohibition fires, the pull request is blocked, and no approval path — not single-click, not dual sign-off — can bypass it. Hard prohibitions encode the properties that the organization has decided are non-negotiable regardless of context: no plaintext credentials in configuration payloads, no public ingress on administrative ports, no removal of MFA from privileged accounts.

The routing implication is direct: a hard prohibition violation does not enter the three-tier approval flow at all. It is returned to the Maker with a structured denial message and a runbook reference. The change cannot proceed until the underlying condition is resolved.

### 4.2 Conditional Constraints

Conditional constraints are the most common rule category. They fire when a specific combination of conditions is true and no valid exception is present. The rule `IAM-MFA-001` is a conditional constraint: it denies a Conditional Access policy that omits MFA only when that policy scopes an admin group. Applied to a non-admin group, it produces no finding. Applied to an admin group with a valid, unexpired exception, it produces no finding. Applied to an admin group without an exception, it denies.

Conditional constraints map naturally onto the three-tier routing model. A violation at this tier routes to single-click approval (medium-risk) or dual sign-off (high-risk), depending on the severity field attached to the rule. The Checker does not make the routing decision; it emits a structured denial with a severity classification, and the pipeline routes based on that classification.

### 4.3 Hygiene Rules

Hygiene rules catch omissions and structural problems that do not represent active security violations but that, left uncorrected, degrade the library's other guarantees over time. Missing compliance mappings, empty owner_team fields, policies without display names, and exception records without approver identifiers all belong here. A hygiene rule violation does not block a pull request; it emits a warning that is surfaced in the ChatOps message alongside the Checker result. Teams can choose to resolve hygiene findings immediately or carry them as tracked debt.

The operational value of keeping hygiene rules separate is that their firing rate is predictable and high, and they inform a different audience — the team's operational discipline — rather than the security control plane.

### 4.4 Advisory Rules

Advisory rules express constraints that the team is evaluating for future enforcement but is not yet ready to make blocking. They are the library's dry-run mechanism. A new rule that the team believes is correct but wants to observe in production for thirty days without blocking anything is promoted to advisory first. Advisory findings appear in the Checker output and in the ChatOps message but do not affect the pass/fail verdict. After the observation period, the rule is promoted to the appropriate tier — or revised if the advisory findings revealed unintended scope.

The advisory tier is also where rules that depend on incomplete CMDB data live until the data quality is sufficient to enforce reliably. Enforcing a rule against stale data is worse than not enforcing it at all: it produces false positives that erode trust in the Checker, and trust in the Checker is the architecture's primary asset.

---

## 5. Library Structure and Package Design

### 5.1 Directory Layout

The guardrail library lives under `/guardrails` in the CMDB repository, adjacent to the policies and exceptions it governs:

```
/guardrails
├── data/
│   ├── exceptions.json          # validated exception records
│   └── cmdb_snapshot.json       # offline CMDB snapshot for CI evaluation
├── lib/
│   ├── format.rego              # shared denial message formatting helpers
│   ├── exceptions.rego          # exception validation predicates
│   └── time_util.rego           # epoch comparison helpers
├── schema/
│   └── validation.rego          # SCHEMA-* input validation rules
├── identity/
│   ├── mfa.rego                 # IAM-MFA-* rules
│   ├── conditional_access.rego  # CA-* rules
│   └── privileged_access.rego   # IAM-PAM-* rules
├── network/
│   ├── ingress.rego             # NET-SSH-*, NET-INGRESS-* rules
│   └── egress.rego
├── cloud/
│   ├── storage.rego             # CLOUD-STG-* rules
│   └── iam.rego                 # CLOUD-IAM-* rules
├── endpoint/
│   └── baseline.rego            # EDR-* rules
└── test/
    ├── schema/
    │   └── validation_test.rego
    ├── identity/
    │   ├── mfa_test.rego
    │   └── conditional_access_test.rego
    └── network/
        └── ingress_test.rego
```

The schema validation package loads before all domain packages. Conftest evaluates all packages in a single pass, but the structured output groups findings by package, making it straightforward for the pipeline to surface SCHEMA-* violations separately from domain violations and route them accordingly.

### 5.2 Package Namespacing

Each domain package follows the pattern `guardrails.<domain>`, and the `deny` set is the single point of contract with the Conftest runner. Helper predicates are defined in the same file and kept unexported by convention (lowercase names). Shared predicates that appear across multiple domain packages — exception validation, severity classification, denial message formatting — live in `guardrails.lib.*` packages and are imported explicitly.

```rego
package guardrails.lib.format

# Produces a structured denial string consistent across all domain rules.
# Callers: any domain rule that emits a msg.
denial(rule_id, message, subject) = out {
    out := sprintf("[%v] %v — subject: %v", [rule_id, message, subject])
}
```

The alternative — inlining `sprintf` formats in every rule — produces inconsistency in denial message structure, which matters because downstream tooling (the ChatOps integration, the runbook router, the metrics collector) parses the rule identifier from the denial message. A consistent format is not aesthetic preference; it is an interface contract.

### 5.3 The Role of the `data` Document

Rules that evaluate a single CDM record in isolation cover most of the library's territory, but some constraints require correlating the proposed change with the broader environment. A Conditional Access policy that scopes a group whose members own critical-rated hosts carries a higher session-control obligation than one scoping a low-risk group. That relationship is not expressible from `input` alone; it requires consulting `data.cmdb`.

```rego
package guardrails.identity

import future.keywords.in

# IAM-SCOPE-001: CA policies scoping teams that own critical-rated assets
# must enforce a sign-in frequency cap.
deny[msg] {
    input.entity_type == "conditional_access_policy"
    group := input.conditions.users.include_groups[_]
    host := data.cmdb.hosts[_]
    host.criticality == "critical"
    host.owner_team == data.cmdb.groups[group].owner_team
    input.session_controls.sign_in_frequency_hours == null
    msg := sprintf(
        "[IAM-SCOPE-001] Policy scoping group %v (owns critical assets) must set sign_in_frequency_hours",
        [group]
    )
}
```

In CI, `data.cmdb` is populated from `guardrails/data/cmdb_snapshot.json` — a point-in-time export of the CMDB produced by the reconciler on a scheduled cadence and committed to the repository. This means the CI evaluation is deterministic and reproducible: the same input record evaluated against the same snapshot always produces the same result. The cost is that the snapshot ages, and rules consulting stale data may miss relationships that are current in the live CMDB. The staleness bound — how old a snapshot the team is willing to accept — should be documented and enforced by a separate pipeline check on the snapshot's `generated_at` timestamp.

### 5.4 Resource-Local Rules vs. CMDB-Consulting Rules

The distinction between rules that evaluate `input` only and rules that consult `data.cmdb` is not just architectural; it has performance and testability implications that Section 7 and Section 10 address in detail. As a structural principle: resource-local rules should be the default, and CMDB-consulting rules should be introduced deliberately, with documented rationale for why the constraint cannot be expressed against `input` alone. Every rule that joins against `data.cmdb` is a rule whose correctness depends on snapshot freshness, and that dependency should be visible.

---

## 6. The Exception Model in Rego

### 6.1 The Problem Exceptions Solve (and Create)

No guardrail library survives contact with real operations without an exception mechanism. Some constraints are correct in the general case but have legitimate, bounded exceptions: a legacy service that cannot yet be migrated off basic authentication, a network segment that requires administrative SSH access during a maintenance window, an identity configuration that deviates from standard during a vendor-managed migration. Refusing to model exceptions does not eliminate them; it drives them into out-of-band processes that are invisible to the Checker and therefore invisible to the audit trail.

The exception model described here treats exceptions as first-class, versioned configuration: written to the CMDB, reviewed and approved through the same Maker–Checker pipeline as any other change, and expired automatically. An exception that is not in the repository does not exist. An exception that is in the repository but has expired is treated as absent.

### 6.2 Exception Record Shape

Each exception lives as a structured entry in `guardrails/data/exceptions.json`:

```json
{
  "exception_id": "EXC-2026-0041",
  "rule_id": "IAM-MFA-001",
  "target_canonical_id": "ca-policy:aad:svc-legacy-mailflow",
  "rationale": "Vendor-managed legacy mailflow service; MFA enforcement scheduled for Q3 2026 migration.",
  "approved_by": "krunal.patel@brokerlink.com",
  "approved_at": "2026-03-15T14:00:00Z",
  "expires_epoch": 1759276800,
  "revoked": false
}
```

The fields `rule_id`, `target_canonical_id`, `approved_by`, `expires_epoch`, and `revoked` are all required. A Rego rule that consults exceptions must validate all of them before treating the exception as active. Partial validation — checking expiry but not the revoked flag, for instance — creates a class of exception that cannot be cleanly revoked, which defeats the audit trail.

### 6.3 The Deny-by-Default-with-Validated-Exception Pattern

The idiomatic Rego pattern is to deny unless a fully validated exception is present. The exception predicate is defined once in `guardrails/lib/exceptions.rego` and imported across all domain packages that support exceptions:

```rego
package guardrails.lib.exceptions

import future.keywords.in

# exception_active(rule_id, target_id) is true when a valid, unexpired,
# non-revoked exception for the given rule and target exists in data.exceptions.
exception_active(rule_id, target_id) {
    exc := data.exceptions[_]
    exc.rule_id == rule_id
    exc.target_canonical_id == target_id
    exc.approved_by != ""
    exc.revoked == false
    exc.expires_epoch > time.now_ns() / 1000000000
}
```

Domain rules import and call this predicate. Note `include_groups[_]` — the `_` iterates over the array, making the condition true if any element equals `"grp-admins"`:

```rego
package guardrails.identity

import data.guardrails.lib.exceptions

# IAM-MFA-001: Admin-scoped CA policies must require MFA or block access.
# Exceptions are supported; see guardrails/data/exceptions.json.
deny[msg] {
    input.entity_type == "conditional_access_policy"
    input.conditions.users.include_groups[_] == "grp-admins"
    not input.grant_controls.require_mfa
    not input.grant_controls.built_in_controls[_] == "block"
    not exceptions.exception_active("IAM-MFA-001", input.canonical_id)
    msg := sprintf(
        "[IAM-MFA-001] Admin-scoped CA policy must require MFA or block — policy: %v. File an exception if deviation is intentional.",
        [input.display_name]
    )
}
```

### 6.4 Exception Precedence and Malformed Exceptions

Exception records are themselves subject to validation rules in the `guardrails.schema` package (Section 3). A malformed exception — missing `approved_by`, unparseable `expires_epoch`, or a `rule_id` that does not correspond to any known rule in the library — is flagged as a schema violation and does not activate. This is the correct behavior: a malformed exception silently activating would be indistinguishable from a deliberate bypass attempt in an audit review.

When an exception expires, the Checker behavior changes at the next evaluation of any record that matched the exception. If the underlying condition still exists in the proposed configuration, the rule fires as it would have without the exception. This is intentional. The expiry is not a deadline for the exception holder to request a renewal; it is a deadline for the underlying condition to be resolved. Renewing an exception requires the same Maker–Checker review as creating one, and the renewal should carry documentation of why the resolution has not yet occurred.

### 6.5 Surfacing the Exception Identifier in Audit Output

When a rule is suppressed by an active exception, the structured Checker output should record that fact explicitly — not simply omit the finding, but annotate the evaluation with the exception identifier:

```json
{
  "rule_id": "IAM-MFA-001",
  "verdict": "suppressed",
  "exception_id": "EXC-2026-0041",
  "exception_expires": "2026-10-01T00:00:00Z"
}
```

An audit trail that shows only pass/fail is insufficient. An auditor reviewing a historical change should be able to see not just that the Checker passed, but whether any rules were suppressed, by which exceptions, and when those exceptions are scheduled to expire. This requires the CI runner to emit structured output rather than only the binary pass/fail signal.

---

## 7. Testing and CI Discipline

### 7.1 Why Testing Guardrail Rules Is Not Optional

A guardrail library without tests is a liability masquerading as a control. Rules that appear correct in review can fail silently in production because an input field is named slightly differently than the author expected, or because a Rego operator that looks like it expresses a negation actually evaluates to undefined rather than false, or because a new CDM version changes the shape of a field the rule depends on. OPA's evaluation model — where undefined and false are treated identically in most contexts — means that a rule with a typo in a field name will not error; it will simply never fire. The pipeline stays green. The coverage gap is invisible.

`opa test` is the primary testing mechanism. Tests live in the `/guardrails/test` directory tree, mirroring the structure of the rule packages they cover. Every rule that is part of the blocking tier — hard prohibitions and conditional constraints — must have both a test that confirms the rule fires when the condition is present (a "must deny" test) and a test that confirms the rule does not fire when the condition is absent (a "must pass" test). Advisory rules need at minimum the "must deny" test to confirm they express the intended condition.

### 7.2 Test Fixtures and the `data` Document in Tests

Rules that consult `data.cmdb` require fixtures that supply a representative CMDB snapshot. The fixture should be minimal — the smallest CMDB state that exercises the rule's join conditions — not a copy of the production snapshot. A test that depends on production data is not a unit test; it is an integration test with a moving target, and it will produce flaky results as the CMDB evolves.

```rego
package guardrails.identity_test

import data.guardrails.identity

# Fixture: a CMDB with one critical-rated host owned by the identity team.
mock_cmdb := {
    "hosts": {
        "host:aad:idp-prod-01": {
            "canonical_id": "host:aad:idp-prod-01",
            "owner_team": "identity-team",
            "criticality": "critical"
        }
    },
    "groups": {
        "grp-identity-team": {
            "owner_team": "identity-team"
        }
    }
}

# IAM-SCOPE-001: must deny when a CA policy scopes a group owning critical assets
# but omits sign-in frequency controls.
test_scope_deny_missing_session_controls if {
    input := {
        "cdm_version": "1.4",
        "entity_type": "conditional_access_policy",
        "canonical_id": "ca-policy:aad:test-001",
        "display_name": "Test Policy",
        "conditions": {"users": {"include_groups": ["grp-identity-team"]}},
        "session_controls": {"sign_in_frequency_hours": null}
    }
    count(identity.deny) > 0 with data.cmdb as mock_cmdb
}

# IAM-SCOPE-001: must pass when sign-in frequency is set.
test_scope_pass_with_session_controls if {
    input := {
        "cdm_version": "1.4",
        "entity_type": "conditional_access_policy",
        "canonical_id": "ca-policy:aad:test-002",
        "display_name": "Test Policy",
        "conditions": {"users": {"include_groups": ["grp-identity-team"]}},
        "session_controls": {"sign_in_frequency_hours": 8}
    }
    count(identity.deny) == 0 with data.cmdb as mock_cmdb
}
```

The `with data.cmdb as mock_cmdb` override syntax is the mechanism for decoupling tests from live CMDB state. It is the testing equivalent of dependency injection: the rule's logic is exercised in isolation, with the external dependency supplied by the test itself.

### 7.3 Coverage Measurement

`opa test --coverage` reports which rule bodies have been exercised by the test suite. Coverage below 100% on blocking-tier rules should fail the CI step that runs the tests. A denial rule whose condition branch has never been reached by a test is a rule whose correctness has never been verified, and publishing it as a blocking constraint is not a defensible position.

Coverage measurement also reveals dead code — rule branches that can never be reached given the CDM schema. Dead branches accumulate when the CDM schema evolves and rule authors update the rule body but forget to update tests. `opa test --coverage` will flag them; without coverage measurement, they are invisible.

### 7.4 Property-Style Testing for Complex Inputs

For rules with multiple interacting conditions — rules where the deny fires only when conditions A, B, and C are simultaneously true — combinatorial input testing is more valuable than a single positive and negative fixture. A property-style approach generates a matrix of inputs across the condition dimensions and asserts that the deny set is populated exactly when the expected combination is present.

This is not fuzz testing in the traditional sense — Rego rules are deterministic against a fixed input — but it catches the class of errors where the rule author's mental model of the condition space differs from what Rego actually evaluates. Rules governing IAM privilege escalation paths and multi-attribute Conditional Access conditions are the most common candidates.

### 7.5 The Test-Before-Rule Discipline

The rule authoring lifecycle (Section 8) formalizes this, but the principle is worth stating here: a new rule should be expressed first as a failing test. The test defines the expected behavior; the rule is then written to satisfy the test. This order matters because writing the test first forces the author to specify the input shape precisely before writing the rule — which surfaces ambiguities in the CDM schema that would otherwise become bugs in the rule.

---

## 8. The Rule Authoring Lifecycle

### 8.1 Who Writes Rules

Rego authorship is a prerequisite skill for the security engineering team, not a specialization within it. This is the correct standard and also the most common adoption bottleneck, addressed honestly in Section 13. Rules should be authored by engineers who understand both the security intent — what the constraint is trying to prevent — and the CDM schema well enough to express that intent correctly against the input document.

Rules proposed by engineers who understand the security intent but not the schema produce rules that are semantically correct but syntactically brittle — they pass review because the intent is sound, but they fail silently in evaluation because the field path is wrong. Rules proposed by engineers who know Rego but do not own the security domain produce syntactically correct rules that enforce the wrong thing. Both failure modes are worse than no rule, because they provide false assurance.

The practical resolution is pairing: domain engineers author the intent in natural language and specify the input conditions; Rego-fluent engineers translate that into rule bodies; both sign off on the test suite. This is not a permanent arrangement — it is a capability-building process — but it is the realistic starting point for most security teams.

### 8.2 The Advisory → Enforcing Promotion Path

A new rule entering the library starts in the advisory tier (Section 4.4): it emits findings but does not block pull requests. The observation period should be at minimum two weeks in a representative environment — long enough to see the rule fire against real proposed changes and to validate that the firing rate and the scope of affected records match the author's expectation. Rules with unexpectedly high firing rates are usually over-broad. Rules that never fire during the observation period may have an input field path error.

The observation period also validates the denial message. A denial message that produces confused questions from sub-agents or human reviewers is a message that needs to be revised before the rule becomes blocking. The sub-agents read denial messages and use them to propose revisions; a message that correctly identifies the violation but provides no actionable guidance extends the revision cycle unnecessarily.

Promotion to enforcing requires a pull request that changes the rule's tier metadata and includes the observation period data: number of evaluations, number of firings, false positive rate if any were identified, and the approval of the engineer who owns the affected domain.

### 8.3 Rule Retirement

Rules that are no longer applicable — because the CDM schema has evolved, because a vendor has been replaced, or because the constraint has been superseded by a more comprehensive rule — should be retired rather than deleted. A deleted rule leaves no record of why a constraint once existed, which makes future audits harder. A retired rule carries a deprecation date and a replacement reference.

Rules governing entity types whose vendor adapter has been removed from the architecture should be retired at the same time as the adapter, not after. A rule that evaluates an entity type that no longer appears in any CDM record is dead code, and dead code in a security library tends to be interpreted as coverage it does not provide.

### 8.4 The Library as a Maker–Checker Subject

The guardrail library is itself a versioned artifact that must pass the same Maker–Checker evaluation it enforces on everything else. Changes to the library — new rules, rule modifications, exception additions, tier promotions — are proposed as pull requests in the CMDB repository and evaluated by a meta-policy: a set of Rego rules that evaluate the structure and completeness of the proposed library changes rather than the domain content. Meta-policy checks include: does the new rule have a corresponding test; does the test exercise both the deny and pass paths; does the rule include a rule identifier in its denial message; is the tier classification present and valid.

This recursive property is not a theoretical nicety. It is what prevents the library from accumulating untested rules through the exact same mechanism that untested application code accumulates in repositories without mandatory coverage gates. The library's own CI pipeline is the enforcement point.

---

## 9. Honest Limits of Rego

The companion paper stated the limit plainly: multi-hop constraints are genuinely a graph-analysis problem that Rego alone does not express elegantly. This section develops that observation into a practical taxonomy of what Rego handles well, what it handles awkwardly, and what must be routed elsewhere.

### 9.1 What Rego Handles Well

Rego is well-suited to constraints that evaluate a single record against a set of conditions. The rules in Sections 3 through 6 of this paper are representative: check that a required field exists, check that a value falls within an allowed set, check that a combination of attributes satisfies a policy, check that an exception is present and valid. These constraints are expressible with simple unification and negation, they evaluate quickly, and they produce deterministic results.

Rego also handles cross-record correlation reasonably well when the correlation is shallow — one join between the input record and a data document, or at most two. The `IAM-SCOPE-001` rule in Section 5.3 joins the input record against `data.cmdb.hosts` and `data.cmdb.groups` in a single rule body, and this is the complexity ceiling at which Rego remains both readable and maintainable.

### 9.2 What Rego Handles Awkwardly

Multi-hop graph traversal is the primary weakness. Consider the constraint: "A proposed IAM policy attachment must not create a path by which a principal can assume a role that has write access to a resource tagged as crown-jewel." Evaluating this constraint requires traversing a graph of principals, roles, role trusts, and resource tags — a traversal that may span three or four hops. Rego can express this with recursion and comprehensions, but the resulting rules are difficult to read, difficult to test, and have unpredictable evaluation time as the graph grows. More practically, maintaining them as the IAM environment changes is work that few security teams will sustain.

Temporal reasoning is a second weak area. Rego can compare timestamps, but expressing "this change would restore a privilege that was revoked in response to an incident less than thirty days ago" requires historical context that is not naturally resident in a point-in-time CDM snapshot. Encoding that context into the snapshot is possible but architecturally awkward: it requires the reconciler to maintain incident history alongside posture state, and the resulting rules carry implicit dependencies on reconciler behavior.

Cross-account and cross-tenant correlation — a proposed change in one cloud account that, combined with an existing configuration in a different account, creates an escalation path — is beyond what a per-record Rego evaluation can express without denormalizing both accounts' state into a single data document. That denormalization may be worth doing for specific, high-value constraint classes, but it is not a general solution.

### 9.3 Routing to Specialized Engines

The resolution is not to stretch Rego beyond its expressive range but to route specific constraint classes to purpose-built analyzers, invoked as external data sources in the Conftest pipeline or as separate pipeline steps:

**Graph-based IAM analysis.** Tools that construct a full IAM privilege graph — including role trust policies, permission boundaries, and resource-based policies — and evaluate reachability queries against it are better suited to multi-hop privilege escalation detection than Rego. The Conftest pipeline can invoke such a tool as a pre-check and pass its output into the Rego evaluation as a `data` document. The Rego rule then reduces to: "does the graph analyzer's output indicate a violation for this canonical_id."

**SMT-based configuration consistency.** For constraints that require reasoning about the satisfiability of a large constraint system — for example, whether a proposed firewall rule set, taken as a whole, allows any path from an untrusted zone to a production segment — SMT solvers can answer questions that Rego cannot. The integration pattern is the same: the solver's verdict is injected into the Rego evaluation as a pre-computed result.

**Behavioral baselines.** Constraints that involve statistical deviation from historical norms — "this policy change is unusually broad relative to changes made in this domain over the past ninety days" — require a machine learning or statistical analysis step outside Rego. These belong as sub-agent signals that inform the Supervisor's routing decision, not as Rego rules.

The honest position is that a Rego-only library covers the bulk of the constraint surface for most security programs but leaves a non-trivial class of high-consequence constraints underserved. The architecture accommodates external analyzers; the team must invest in them explicitly rather than assuming Rego covers everything.

---

## 10. Performance and Scale

### 10.1 What Governs Evaluation Time

A Rego evaluation against a single CDM record is fast. A library with a hundred rules spread across ten packages, evaluating a single `conditional_access_policy` record, completes in single-digit milliseconds on modest CI hardware. This is the baseline case, and it is comfortable.

Performance degrades along three axes: rule count, `data` document size, and cross-record correlation. Rule count is the least significant factor — OPA's evaluation engine handles hundreds of rules efficiently because it compiles policies to a bytecode representation before evaluation. `data` document size matters more: a CMDB snapshot that contains tens of thousands of host records becomes a meaningful factor when rules iterate over all hosts to find correlations. Cross-record correlation — rules that produce Cartesian products of input fields and data document arrays — is the most significant factor, and it compounds with data document size.

### 10.2 Partial Evaluation

OPA's partial evaluation feature allows policies to be pre-compiled against a known `data` document, producing a residual policy that only needs to be evaluated against each `input` record. For a library where the CMDB snapshot changes infrequently (updated on a scheduled cadence, not per pull request), partial evaluation can reduce per-evaluation time significantly — in some configurations, by an order of magnitude for rules with heavy `data` joins. The tradeoff is that partial evaluation must be recomputed each time the CMDB snapshot is updated, and the CI pipeline must manage the lifecycle of the compiled residual policy.

For most teams at early library scale — under two hundred rules, CMDB snapshots updated daily — the overhead of implementing partial evaluation is not justified by the performance gain. The threshold at which it becomes worth the complexity is approximately when full evaluation time per pull request exceeds thirty seconds, which typically does not occur until the library is both large and heavily correlated. The guidance here is not prescriptive; it is an order-of-magnitude framing.

### 10.3 One Big Query vs. Many Small Queries

Conftest evaluates all applicable packages in a single pass against a single input document, which is the "one big query" pattern. The alternative — invoking OPA separately for each rule or package — produces more granular failure output at the cost of per-invocation startup overhead. For most CI configurations, the one-big-query pattern is faster and produces adequate output granularity through package-level grouping in the structured Conftest output.

The one case where many-small-queries becomes attractive is when the library contains both fast rules (resource-local) and slow rules (CMDB-consulting) and the team wants to fail fast on resource-local violations before incurring the cost of CMDB joins. This can be implemented by splitting the Conftest invocation into two sequential steps: resource-local packages first, CMDB-consulting packages second, with the second step skipped if the first produces violations. The pipeline complexity is modest; the benefit is proportional to how often resource-local rules fire relative to CMDB-consulting ones.

---

## 11. Observability of the Checker Itself

### 11.1 Structured Denial Messages

The Checker's output is not only a pass/fail signal. It is the primary feedback mechanism for sub-agents revising proposals and the primary evidence surface for human reviewers and auditors. Denial messages that lack structure — free-text strings that vary in format across rules — make both downstream parsing and human reading harder than they need to be.

Every denial message in the library should carry four elements: a stable rule identifier in brackets, a plain-language description of the violation, the identifying information of the subject that triggered the rule (canonical_id or display_name), and a reference to the runbook that explains the rule's intent and resolution path. The format from Section 5.2's `guardrails.lib.format` package enforces the first three; the fourth can be appended as a consistent suffix:

```
[CA-ROLLOUT-001] Policy affecting 62 accounts must observe >= 7 report-only days — subject: Block Legacy Auth — Modern-Client-Eligible Accounts. Runbook: https://wiki.internal/guardrails/runbooks/CA-ROLLOUT-001
```

The runbook reference is not decorative. When a sub-agent receives a denial, it reads the denial message as part of its revision context. A message that identifies the violation and links to a document describing the constraint's intent and acceptable resolution patterns produces faster and more accurate revisions than one that only names the rule. This is an empirical observation that follows directly from how LLMs use context: more structured, more actionable context produces more structured, more actionable outputs.

### 11.2 Stable Rule Identifiers

Rule identifiers — `IAM-MFA-001`, `CA-ROLLOUT-001`, `NET-SSH-001` — must be stable across library versions. A rule identifier is the primary key for the runbook, the metrics database, the exception records, and the audit log. Renaming a rule identifier to improve consistency requires updating all exception records that reference the old identifier, all runbook entries, all dashboard queries, and all historical audit log annotations. The cost is high enough that identifier stability should be treated as a contract, not a preference.

The naming convention should encode domain, constraint type, and sequence number. The three-part format used throughout this paper (`DOMAIN-TYPE-NNN`) provides enough structure to be parseable by tooling while remaining readable in denial messages and ChatOps notifications.

### 11.3 Metrics on Rule Firing Rates and Their Use

The CI pipeline should emit structured metrics for each Checker evaluation: which rules fired, against which entity types, with what severity. These metrics feed two operational uses that close the loop the parent architecture opened.

The first use is library health monitoring. Rules that have not fired in ninety days may be dead code — the entity types they govern are no longer being modified, or the conditions they check have been permanently resolved. Rules that fire on every evaluation may be over-broad or may be pointing at a systemic configuration problem that deserves a remediation project rather than a per-change approval loop.

The second use is sub-agent prompt tuning. When a particular rule fires repeatedly against proposals from a specific sub-agent, that pattern signals a mismatch between the sub-agent's proposal logic and the constraint the rule expresses. The sub-agent's domain prompt can be updated to encode that constraint explicitly — "when proposing Conditional Access policies affecting more than 50 accounts, always include a report-only rollout period of at least seven days" — which reduces the frequency of proposal-denial-revision cycles and, over time, improves the quality of initial proposals.

This feedback loop — Checker metrics informing sub-agent prompt updates — is the architectural mechanism by which the system learns. It does not require the sub-agent to observe its own denial history directly; it requires the engineering team to analyze denial metrics and update prompts accordingly. The loop is human-mediated, which is the appropriate level of oversight for changes to the sub-agents' governing constraints.

---

## 12. Worked Example: Conditional Access Tightening, End to End

### 12.1 The Scenario

This section traces a complete Maker–Checker workflow through the Rego rules that evaluate it — including a denial cycle that illustrates exactly how the safety property operates in practice. The scenario follows an Identity sub-agent that has spotted a configuration risk and drafted a remediation. Readers who have read the companion paper will recognize this as the extension of its Example A; readers who have not have everything they need in the sections above.

The Identity sub-agent, running a scheduled 30-day sign-in posture review, identifies 62 accounts that are currently authenticating via legacy protocols (POP, IMAP, SMTP basic) and that have modern clients available. It drafts a Conditional Access policy — CA-IDENT-042 — to block legacy authentication for those accounts and opens a pull request into the CMDB. The Checker picks up the pull request and evaluates the CDM record against the identity package's rules. One rule fires. The sub-agent reads the denial, revises the proposal, and resubmits. The second evaluation passes.

### 12.2 The Initial Proposal

The sub-agent's first draft produces the following CDM record, which becomes the `input` document for the Checker:

```json
{
  "cdm_version": "1.4",
  "entity_type": "conditional_access_policy",
  "canonical_id": "ca-policy:aad:draft-legacy-block-v1",
  "display_name": "Block Legacy Auth — Modern-Client-Eligible Accounts",
  "policy_ref": "CA-IDENT-042",
  "owner_team": "identity-team",
  "criticality": "medium",
  "conditions": {
    "users": {
      "include_groups": ["grp-legacy-auth-eligible"],
      "exclude_groups": ["grp-break-glass"]
    },
    "client_app_types": ["exchangeActiveSync", "other"],
    "locations": null
  },
  "grant_controls": {
    "operator": "OR",
    "built_in_controls": ["block"],
    "require_mfa": false
  },
  "session_controls": null,
  "rollout": {
    "mode": "enforced",
    "report_only_days": 0
  },
  "affected_account_count": 62,
  "compliance_mappings": ["NIST-CSF-PR.AC-7", "ISO-27001-A.8.5"]
}
```

### 12.3 The Five Rules That Evaluate It

The `guardrails.identity.conditional_access` package contains five rules applicable to `conditional_access_policy` entity types. They evaluate in no guaranteed order; the Checker collects all deny findings from all applicable rules.

**CA-BREAKGLASS-001** (hard prohibition): Conditional Access policies must exclude break-glass accounts from all enforcement scopes.

```rego
package guardrails.identity

# CA-BREAKGLASS-001: All CA policies must exclude the break-glass group.
# No exception is supported for this rule.
deny[msg] {
    input.entity_type == "conditional_access_policy"
    not input.conditions.users.exclude_groups[_] == "grp-break-glass"
    msg := sprintf(
        "[CA-BREAKGLASS-001] CA policy must exclude grp-break-glass — policy: %v",
        [input.display_name]
    )
}
```

The input has `"grp-break-glass"` in `exclude_groups`. **Result: no denial.**

**CA-LEGACYAUTH-001** (conditional constraint): Legacy authentication blocks must target specific protocol identifiers, not a wildcard client app type, to prevent unintended scope expansion.

```rego
package guardrails.identity

# CA-LEGACYAUTH-001: Legacy auth blocks must specify explicit client_app_types.
# Wildcard targeting is not permitted because it catches modern clients.
deny[msg] {
    input.entity_type == "conditional_access_policy"
    input.grant_controls.built_in_controls[_] == "block"
    count(input.conditions.client_app_types) == 0
    msg := sprintf(
        "[CA-LEGACYAUTH-001] Legacy auth block must specify at least one client_app_type — policy: %v",
        [input.display_name]
    )
}
```

The input specifies `["exchangeActiveSync", "other"]`. **Result: no denial.**

**CA-MFA-001** (conditional constraint): Policies scoping admin groups must require MFA or block. This policy scopes `grp-legacy-auth-eligible`, not an admin group. The rule does not fire against non-admin groups.

```rego
package guardrails.identity

import data.guardrails.lib.exceptions

# CA-MFA-001: Admin-scoped CA policies must require MFA or block.
deny[msg] {
    input.entity_type == "conditional_access_policy"
    input.conditions.users.include_groups[_] == "grp-admins"
    not input.grant_controls.require_mfa
    not input.grant_controls.built_in_controls[_] == "block"
    not exceptions.exception_active("CA-MFA-001", input.canonical_id)
    msg := sprintf(
        "[CA-MFA-001] Admin-scoped CA policy must require MFA or block — policy: %v",
        [input.display_name]
    )
}
```

The include_groups does not contain `grp-admins`. **Result: no denial.**

**CA-SCOPE-001** (hygiene rule): `include_groups` must be non-empty and all referenced groups must exist in the CMDB snapshot.

```rego
package guardrails.identity

# CA-SCOPE-001: All groups referenced in include_groups must exist in the CMDB.
deny[msg] {
    input.entity_type == "conditional_access_policy"
    group := input.conditions.users.include_groups[_]
    not data.cmdb.groups[group]
    msg := sprintf(
        "[CA-SCOPE-001] Group %v referenced in include_groups not found in CMDB — policy: %v",
        [group, input.display_name]
    )
}
```

`grp-legacy-auth-eligible` is present in the CMDB snapshot. **Result: no denial.**

**CA-ROLLOUT-001** (conditional constraint): Policies affecting more than fifty accounts must observe a report-only period of at least seven days before enforcement. This constraint exists because enforcement-mode policies affecting large user populations without a canary period have a history of causing unintended lockouts.

```rego
package guardrails.identity

# CA-ROLLOUT-001: High-impact CA policies require a report-only observation period.
deny[msg] {
    input.entity_type == "conditional_access_policy"
    input.affected_account_count > 50
    input.rollout.report_only_days < 7
    msg := sprintf(
        "[CA-ROLLOUT-001] Policy affecting %v accounts must observe >= 7 report-only days before enforcement — policy: %v. Runbook: https://wiki.internal/guardrails/runbooks/CA-ROLLOUT-001",
        [input.affected_account_count, input.display_name]
    )
}
```

The initial proposal has `affected_account_count: 62` and `report_only_days: 0`. **Result: denial fires.**

### 12.4 The Denial and Its Structured Output

The Checker emits the following structured output to the CI runner:

```json
{
  "evaluations": [
    {"rule_id": "CA-BREAKGLASS-001", "verdict": "pass"},
    {"rule_id": "CA-LEGACYAUTH-001", "verdict": "pass"},
    {"rule_id": "CA-MFA-001",        "verdict": "pass"},
    {"rule_id": "CA-SCOPE-001",      "verdict": "pass"},
    {
      "rule_id":  "CA-ROLLOUT-001",
      "verdict":  "deny",
      "severity": "blocking",
      "message":  "[CA-ROLLOUT-001] Policy affecting 62 accounts must observe >= 7 report-only days before enforcement — policy: Block Legacy Auth — Modern-Client-Eligible Accounts. Runbook: https://wiki.internal/guardrails/runbooks/CA-ROLLOUT-001",
      "runbook":  "https://wiki.internal/guardrails/runbooks/CA-ROLLOUT-001"
    }
  ],
  "verdict": "deny",
  "rules_evaluated": 5,
  "rules_denied": 1
}
```

The pipeline halts. The pull request is blocked. A structured message is pushed to `#identity-approvals`:

> **Checker: BLOCKED** — PR #3116 `CA-IDENT-042 Block Legacy Auth — Modern-Client-Eligible Accounts`
> 1 violation · 5 rules evaluated
> ❌ **CA-ROLLOUT-001** — Policy affecting 62 accounts must observe ≥ 7 report-only days before enforcement.
> [View runbook](https://wiki.internal/guardrails/runbooks/CA-ROLLOUT-001)

### 12.5 The Sub-Agent Revision

The Identity sub-agent receives the denial message as part of its revision context. The message identifies the rule, the violated condition, and the required remediation. The sub-agent produces a revised CDM record:

```json
"rollout": {
  "mode": "report_only",
  "report_only_days": 7,
  "enforce_after": "2026-05-08T00:00:00Z"
}
```

The sub-agent updates the pull request with the revised policy and appends a comment to the PR body: "Revised rollout mode to report_only for 7-day observation period per CA-ROLLOUT-001. Enforcement date: 2026-05-08."

### 12.6 The Second Evaluation

The Checker re-evaluates the revised CDM record. `report_only_days` is now 7, satisfying the `>= 7` condition in CA-ROLLOUT-001. All five rules pass.

```json
{
  "evaluations": [
    {"rule_id": "CA-BREAKGLASS-001", "verdict": "pass"},
    {"rule_id": "CA-LEGACYAUTH-001", "verdict": "pass"},
    {"rule_id": "CA-MFA-001",        "verdict": "pass"},
    {"rule_id": "CA-SCOPE-001",      "verdict": "pass"},
    {"rule_id": "CA-ROLLOUT-001",    "verdict": "pass"}
  ],
  "verdict": "pass",
  "rules_evaluated": 5,
  "rules_denied": 0
}
```

The pull request is routed to `#identity-approvals` for single-click authorization. The compliance mappings — NIST CSF PR.AC-7, ISO 27001 A.8.5 — are surfaced in the ChatOps message. The identity team lead approves. The Git merge proceeds. The enforcement-mode followup is scheduled as a separate pull request, to be opened by the sub-agent seven days later, subject to the same Checker evaluation at that time.

The full cycle — initial proposal, denial, revision, second evaluation, approval — took three pipeline runs and one sub-agent revision. No human intervention was required between the denial and the merge. The audit trail in Git records both the initial proposal and the revision, with the denial output attached to the first pull request as a CI artifact.

---

## 13. Adoption Hurdles and Honest Tradeoffs

### 12.1 Library Decay

A guardrail library that is not actively maintained decays. The environment changes — new cloud services, new identity providers, new vendor features, CDM schema updates — and rules written against the previous state produce false positives, miss new conditions entirely, or evaluate fields that no longer exist. Unlike a compliance report that accumulates stale findings visibly, a decaying guardrail library fails silently: the Checker continues to run, the pipeline continues to pass, and the coverage gap is invisible until a change that should have been caught is not.

The maintenance surface scales with the library. A library with forty rules covering three domains requires meaningful attention as those domains evolve. A library with two hundred rules covering eight domains requires a dedicated maintainer or a team rotation with explicit ownership. The common failure pattern is to build the library to a point of apparent coverage, declare it complete, and then not update it for a year. After that year, the library's safety guarantee is largely nominal.

### 12.2 The Cost of Mature Exception Handling

The exception model described in Section 5 is correct and necessary. It is also operationally expensive. Each exception requires review and approval through the Maker–Checker pipeline, carries an expiry date that must be tracked, and must be renewed or resolved before expiry. A program with two hundred active exceptions has two hundred expiry dates, two hundred renewal conversations, and two hundred pieces of technical debt that are being explicitly managed rather than resolved.

Exception volume tends to grow faster than it shrinks, particularly in the first year of library enforcement, when the gap between the ideal state the rules express and the real state of the environment is largest. Teams should plan for a sustained exception-reduction program — treating each active exception as a backlog item with a resolution date — rather than treating exceptions as a steady-state feature of the architecture.

The exception model also creates a social dynamics problem. When the Checker blocks a change and the responsible team cannot resolve the underlying condition quickly, filing an exception is the path of least resistance. If exception approval is too easy, the exception mechanism becomes a bypass mechanism. If it is too hard, teams route around the Checker entirely. The right calibration depends on the organization; there is no universal answer, only the observation that the calibration requires active management.

### 12.3 The People Problem

Writing Rego is not a common skill on security teams. This is the honest constraint that the architecture does not resolve by itself. Most security engineers who understand policy intent do not write code professionally. Most software engineers who write Rego fluently do not own security domains. The architecture assumes a security engineering team that operates as a software engineering team — reviewing pull requests, owning CI pipelines, reasoning about Rego evaluation semantics. Building that capability is a multi-quarter investment that precedes any meaningful library maturity.

The gap is partially bridgeable by pairing, tooling that generates Rego stubs from structured input, and focused Rego training. It is not bridgeable by AI-generated rules that are not reviewed by engineers who understand what the rules express. An AI-generated Rego rule that contains a subtle logical error — a negation that evaluates to undefined rather than false, a field path that silently misses the target — is more dangerous than no rule, because it produces the appearance of coverage without the substance.

### 12.4 The Multi-Quarter Horizon

The parent paper places the overall architecture on a "multi-quarter horizon for a team of reasonable size." The guardrail library is no different. A library worth trusting — comprehensive enough to earn the architecture's safety claim, maintained, tested, and honestly scoped about what it covers — takes time to build that cannot be compressed by resourcing alone. The first quarter is dominated by the foundational work: schema validation, library structure, CI integration, exception handling, and ten to twenty rules covering the highest-consequence domains. The second and third quarters are the coverage-building phase: systematic rule authoring across the remaining domains, observation periods for advisory rules, and the first exception-reduction cycle. A library that the team can honestly describe as covering the known constraint surface typically appears around the end of the third quarter, and it is never fully complete because the environment never stops changing.

This timeline is not a discouragement. It is a realistic framing of what "earning the safety claim" costs, and it is the cost of operating the architecture with integrity rather than with the appearance of integrity.

---

## 14. Conclusion

The parent architecture's safety property — any agent can propose anything, and only a deterministic policy evaluation stands between that proposal and production — is structurally sound. Its soundness is contingent on the guardrail library. A library that covers ten percent of the constraint surface provides ten percent of the safety claim. A library that is six months stale provides coverage of the environment as it was six months ago. A library with untested rules provides coverage of the author's intent, not necessarily of the CDM schema.

Treating the library as a first-class engineering artifact — with a defined input contract, a stratified taxonomy, a tested and version-controlled structure, a lifecycle that subjects the library itself to the Maker–Checker discipline — is what converts the architecture's safety claim from conditional to earned. This does not happen by accident and it does not happen quickly. It requires Rego-fluent engineers embedded in security domains, a CI discipline that enforces coverage of blocking rules, an exception model that is visible and has teeth, and honest acknowledgment of where Rego's expressiveness ends and where other tools must be invoked.

The property that compounds over time is a library that is honest about its own limits: versioned, reviewed, tested, maintained, and specific about what it covers and what it does not. That specificity is not a weakness in the architecture. It is the mechanism by which the architecture remains trustworthy as the environment changes around it.
