# Guardrails-as-Code for AI Security Programs

> White Paper: *Earning the safety claim the Maker–Checker architecture makes*

A technical deep-dive into the engineering discipline behind the Rego guardrail library that backs AI-orchestrated security automation.

**Published:** April 2026

## Read the White Paper

👉 [View White Paper](https://krunalpatel1107.github.io/guardrails-as-code-for-ai-security-programs/whitepaper)

## About

This repository is a research archive for the whitepaper **"Guardrails-as-Code for AI Security Programs."**

The paper argues that the safety property of an AI-orchestrated security architecture — *AI proposes, deterministic code disposes* — is only as strong as the Rego library that implements the Checker. It covers:

- The distinction between policy-as-code generally and guardrails-as-code as a safety-gate discipline
- The CDM input contract, schema versioning, and fail-closed behavior on unknown CDM versions
- A four-tier rule taxonomy: hard prohibitions, conditional constraints, hygiene rules, and advisory rules
- The exception model — deny-by-default with validated, expiring, audit-visible exceptions
- Testing discipline: `opa test`, fixture isolation, coverage enforcement on blocking-tier rules
- The rule authoring lifecycle, including the advisory → enforcing promotion path and recursive Maker–Checker governance of the library itself
- Honest limits of Rego: where graph analyzers, SMT solvers, and purpose-built analyzers must take over
- A full worked example tracing CA-IDENT-042 through a denial-and-revision cycle, end to end

## Topics

`rego` `open-policy-agent` `policy-as-code` `guardrails` `ai-security` `devsecops` `conftest` `maker-checker` `zero-trust` `everything-as-code`

---

Part of a broader security research series.
Companion paper: [The AI-Orchestrated Central Security Nervous System](https://krunalpatel1107.github.io/AI-Orchestrated-SecuritySystems/whitepaper)
