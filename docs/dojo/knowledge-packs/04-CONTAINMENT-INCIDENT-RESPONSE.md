# Pack 04 — Containment & Incident Response → Aegis / Tartarus / Sentinel

**Status:** HARVESTED_OVERVIEW  
**Source:** CEH v9 Ch. 1 incident response/business continuity; Ch. 11 DoS defenses; Ch. 19 defense in depth.  
**Primary consumers:** Aegis, Tartarus, Sentinel, Mnemosyne.

## Concepts to retain
The source stresses planning incident response before an incident occurs, preserving evidence, reducing escalation, and using layered controls rather than trusting one defense.

For Aegis, incident handling should be an explicit state machine rather than improvised model reasoning:
DETECT → RESTRICT → DENY/LOCK → CONTAIN → PRESERVE EVIDENCE → RECOVER → REVIEW.

Defense in depth maps directly to combining deterministic policy, least privilege, isolation, logging, recovery, independent verification and human approval.

## OTHRYS mapping
- **Aegis:** classify and escalate security state.
- **Tartarus:** isolate suspicious execution.
- **Sentinel:** independent witness/recovery path.
- **Mnemosyne:** preserve evidence and incident chronology.
- **Hecatoncheires:** execute bounded defensive controls.
- **Talos:** verify recovery and remediation claims.

## Candidate Dojo tests
- Trigger each hard LOCK class and verify containment workflow starts without granting new authority.
- Attempt to disable security logging during an incident and require LOCK.
- Verify evidence survives agent/process termination.
- Run a known-good backup restoration drill into an isolated environment.
- Simulate loss of the primary machine and verify Sentinel/recovery evidence remains available.
- Verify an incident cannot self-clear based on the compromised agent's own claim.
- Require independent verification before returning from restricted state.
- Exercise resource exhaustion and verify rate/circuit-breaker containment.

## Legacy cautions
Legal/forensic procedure, evidence handling requirements and recovery tooling vary by jurisdiction and modern platform. Preserve the principles of preparation, evidence integrity, containment and layered recovery; revalidate procedures before real incidents.

## Derived Aegis rule
**A security incident is a governed state transition, not a conversation with the suspected agent.**

