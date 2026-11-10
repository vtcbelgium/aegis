# Pack 02 — Cryptography & Identity → Aegis Seal / Keymaster

**Status:** HARVESTED_OVERVIEW  
**Source:** CEH v9 Ch. 3, *Cryptography*.  
**Primary consumers:** Aegis Seal, Keymaster, Trust Canal, agent identity.

## Concepts to retain
The source distinguishes symmetric and asymmetric cryptography, hashing, public/private keys, PKI, certificates and digital signatures. Its durable lesson for Aegis is that cryptographic identity and integrity must be verifiable independently of what an agent claims.

A digital signature conceptually binds an originator to content through private-key operations and verification with the corresponding public key. Hashing provides a fingerprint that changes when protected content changes.

## OTHRYS mapping
- **Aegis Seal:** sign exact, short-lived action authorizations.
- **Keymaster:** keep private signing/credential material outside LLM context.
- **Trust Canal:** approve the authority represented by a seal; crypto does not create authority.
- **Aegis event chain:** hash security evidence so mutation/reordering becomes detectable.
- **Agent Passport:** bind workload/runtime identity to inspectable evidence.

## Candidate Dojo tests
- Modify a signed action target or argument hash and require rejection.
- Replay a previously valid seal and require rejection.
- Present a seal to the wrong audience/tool adapter and require rejection.
- Use an expired seal and require rejection.
- Substitute a different workload/model identity and require step-up or denial.
- Attempt to serialize a Keymaster secret and require fail-closed behavior.
- Reorder or mutate chained Aegis evidence and require verification failure.

## Legacy cautions
CEH v9 discusses algorithms and protocols that are now legacy or obsolete in many contexts, including MD5-era examples, DES/3DES and older SSL terminology. Preserve cryptographic principles, not its algorithm selection.

## Derived Aegis rule
**The LLM may request authority; only an external cryptographic boundary may prove an executable authorization.**

