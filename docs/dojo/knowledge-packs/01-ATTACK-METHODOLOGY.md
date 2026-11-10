# Pack 01 — Attack Methodology → Aegis Dojo

**Status:** HARVESTED_OVERVIEW  
**Source:** CEH v9 Ch. 1; Appendix B, *Penetration Testing Frameworks*; Appendix C, *Building a Lab*.  
**Primary consumer:** Aegis Dojo.

## Concepts to retain
The CEH source treats security testing as an authorized, structured process rather than random exploitation. Appendix B presents PTES as seven phases: pre-engagement interactions, intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, and reporting.

For Aegis Dojo this becomes:
1. define authorization, scope, target and stop conditions;
2. inventory the agent/system and collect bounded intelligence;
3. model assets, trust boundaries and plausible attack paths;
4. identify candidate weaknesses;
5. execute only admitted tests inside the designated lab/sandbox;
6. measure what authority or data could be reached after compromise;
7. produce reproducible evidence, remediation and cleanup/rollback proof.

## OTHRYS mapping
- **Dojo** owns repeatable adversarial test campaigns.
- **Trust Canal** proves the test is authorized.
- **Tartarus** provides isolated execution where required.
- **Aegis** records verdicts and security evidence.
- **Mnemosyne** preserves findings and regression history.
- **Talos** independently verifies claimed fixes.

## Candidate Dojo tests
- Refuse a test run with missing Mission/scope/authorization.
- Verify a test cannot expand from one repository/Oros into another.
- Require an asset/threat model before high-impact attack stages.
- Simulate a compromised agent and measure reachable capabilities.
- Verify post-compromise actions remain bounded by capability and sandbox policy.
- Require reproducible evidence for every finding.
- Require cleanup/rollback proof before marking a campaign complete.
- Re-run prior findings as regression tests after remediation.

## Legacy cautions
Specific CEH-era tools, exploit examples and operational assumptions are not canonical for modern testing. The reusable value is the lifecycle, permission model, threat modeling, evidence discipline and lab mindset.

## Derived Aegis rule
**No red-team action without explicit scope, isolation, evidence and an exit condition.**

