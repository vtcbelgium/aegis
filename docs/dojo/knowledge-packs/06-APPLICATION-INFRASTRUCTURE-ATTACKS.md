# Pack 06 — Application & Infrastructure Attacks → Aegis Self-Test

**Status:** HARVESTED_OVERVIEW  
**Source:** CEH v9 Ch. 7 System Hacking; Ch. 8 Malware; Ch. 11 DoS; Ch. 12 Session Hijacking; Ch. 13 Web Servers and Applications; Ch. 14 SQL Injection; Ch. 18 Cloud Technologies and Security.  
**Primary consumers:** Aegis Dojo, Aegis web/control plane, OTHRYS infrastructure.

## Concepts to retain
The source repeatedly tests systems at trust boundaries: authentication, privilege, sessions, input handling, resource availability, application/data separation, and cloud identity/access controls.

For Aegis itself, the important lesson is that an agent-security product can still fail through ordinary application and infrastructure vulnerabilities. The control plane must be tested as software, not treated as secure because its purpose is security.

## OTHRYS mapping
- **Aegis Dojo:** regression tests against the Aegis control plane and adapters.
- **Trust Canal:** authorization and privilege boundary.
- **Keymaster:** credential/session secret custody.
- **Tartarus:** isolate suspicious code/dependencies.
- **Web/API surfaces:** validate input, authorization, session handling and data access.
- **Rhea/Sentinel:** availability and recovery evidence.

## Candidate Dojo tests
- Attempt an authorization bypass across roles/Missions and require denial.
- Feed malformed/untrusted input through web/API surfaces and verify safe handling.
- Exercise database inputs with non-destructive injection test cases and require parameterized/safe behavior.
- Reuse or substitute a session/token outside its intended identity/scope and require rejection.
- Simulate resource exhaustion and verify budgets/circuit breakers preserve control-plane availability.
- Attempt privilege escalation from a low-capability agent and verify no authority expansion.
- Test cloud/service identity boundaries with least privilege and explicit scope.
- Verify malware-like or unexpected executable artifacts are isolated before privileged execution.

## Legacy cautions
Named malware, exploit tools, web stacks and cloud products in CEH v9 are historical. Modern Aegis self-testing should map these concepts to current OWASP ASVS, API, agentic and MCP guidance before implementation.

## Derived Aegis rule
**Aegis must withstand both agent-specific attacks and ordinary software-security failures.**

