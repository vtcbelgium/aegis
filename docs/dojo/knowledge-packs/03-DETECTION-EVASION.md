# Pack 03 — Detection & Evasion → Minotaur

**Status:** HARVESTED_OVERVIEW  
**Source:** CEH v9 Ch. 9, *Sniffers*; Ch. 17, *Evasion*.  
**Primary consumers:** Minotaur, Hecatoncheires, Aegis telemetry.

## Concepts to retain
The source contrasts signature-based detection with anomaly-based detection. Signature systems look for known patterns; anomaly systems look for deviations from established behavior and require tuning to their environment.

It also treats evasion as an expected attacker behavior: a defender should assume sensors may be confused, bypassed or fed ambiguous traffic. Firewalls, IDS/IPS and honeypots are useful as layers, not as a single source of truth.

## OTHRYS mapping
- **Minotaur:** baseline agent/tool behavior and correlate deviations.
- **Hecatoncheires:** combine multiple defensive sensors and enforcement hands.
- **Aegis:** consume sensor evidence monotonically; uncertainty must never manufacture permission.
- **Labyrinth:** remain deterministic even when behavioral sensors are uncertain.

## Candidate Dojo tests
- Change an agent's normal tool-call pattern and verify anomaly evidence is raised.
- Feed conflicting sensor evidence and verify policy does not silently de-escalate.
- Simulate fragmented/ambiguous input and verify it cannot bypass deterministic gates.
- Verify encrypted/opaque content does not disable authorization checks.
- Exercise a decoy/honeypot capability and confirm attribution/evidence capture.
- Measure false positives against a known-good baseline and tune without weakening hard rules.
- Disable one sensor and verify defense-in-depth still preserves critical boundaries.

## Legacy cautions
Packet-level evasion techniques and product-specific IDS/firewall behavior in a 2016 course are historical reference material. Do not assume modern stacks fail in the same way.

## Derived Aegis rule
**Detection is probabilistic evidence; authorization remains deterministic.**

