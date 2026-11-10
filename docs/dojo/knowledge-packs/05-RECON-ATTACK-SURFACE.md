# Pack 05 — Recon & Attack Surface → Labyrinth / Inventory

**Status:** HARVESTED_OVERVIEW  
**Source:** CEH v9 Ch. 2 system/network fundamentals; Ch. 4 Footprinting; Ch. 5 Scanning; Ch. 6 Enumeration.  
**Primary consumers:** Labyrinth, capability registry, Aegis inventory, Prometheus discovery.

## Concepts to retain
The source separates passive information gathering, active scanning and enumeration. The durable security lesson is that defenders need an accurate inventory before they can defend an estate.

For Aegis, attack surface includes more than hosts and ports:
- agents and runtimes;
- MCP servers and tools;
- APIs and endpoints;
- credentials and capability classes;
- repositories/filesystem scopes;
- network destinations;
- scheduled/automated actions;
- stale, shadow or unregistered integrations.

## OTHRYS mapping
- **Labyrinth:** compare requested actions against known/admitted surfaces.
- **Capability Registry:** inventory available tools/providers and readiness.
- **Aegis:** flag drift and unknown surfaces.
- **Prometheus:** discover opportunities/gaps without granting authority.

## Candidate Dojo tests
- Introduce an unregistered MCP/tool and verify it is discovered and not automatically trusted.
- Expose an unexpected listening service and verify inventory drift is recorded.
- Attempt access to a stale/disabled provider and require denial or quarantine.
- Probe repeated resource names and verify enumeration/rate evidence is raised.
- Request an unknown network destination and require explicit policy handling.
- Detect a capability present on disk but absent from the admitted registry.
- Verify passive discovery never becomes execution authority.

## Legacy cautions
Specific scan tools, default ports, service weaknesses and enumeration techniques age quickly. Use the reconnaissance model and inventory discipline; do not treat CEH v9's tool lists as a current attack-surface catalog.

## Derived Aegis rule
**Unknown surface is not trusted surface. Discovery may create evidence, never authority.**

