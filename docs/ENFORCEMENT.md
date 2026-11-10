# Enforcement and migration

Aegis is the shared deterministic engine. Labyrinth checks paths; Tartarus checks commands
and supplies Linux OS confinement; Custody checks credentials and destinations;
Hecatoncheires brakes repetition; Minotaur correlates session evidence. The old OTHRYS books
provide the doctrine, rather than a second engine that must be kept in sync.

## Host responsibilities

The host must intercept every executable tool, provide the actual working directory and
stable session identity, enforce a refusal, and authenticate approvals itself. A PASS adds no
authority. Aegis cannot secure a tool path that bypasses its interceptor.

The owner controls policy and AEGIS_HOME. Keep security state outside agent-writable roots;
the same operating-system user can otherwise tamper with files without going through the gate.
Text checks are an additional layer, not a replacement for OS access controls.

An approval callback is a trusted host capability. It must bind the owner decision to the
exact action and arguments, expire it, prevent reuse, and re-evaluate before execution.
It must never treat a model's generic reply as approval. DENY and LOCK cannot be approved.
The engine refuses an approval that finishes after the session has become LOCKed.

## Durable hooks

The generic evaluator serializes read/evaluate/write under one cross-process session lock.
Session names are hashed to prevent collisions and path traversal. Original 1.0 session files
are still read during migration, preserving existing quarantines. LOCK does not expire after
24 hours; ordinary Minotaur evidence has its own bounded time window.

Malformed session state, unreadable tripwire registries, failed locks and failed ledger writes
stop evaluation. A corrupted registry is not interpreted as an empty registry. Receiving a
canary in a post hook persists the quarantine for the next pre hook. Disabling the data-leak
heuristic leaves tripwire detection enabled.

Do not let agents choose a new session identifier to evade an existing quarantine. An owner
reset is a privileged host operation; deleting session files is not a reset API for agents.

## Ledger guarantees

Hook integrations record all decisions. In-process integrations opt in by supplying
`DecisionLedger` to the gate. Appends and rotations share an OS file lock; archive filenames
are unique even when many rotations occur within one second. Logging failure propagates to
the enforcing caller instead of silently losing evidence.

The hash chain detects edits, missing initial entries and broken links. A chain alone cannot
prove that complete tail entries or entire archives have not been removed, or that someone
with write access has not recomputed the chain. Retain rotated archives, and keep trusted tip
digests on a separate trusted system. `ledger.verify(expected_tip=...)` and
`aegis ledger verify --expect-tip ...` detect a mismatch with that checkpoint. Verification
of a rotated file's incoming link requires the preceding archive's trusted tip via
`verify(path, expect_previous=...)`; it is not an automatic audit of every archive.

Recognized credential signatures and long opaque tokens are redacted. Pattern-based redaction
cannot identify every possible password; protect the ledger as sensitive owner data.

## Linux confinement

`aegis sandbox probe` runs the same launcher/profile path as real execution. Linux and working
unprivileged user namespaces plus bubblewrap are required. Windows and macOS fail closed;
there is no automatic unconfined fallback.

The default profile provides a writable workspace, read-only runtime mounts, private PID/IPC/
UTS/user/network namespaces, dropped capabilities, a minimal environment and fresh devices.
Network sharing is an explicit host option. System roots cannot be writable extra roots.

Project secret files and home credential stores are masked; protected state can be declared
through policy paths; named backup folders are mounted read-only. File masks use read-only
empty files and directory masks use read-only empty mounts. The scanner does not follow
symlinks and refuses oversized scans. Do not expose unreviewed roots containing secrets under
unrecognized names. Provision required dependencies before running with networking disabled.

Containment tests use a disposable workspace and verify ordinary output writes, hidden project
secrets, read-only backups, missing host files, stripped inherited secrets, and loopback-only
network interfaces. These are exercised with real bubblewrap on Linux; other hosts skip that
live test and still run profile and unavailable-host regressions.

## Hooks and catalogues

`aegis hook --format json` emits a neutral decision object. `--format exit` returns 2 for
ASK/DENY/LOCK, including post-tool canary detection. The default format targets Claude Code;
other products must adapt to their own documented hook contract. Tool normalization is
vendor-neutral and does not imply identical host protocols.

MCP pinning is opt-in on a proxy, requiring both `tool_pins` and a stable `server_id`. Review
and pin catalogues explicitly. Tools remain unavailable until a matching catalogue is seen,
and catalogue drift clears the accepted tool set. Fingerprints cover descriptions, input and
output schemas, and annotations. Pinning does not inspect a server's implementation.
