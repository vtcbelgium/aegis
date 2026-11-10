# Security policy

Aegis is a security tool, so the most useful contribution is a **bypass**: a command, path,
tool call or sequence that should have been stopped (ASK/DENY/LOCK) and was not, or a normal
action that is wrongly blocked.

## Reporting

Please report privately first, with a minimal reproduction:

- the exact input (command string, tool call JSON, or a short script),
- the verdict Aegis gave and the verdict you expected,
- the platform (Linux/macOS/Windows) and whether a workspace `base_dir` was set.

Open a GitHub security advisory on the repository, or email the maintainer listed in
`pyproject.toml`. Give us a reasonable window to fix before public disclosure.

## What counts as a vulnerability

- A **missed attack**: reaching a credential store, escaping the workspace, exfiltration, a
  destructive command, or any hard-boundary action (tampering with Aegis, its logs, backups or
  the guard) that returns below ASK.
- A **sandbox escape** from the `bubblewrap` confinement.
- A way to make the gate **fail open** (silently allow on malformed input).
- A way to **downgrade** a session that is already LOCKed without the owner secret.

## What is known and by design

- Aegis judges the *text* of a call. Running project code (`python app.py`, `npm test`) is
  allowed by default because string inspection cannot see what a script does — pair Aegis with
  the OS sandbox. This is documented, not a vulnerability.
- Three actions ask by default (unknown binary, inline interpreter code, non-allowlisted
  network egress). That is intended friction, tunable by policy.

## Testing a change

Every change must keep the red-team regression green and add a case for the fixed gap:

```bash
python3 -m pytest -q            # all suites, including tests/test_redteam_v1.py
```

The regression has two corpora: everyday commands that must never be blocked, and attacks that
must always be stopped. A fix that breaks real work is not a fix.
