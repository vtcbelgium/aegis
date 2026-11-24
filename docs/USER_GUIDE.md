# Aegis Quick Manual

**Aegis is an offline safety lock that sits between your AI assistants and your computer.**

It runs 100% locally on loopback `127.0.0.1`, needs no account, uses zero AI tokens, and makes every decision with fixed, predictable rules instead of another AI model.

> **The Supreme Law:** *Aegis may subtract authority. Aegis may never create it.*

---

## How Aegis Works (in 30 Seconds)

1. **Before an AI acts (Guard):** Every terminal command, file edit, and URL passes through offline deterministic rules. Safe work runs normally; dangerous actions pause for you (`ASK`) or get blocked (`DENY` / `LOCK`). Every decision is recorded in a tamper-evident SHA-256 diary (`~/.aegis/ledger.jsonl`).
2. **After an AI replies (Detective — Clan Lynceus):** Cross-examines what the AI claims ("all tests passed") against real recorded command exits, files on disk, and git diffs so agents cannot fabricate green test runs or quietly weaken your test suite.
3. **Across your machines (Tekton Integration):** When a local Tekton runtime is installed, the **Tekton** tab inside Aegis shows your live fleet nodes, allowed folders, pending approvals, and lets you push your Aegis policy floor down into Tekton with one click.

---

## Opening Aegis

- **Desktop Icon:** Double-click **Aegis** on your Desktop (or Start Menu). Clicking it again focuses the running app instead of spawning duplicates.
- **Terminal:** Run `aegis desktop` (chromeless desktop window) or `aegis ui` (default browser at `http://127.0.0.1:9999`).
- **Stopping cleanly:** Open **Settings** and click **Stop server** -> **Confirm stop**.

---

## Tour of the 7 Tabs

| Key | Tab | What You Do Here |
| :--- | :--- | :--- |
| `1` | **Guard** | Test any shell command or text snippet safely without running it, run all **42 offline safety drills**, and search/filter or export your **Decision diary**. |
| `2` | **Detective** | Switch Detective mode (`Off`, `Passive`, `Strict`), turn on **Freeze test files** during bug fixes, scan your git diff for tampered tests, or verify a draft AI reply against real evidence. |
| `3` | **Approvals** | Approve once or deny paused `ASK` actions. Destructive deletes show exact blast-radius counts and require typing a confirmation phrase. |
| `4` | **Apps** | Turn Aegis protection on or off for Claude Code, Gemini CLI, Cursor, Claude Desktop, Antigravity IDE, and VS Code. Aegis always backs up your config file first and skips double-wrapping native Tekton MCP entries. |
| `5` | **Tekton** | View Tekton version, pinned `aegis-gate` version, monotonic policy floor (`Sync policy floor`), live fleet nodes, allowed workspaces (`Add folder` / `Remove`), pending Tekton approvals, and **Open Tekton GUI**. |
| `6` | **Settings** | Switch between `Balanced` and `Strict` posture, plant Minotaur decoy tripwires, change the **Active workspace**, scan any folder offline for keys/OWASP issues, copy diagnostics, export diary, or stop the background server. |
| `7` or `?` | **Help** | Built-in quick manual, verdict guide, copy-ready CLI commands, keyboard shortcuts, FAQ, and one-click **Copy diagnostics** / **Export diary**. |

---

## What Each Verdict Means

- **`PASS`** — Safe. Allowed automatically and logged.
- **`WARN`** — Allowed with an advisory note.
- **`ASK`** — Paused in **Approvals** until you approve once or deny.
- **`DENY`** — Blocked immediately; the agent can keep working on safe tasks.
- **`LOCK`** — Severe breach (such as reading `~/.ssh` keys or touching a decoy tripwire). The session freezes until *you* click **Unlock session** on **Guard**. Agents can never unlock themselves.

---

## Keyboard Shortcuts

- `1` through `7` — Switch tabs (`Guard` through `Help`)
- `/` — Jump to the command check box on **Guard**
- `R` — Refresh the active tab
- `?` — Open **Help**
- `Esc` — Leave the current input field

---

## Everyday Terminal Commands

```bash
aegis doctor                                          # Health, diary chain, and connected apps
aegis explain "git reset --hard"                      # Dry-run verdict without running the command
aegis audit .                                         # Offline scan for exposed keys & OWASP issues
aegis detective status                                # Detective mode, checkpoints, and operator tips
aegis detective verify-reply --text "All tests pass"  # Cross-examine an agent reply
aegis mcp wrap --server demo -- npx -y @modelcontextprotocol/server-filesystem .
aegis pins diff --server demo --tools tools.json      # Inspect MCP tool schema changes
```

---

## Browser Extension (Aegis AI Shield)

Protects browser-based AI assistants from hidden prompt-injection traps on web pages and secret-leaking image beacons:
1. Open `chrome://extensions` (Chrome, Edge, Brave, or BrowserOS).
2. Enable **Developer mode**.
3. Click **Load unpacked** and pick the `browser-extension/` folder (or extract `aegis-ai-shield-extension-*.zip` from GitHub Releases).

---

## Troubleshooting & Diagnostics

- **Session locked unexpectedly?** Check the top entries in **Guard -> Decision diary** to see exactly what triggered `LOCK`, then click **Unlock session**.
- **Need to report an issue or inspect paths?** Open **Help** (or **Settings**) and click **Copy diagnostics** — this copies a clean, secret-free JSON snapshot of your versions, file paths, ledger integrity, and Tekton link.
- **Where files live:** Rules are in `~/.aegis/policy.json`, diary in `~/.aegis/ledger.jsonl`, and Tekton's synced floor in Tekton's data folder (`aegis/policy.json`).

## Honest Limits

- **Not a general antivirus:** Aegis guards your workstation against *AI assistant actions*, not traditional OS malware.
- **OS container sandbox (`bubblewrap`) is Linux-only today:** Rule enforcement works on Windows, macOS, and Linux; Windows and macOS honestly report `Rules only`.
- **Keep backups:** Aegis is a deterministic safety layer, not a replacement for Git commits and backups.
