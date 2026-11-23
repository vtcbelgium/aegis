# Aegis User Guide — Simple, Everyday Protection for Your AI Assistants

**Aegis is a free, open-source safety lock that sits between your AI assistant and your computer.**

It runs 100% offline on your own device, needs no account, costs zero AI tokens, and makes every decision using fixed, predictable rules—never another AI model that a clever prompt could talk around.

> **The Golden Rule:** *Aegis can only say "No" or "Ask the owner first." It can never grant an AI extra permission.*

---

## 60-Second Quick Start

### Option A: Open the Control Center App (Recommended)

* **No Python needed:** Download `aegis-desktop-windows-x64.exe`, `aegis-desktop-macos`, or `aegis-desktop-linux-x64` from [GitHub Releases](https://github.com/vtcbelgium/aegis/releases/latest) and run it.
* **Or via Python (3.9+):**
```bash
pip install git+https://github.com/vtcbelgium/aegis.git
aegis ui
```
This opens the **Aegis Control Center** in your browser (`http://127.0.0.1:9999`) where you can:
1. Click **Connect AI Apps** to turn on protection for Claude Code, Gemini CLI, Cursor, or Claude Desktop (Aegis backs up your config first).
2. Click **Run All 32 Safety Drills** to verify every lock works offline.
3. Adjust **Protection Rules** visually—saved safely to `~/.aegis/policy.json`, where AI agents cannot edit it.
4. Click **Scan a Folder** to check any project for leaked passwords or common security holes.

### Option B: One-Line Terminal Setup
```bash
aegis setup          # Auto-connects detected Claude Code / Gemini CLI hooks (creates a backup)
aegis doctor         # Shows your protection status, diary integrity, and connected AI apps
```

### Option C: Browser Protection ("Aegis AI Shield")
Protects you when using AI browser assistants (or reading webpages with AI):
1. Download `aegis-ai-shield-extension-1.0.0.zip` from GitHub Releases (or use the `browser-extension/` folder).
2. In **Chrome / Edge / Brave**, open `chrome://extensions`, turn on **Developer mode**, and click **Load unpacked** → select `browser-extension/`.
3. In **Firefox**, open `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** → select `browser-extension/manifest.json`.
4. Click the blue shield icon in your toolbar to pause, trust specific sites, or view blocked traps.

---

## What Aegis Protects You From (In Plain English)

1. **Folder Fence (Labyrinth):** Keeps AI inside the project folder you picked. Blocks snooping in SSH keys (`~/.ssh`), cloud logins (`~/.aws`), browser password folders, startup scripts, and `.env` secrets.
2. **Command & Delete Guard (Tartarus):** Checks terminal commands (Windows PowerShell/CMD, Mac, Linux) and database queries before they run. Stops disk wipes (`rm -rf /`, `format C:`), disguised commands, and asks before large deletes (>100 items or >500 MB) or destructive `git` actions.
3. **Secret & Leak Shield (Custody):** Catches real API keys, private keys, and tokens so AI cannot leak them. Blocks uploads to anonymous paste/file-drop sites (`transfer.sh`, `pastebin.com`, `webhook.site`) and blocks hidden cloud-server attacks (`169.254.169.254`, `.sslip.io`).
4. **Runaway Loop Brake (Hecatoncheires):** Stops an AI stuck repeating the exact same action or hammering blocked rules, locking the session automatically.
5. **Decoy Tripwires (Minotaur):** Plants harmless fake credential files in places normal work never touches. If a hijacked AI reads one or repeats a fake key, Aegis freezes the session instantly.
6. **3-Step Data-Theft Alarm (Minotaur Leak Guard):** Watches for the classic hijack combo—AI read private data + AI read untrusted web/doc text + AI tries to send data out—and stops to ask you first.
7. **Exact Confirmation for Destructive Actions:** Never lets you accidentally click "OK" on a dangerous delete. Shows exact file counts/sizes and requires typing a clear confirmation phrase.
8. **Self-Protection & Tamper-Proof Diary:** AI cannot turn Aegis off, clear its logs, delete backups, or unlock itself. Every decision is chained with SHA-256 hashes (with secrets automatically blurred out).
9. **AI Plugin Guard (MCP Proxy & Tool Pinning):** Wraps MCP plugins, scrubs hidden prompt-injection instructions out of replies, and alerts you if a plugin secretly changes its tools later ("rug pull").
10. **Offline Folder Security Scanner (`aegis audit`):** Scans any folder for hardcoded keys and common OWASP code weaknesses—locally, offline, for free.
11. **Web Browser Shield:** Removes hidden AI hijack text planted on websites (invisible 0px fonts, zero-width tricks, English/Dutch/French/German/Spanish traps) and blocks hidden tracking/data-theft image beacons.
12. **Linux Sandbox Jail (Linux only):** On Linux with `bubblewrap`, runs commands inside an isolated jail where the system is read-only, secrets are hidden, and the internet is off by default.
13. **32 Offline Safety Drills (`aegis dojo`):** Verifies all protections using harmless mock inputs—never runs real commands or touches your files.

---

## Honest Limits (What Aegis Is *Not*)
* **Not a PC antivirus or WordPress malware cleaner:** Aegis guards your computer and files against *AI assistants*. It does not scan Windows `.exe` files for viruses or clean hacked PHP websites.
* **OS Sandbox is Linux-only today:** Rule-based blocking works on Windows, macOS, and Linux. Full process containerization (`bubblewrap`) currently requires Linux; Windows and macOS honestly report unavailable rather than faking a sandbox.
* **One layer of good hygiene:** Always keep backups and give AI tools only the folders they need.
