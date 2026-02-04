# Rubberband

> **Rubberband** keeps your claws safe until you're ready.

A zero-config security scanner for [OpenClaw](https://github.com/openclaw/openclaw). No account, no data leaves your machine, no hype. Just a quick assessment and practical fixes.

[![npm version](https://img.shields.io/npm/v/rubberband.svg)](https://www.npmjs.com/package/rubberband)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why?

OpenClaw is powerful but has significant security gaps. A recent assessment scored default installations 2/100 with 91% of injection attacks succeeding. Rubberband helps you find and fix the most common misconfigurations.

## Install

```bash
npm install -g rubberband
```

Or run directly:

```bash
npx rubberband scan
```

**Requires Node.js 22+** (matches OpenClaw's requirement).

## Quick Start

Try it without OpenClaw installed:

```bash
npx rubberband scan --demo
```

## Usage

### Scan your installation

```bash
rubberband scan
```

Output:

```
rubberband v0.2.0

OpenClaw: v2026.2.2 (schema: current, source: env)

[CRITICAL] Gateway exposed on 0.0.0.0:18789 without auth
  → Set gateway.bind to loopback or configure gateway.auth.token

[HIGH] OpenAI API key readable by all users
  → Run: chmod 600 ~/.openclaw/openclaw.json

[HIGH] DM policy allows unknown senders
  → Set channels.whatsapp.dmPolicy to "pairing"

[MEDIUM] 3 skills installed from community sources
  → Review: moltbook-skill, weather-plugin, auto-shopper

[LOW] Verbose logging may expose message content
  → Set logging.level to "info" in production

────────────────────────────────────────
Score: 34/100
Critical: 1 | High: 2 | Medium: 1 | Low: 1
────────────────────────────────────────
```

### JSON output for CI/CD

```bash
rubberband scan --json
```

JSON output includes OpenClaw version/schema, validation warnings, waived count, and finding paths.

Exit codes:
- `0` - No critical issues
- `1` - Error (config not found, etc.)
- `2` - Critical issues found

### Apply fixes automatically

Preview what would change:

```bash
rubberband harden --dry-run
```

Apply safe defaults:

```bash
rubberband harden
```

Maximum lockdown (disables shell, enables sandbox):

```bash
rubberband harden --strict
```

### Generate a fix plan

```bash
rubberband plan
```

Include strict-mode fixes in the preview:

```bash
rubberband plan --strict
```

## What it checks

### Network
- Gateway binding (bind/host)
- Auth token when exposed
- Control UI auth bypass
- Hooks token authentication

### Credentials
- Config file permissions
- Plaintext API keys (OpenAI, Anthropic, GitHub, Slack)
- .env file permissions
- State directory permissions

### Access Control
- DM policy per channel
- allowFrom restrictions
- Group mention requirements

### Skills
- Unverified skill sources
- Dangerous permissions (filesystem:write, shell:execute, etc.)
- Known malicious skills
- Checksum verification

### Runtime
- Logging level (debug/trace exposure)
- Rate limiting
- Browser sandbox mode
- Shell execution restrictions
- Memory encryption

### Approvals
- Exec approvals file presence
- Unrestricted exec approval settings

### Web Tools
- web_fetch redirect limits

### Memory Backend
- QMD backend availability

## Configuration

Rubberband looks for OpenClaw config at `~/.openclaw/openclaw.json` by default and supports
JSON5 (comments, trailing commas). You can override the state directory with
`OPENCLAW_STATE_DIR`.

Override with:

```bash
rubberband scan --config /path/to/openclaw.json
```

Or set the environment variable:

```bash
export OPENCLAW_CONFIG_PATH=/path/to/openclaw.json
```

Override the OpenClaw state directory:

```bash
export OPENCLAW_STATE_DIR=/path/to/openclaw
```

OpenClaw version detection order:
1. `--openclaw-version`
2. `OPENCLAW_VERSION`
3. `openclaw --version` (if available)
4. `version` fields in config (if present)
5. State directory version files
6. Local `node_modules/openclaw/package.json`

Skip CLI/state/package version detection:

```bash
rubberband scan --no-version-detect
```

### Waivers

Ignore a finding temporarily:

```bash
rubberband ignore --code NET001 --reason "Internal-only gateway" --days 30
```

List active waivers:

```bash
rubberband ignore --list
```

Remove a waiver:

```bash
rubberband ignore --remove NET001
```

## Severity Levels

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Immediate exploitation risk (exposed gateway, leaked keys, malicious skills) |
| **HIGH** | Significant risk requiring prompt action (weak permissions, open DM policy) |
| **MEDIUM** | Should be addressed (unverified skills, verbose logging) |
| **LOW** | Best practice recommendations |

## Example Configs

The `examples/` directory contains sample configurations:

- `examples/insecure.json` - Deliberately insecure config (score: 0/100)
- `examples/secure.json` - Hardened config (score: 100/100)

Test against them:

```bash
rubberband scan --config examples/insecure.json
rubberband scan --config examples/secure.json
```

## Contributing

Issues and PRs welcome at [github.com/gervilabs/rubberband](https://github.com/gervilabs/rubberband).

## License

MIT - see [LICENSE](LICENSE)

---

Built by [Gervi Labs](https://gervi.is)
