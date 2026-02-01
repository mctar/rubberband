# Rubberband

A lightweight security assessment tool for OpenClaw installations.

## Project context

OpenClaw (formerly Clawdbot/Moltbot) is a viral open-source AI agent framework with 135k+ GitHub stars. It's powerful but has significant security gaps: a recent ZeroLeaks assessment scored it 2/100 with 91% of injection attacks succeeding.

Rubberband helps users quickly assess and harden their OpenClaw installations. No account, no data leaves the machine, no hype.

## Core philosophy

- Ship something useful, not something perfect
- Zero config: works out of the box
- Practical fixes, not just warnings
- Complementary to OpenClaw's formal verification work (checks deployment state, not system design)

## Tech stack

- TypeScript
- Node.js (match OpenClaw's requirement: Node ≥22)
- CLI via commander or similar
- No external dependencies beyond what's needed

## Commands

```bash
rubberband scan                  # Run all checks, output report
rubberband scan --json           # JSON output for CI/CD
rubberband harden --dry-run      # Preview fixes
rubberband harden                # Apply safe defaults
rubberband harden --strict       # Maximum lockdown
```

## Scanner modules

### 1. Network (src/scanner/network.ts)
- Gateway binding (0.0.0.0 vs 127.0.0.1)
- Auth token configured when exposed
- Control UI auth bypass flag
- Webhook authentication
- Tailscale exposure detection

### 2. Credentials (src/scanner/credentials.ts)
- Config file permissions (should be 600)
- Plaintext secrets in openclaw.json
- .env file permissions
- State directory permissions
- Known API key patterns (OpenAI, Anthropic, GitHub, Slack)

### 3. Access (src/scanner/access.ts)
- DM policy per channel (open vs pairing vs allowlist)
- allowFrom restrictions
- Group mention requirements
- Pairing code expiry

### 4. Skills (src/scanner/skills.ts)
- Unverified skill sources
- Dangerous permissions (filesystem:write, shell:execute, etc.)
- Heartbeat fetching external URLs
- Checksum integrity verification
- Known malicious skills list
- Moltbook skill warning (fetches instructions periodically)

### 5. Runtime (src/scanner/runtime.ts)
- Logging level (debug/trace exposes content)
- Log file permissions
- Rate limiting enabled
- Browser sandbox mode
- Shell execution restrictions
- Model selection (weak models = weaker injection resistance)
- Memory encryption
- Auto-update settings

## Output format

```
rubberband v0.1.0

[CRITICAL] Gateway exposed on 0.0.0.0:18789 without auth
  → Set gateway.host to 127.0.0.1 or configure auth token

[HIGH] OpenAI API key readable by all users
  → Run: chmod 600 ~/.openclaw/openclaw.json

[HIGH] DM policy allows unknown senders
  → Set channels.whatsapp.dmPolicy to "pairing"

[MEDIUM] 3 skills installed from community sources
  → Review: moltbook-skill, weather-plugin, auto-shopper

[LOW] Verbose logging may expose message content
  → Set logging.level to "info" in production

──────────────────────────────────
Score: 34/100
Critical: 1 | High: 2 | Medium: 1 | Low: 1
──────────────────────────────────
```

## Severity levels

- **CRITICAL**: Immediate exploitation risk (exposed gateway, leaked keys, malicious skills)
- **HIGH**: Significant risk requiring prompt action (weak permissions, open DM policy)
- **MEDIUM**: Should be addressed (unverified skills, verbose logging)
- **LOW**: Best practice recommendations

## Hardening

The hardener applies fixes automatically. Map finding codes to remediation functions:

- NET001 → Bind gateway to localhost
- CRED001 → Fix config file permissions (chmod 600)
- ACCESS001 → Set DM policy to pairing
- ACCESS003 → Require mentions in groups
- RUN003 → Enable rate limiting
- RUN004 → Enable browser sandbox (strict mode)
- RUN006 → Disable shell execution (strict mode)

## File structure

```
rubberband/
├── src/
│   ├── index.ts           # CLI entry point
│   ├── scanner/
│   │   ├── index.ts       # Orchestrates all scanners
│   │   ├── network.ts
│   │   ├── credentials.ts
│   │   ├── access.ts
│   │   ├── skills.ts
│   │   └── runtime.ts
│   ├── hardener/
│   │   └── index.ts
│   ├── reporter/
│   │   ├── console.ts     # Pretty terminal output
│   │   └── json.ts        # JSON for CI/CD
│   └── utils/
│       ├── config.ts      # Load/save OpenClaw config
│       └── types.ts       # TypeScript interfaces
├── package.json
├── tsconfig.json
├── README.md
├── LICENSE                # MIT
└── CLAUDE.md
```

## OpenClaw config location

Default: `~/.openclaw/openclaw.json`
Can be overridden via `--config` flag or `OPENCLAW_CONFIG_PATH` env var.

## Key OpenClaw config paths to check

- `gateway.host`, `gateway.port`, `gateway.authToken`
- `controlUI.enabled`, `controlUI.dangerousDeviceAuthBypass`
- `webhooks.enabled`, `webhooks.requireAuth`
- `channels.[whatsapp|telegram|discord|etc].dm.policy`
- `channels.[channel].allowFrom`
- `channels.[channel].groups.*.requireMention`
- `shell.enabled`, `shell.allowedCommands`
- `browser.enabled`, `browser.sandbox`, `browser.headless`
- `logging.level`, `logging.file`
- `rateLimit.enabled`
- `memory.persistent`, `memory.encrypted`
- `updates.autoInstall`

## README opener

> **Rubberband** keeps your claws safe until you're ready.
>
> A zero-config security scanner for OpenClaw. No account, no data leaves your machine, no hype. Just a quick assessment and practical fixes.
>
> Built by Gervi Labs.

## Development notes

- Match OpenClaw's Node version requirement (≥22)
- Keep dependencies minimal
- All checks should run offline (except optional malicious skills list fetch)
- Fail gracefully if OpenClaw isn't installed
- Support both npm global install and npx usage
