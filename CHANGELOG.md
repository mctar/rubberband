# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-01

### Added

- Initial release
- `scan` command with console and JSON output
- `harden` command with dry-run and strict modes
- Network scanner: gateway binding, auth tokens, control UI bypass, webhooks
- Credentials scanner: file permissions, plaintext API keys (OpenAI, Anthropic, GitHub, Slack)
- Access scanner: DM policies, allowFrom restrictions, group mention requirements
- Skills scanner: malicious skills detection, dangerous permissions, verification status
- Runtime scanner: logging levels, rate limiting, browser sandbox, shell restrictions, memory encryption
- Security score (0-100) based on findings
- Exit code 2 for CI/CD integration when critical issues found
- `--demo` flag to try without OpenClaw installed
