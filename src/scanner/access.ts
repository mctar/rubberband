import type { Finding, OpenClawConfig } from '../utils/types.js';

export function scanAccess(config: OpenClawConfig): Finding[] {
  const findings: Finding[] = [];

  if (!config.channels) {
    return findings;
  }

  for (const [channelName, channelConfig] of Object.entries(config.channels)) {
    // Check DM policy
    const dmPolicy = channelConfig.dm?.policy;
    if (dmPolicy === 'open') {
      findings.push({
        code: 'ACCESS001',
        severity: 'high',
        title: `${channelName}: DM policy allows unknown senders`,
        detail: `Channel ${channelName} has dm.policy set to "open", allowing anyone to send commands.`,
        recommendation: `Set channels.${channelName}.dm.policy to "pairing" or "allowlist"`,
        fixable: true,
      });
    }

    // Check allowFrom restrictions
    const allowFrom = channelConfig.allowFrom;
    if (!allowFrom || allowFrom.length === 0) {
      if (dmPolicy !== 'allowlist') {
        findings.push({
          code: 'ACCESS002',
          severity: 'medium',
          title: `${channelName}: No allowFrom restrictions`,
          detail: `Channel ${channelName} has no allowFrom list configured.`,
          recommendation: `Configure channels.${channelName}.allowFrom with trusted identifiers`,
          fixable: false,
        });
      }
    }

    // Check group mention requirements
    if (channelConfig.groups) {
      for (const [groupName, groupConfig] of Object.entries(channelConfig.groups)) {
        if (!groupConfig.requireMention) {
          findings.push({
            code: 'ACCESS003',
            severity: 'medium',
            title: `${channelName}/${groupName}: Mention not required`,
            detail: `Group ${groupName} in ${channelName} does not require @mention, bot responds to all messages.`,
            recommendation: `Set channels.${channelName}.groups.${groupName}.requireMention to true`,
            fixable: true,
          });
        }
      }
    }
  }

  return findings;
}
