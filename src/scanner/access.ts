import type { Finding, OpenClawConfig, ScanContext } from '../utils/types.js';
import { resolveDmPolicy } from '../utils/openclaw.js';

export function scanAccess(config: OpenClawConfig, context: ScanContext): Finding[] {
  const findings: Finding[] = [];

  if (!config.channels) {
    return findings;
  }

  for (const [channelName, channelConfig] of Object.entries(config.channels)) {
    // Check DM policy
    const dmPolicy = resolveDmPolicy(channelConfig, context.openClaw.schema);
    const dmPolicyPath =
      context.openClaw.schema === 'legacy'
        ? `channels.${channelName}.dm.policy`
        : context.openClaw.schema === 'current'
          ? `channels.${channelName}.dmPolicy`
          : channelConfig.dm?.policy !== undefined
            ? `channels.${channelName}.dm.policy`
            : `channels.${channelName}.dmPolicy`;
    if (dmPolicy === 'open') {
      findings.push({
        code: 'ACCESS001',
        severity: 'high',
        title: `${channelName}: DM policy allows unknown senders`,
        detail: `Channel ${channelName} has a DM policy set to "open", allowing anyone to send commands.`,
        recommendation: `Set ${dmPolicyPath} to "pairing" or "allowlist"`,
        fixable: true,
        path: dmPolicyPath,
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
          path: `channels.${channelName}.allowFrom`,
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
            path: `channels.${channelName}.groups.${groupName}.requireMention`,
          });
        }
      }
    }
  }

  return findings;
}
