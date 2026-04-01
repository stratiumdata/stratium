/**
 * notifications.js
 *
 * Webhook notifications for Stratium authorization events.
 *
 * Sends DENY events (and optionally ALLOW events) to configured webhooks
 * (Slack, Teams, or generic HTTP endpoints) so security teams receive
 * real-time visibility into blocked tool attempts.
 *
 * Notifications are:
 *   - Fire-and-forget (non-blocking — never delays or fails tool enforcement)
 *   - Sent in the background via a detached subprocess
 *   - Configured in ~/.claude/stratium.json under "notifications"
 *
 * Config schema:
 * {
 *   "notifications": {
 *     "on_deny": true,           // notify on every DENY (default: true)
 *     "on_allow": false,         // notify on every ALLOW (default: false — too noisy)
 *     "on_override": true,       // notify when break-glass override is used
 *     "webhooks": [
 *       {
 *         "type": "slack",
 *         "url": "https://hooks.slack.com/services/...",
 *         "channel": "#security-alerts"  // optional, overrides webhook default
 *       },
 *       {
 *         "type": "teams",
 *         "url": "https://outlook.office.com/webhook/..."
 *       },
 *       {
 *         "type": "generic",
 *         "url": "https://my-siem.corp.com/events",
 *         "headers": { "Authorization": "Bearer <token>" }
 *       }
 *     ]
 *   }
 * }
 */

'use strict';

const { execFileSync } = require('child_process');
const os   = require('fs');
const path = require('path');

/**
 * @typedef {object} NotificationEvent
 * @property {'deny'|'allow'|'override'} type
 * @property {string} tool_name
 * @property {string} reason
 * @property {string} user
 * @property {string} delegation_id
 * @property {string} [project]
 * @property {string} [machine]
 */

/**
 * Build a Slack Block Kit message payload for a DENY event.
 *
 * @param {NotificationEvent} event
 * @param {string} [channel]
 * @returns {object}
 */
function buildSlackPayload(event, channel) {
  const emoji   = event.type === 'override' ? '⚠️' : (event.type === 'deny' ? '🚫' : '✅');
  const title   = event.type === 'override'
    ? 'Stratium: Break-Glass Override'
    : (event.type === 'deny' ? 'Stratium: Tool Blocked' : 'Stratium: Tool Allowed');

  const payload = {
    blocks: [
      {
        type: 'header',
        text: { type: 'plain_text', text: `${emoji} ${title}` },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Tool:*\n\`${event.tool_name}\`` },
          { type: 'mrkdwn', text: `*User:*\n${event.user || 'unknown'}` },
          { type: 'mrkdwn', text: `*Machine:*\n${event.machine || 'unknown'}` },
          { type: 'mrkdwn', text: `*Project:*\n${event.project || 'unknown'}` },
        ],
      },
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `*Reason:*\n${event.reason}` },
      },
      {
        type: 'context',
        elements: [{
          type: 'mrkdwn',
          text: `Delegation: \`${event.delegation_id || 'n/a'}\` · ${new Date().toISOString()}`,
        }],
      },
    ],
  };

  if (channel) payload.channel = channel;
  return payload;
}

/**
 * Build a Microsoft Teams Adaptive Card payload for a DENY event.
 *
 * @param {NotificationEvent} event
 * @returns {object}
 */
function buildTeamsPayload(event) {
  const color   = event.type === 'override' ? 'warning' : (event.type === 'deny' ? 'attention' : 'good');
  const title   = event.type === 'override'
    ? '⚠️ Stratium: Break-Glass Override'
    : (event.type === 'deny' ? '🚫 Stratium: Tool Blocked' : '✅ Stratium: Tool Allowed');

  return {
    type: 'message',
    attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      content: {
        type: 'AdaptiveCard',
        version: '1.4',
        body: [
          {
            type: 'TextBlock',
            text: title,
            size: 'Large',
            weight: 'Bolder',
            color,
          },
          {
            type: 'FactSet',
            facts: [
              { title: 'Tool',       value: event.tool_name      || 'unknown' },
              { title: 'User',       value: event.user           || 'unknown' },
              { title: 'Machine',    value: event.machine        || 'unknown' },
              { title: 'Project',    value: event.project        || 'unknown' },
              { title: 'Delegation', value: event.delegation_id  || 'n/a' },
            ],
          },
          {
            type: 'TextBlock',
            text: event.reason,
            wrap: true,
          },
        ],
      },
    }],
  };
}

/**
 * Build a generic JSON payload for SIEM or custom webhook endpoints.
 *
 * @param {NotificationEvent} event
 * @returns {object}
 */
function buildGenericPayload(event) {
  return {
    source:       'stratium-claude-hooks',
    event_type:   `tool_${event.type}`,
    ts:           new Date().toISOString(),
    tool_name:    event.tool_name,
    reason:       event.reason,
    user:         event.user,
    delegation_id: event.delegation_id,
    project:      event.project,
    machine:      event.machine,
  };
}

/**
 * Send a single webhook notification via curl (fire-and-forget).
 *
 * @param {object} webhook - Webhook config entry
 * @param {object} payload - JSON payload to send
 */
function sendWebhook(webhook, payload) {
  const curl    = process.env.STRATIUM_CURL_PATH || 'curl';
  const headers = webhook.headers || {};

  const args = [
    '-s', '-S',
    '-X', 'POST',
    '-H', 'Content-Type: application/json',
    '--max-time', '10',
    '--retry', '2',
    '--retry-delay', '1',
  ];

  for (const [k, v] of Object.entries(headers)) {
    args.push('-H', `${k}: ${v}`);
  }

  args.push('-d', JSON.stringify(payload));
  args.push(webhook.url);

  try {
    // Use background execution to not block the hook
    const { spawn } = require('child_process');
    const proc = spawn(curl, args, {
      detached: true,
      stdio: 'ignore',
    });
    proc.unref(); // allow parent to exit without waiting
  } catch {
    // Notification failure must never block enforcement
  }
}

/**
 * Send authorization event notifications to all configured webhooks.
 *
 * This function is non-blocking — it spawns background curl processes
 * and returns immediately.
 *
 * @param {NotificationEvent} event
 * @param {object} notificationsConfig - The "notifications" block from stratium.json
 */
function notify(event, notificationsConfig) {
  if (!notificationsConfig) return;

  const webhooks = notificationsConfig.webhooks || [];
  if (webhooks.length === 0) return;

  // Check if this event type should trigger notifications
  const shouldNotify = (
    (event.type === 'deny'     && notificationsConfig.on_deny     !== false) ||
    (event.type === 'allow'    && notificationsConfig.on_allow    === true)  ||
    (event.type === 'override' && notificationsConfig.on_override !== false)
  );

  if (!shouldNotify) return;

  for (const webhook of webhooks) {
    if (!webhook.url) continue;

    let payload;
    switch (webhook.type) {
      case 'slack':
        payload = buildSlackPayload(event, webhook.channel);
        break;
      case 'teams':
        payload = buildTeamsPayload(event);
        break;
      default:
        payload = buildGenericPayload(event);
    }

    sendWebhook(webhook, payload);
  }
}

module.exports = { notify, buildSlackPayload, buildTeamsPayload, buildGenericPayload };
