const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { Pool } = require('pg');
const { ensureInternalAuth } = require('../middleware/internalAuth');

const router = express.Router();

// Database connection with secure SSL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Neon provides valid SSL certificates - verify them for security
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});

// Verify GitHub webhook signature
function verifySignature(payloadBuffer, signatureHeader) {
  if (!process.env.WEBHOOK_SECRET) {
    console.warn('WEBHOOK_SECRET not set - rejecting webhook');
    return false;
  }
  if (!signatureHeader) {
    return false;
  }

  const hmac = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET);
  const digest = 'sha256=' + hmac.update(payloadBuffer).digest('hex');

  const signatureBuffer = Buffer.from(signatureHeader);
  const digestBuffer = Buffer.from(digest);

  // timingSafeEqual throws if buffer lengths differ, so guard lengths first
  if (signatureBuffer.length !== digestBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(signatureBuffer, digestBuffer);
}

// Register webhook for a repository
router.post('/register', async (req, res) => {
  const internalSecret = process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  if (internalSecret && req.headers['x-internal-secret'] !== internalSecret) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { repository_full_name, github_token } = req.body;

  if (!repository_full_name || !github_token) {
    return res.status(400).json({
      error: 'Missing required fields: repository_full_name, github_token'
    });
  }

  const webhookUrl = `${process.env.WEBHOOK_URL}/webhooks/github`;

  try {
    // Fetch repo metadata to get the stable GitHub repo ID
    const repoResp = await axios.get(
      `https://api.github.com/repos/${repository_full_name}`,
      {
        headers: {
          Authorization: `Bearer ${github_token}`,
          Accept: 'application/vnd.github+json',
        },
      }
    );
    const repoId = repoResp.data.id;

    // First, check if webhook already exists
    const existingHooksResponse = await axios.get(
      `https://api.github.com/repos/${repository_full_name}/hooks`,
      {
        headers: {
          Authorization: `Bearer ${github_token}`,
          Accept: 'application/vnd.github+json',
        },
      }
    );

    // Find existing webhook with our URL
    const existingWebhook = existingHooksResponse.data.find(
      hook => hook.config?.url === webhookUrl
    );

    if (existingWebhook) {
      console.log(`Webhook already exists for ${repository_full_name}, returning existing ID: ${existingWebhook.id}`);
      // Persist webhook details to DB if we have the repository row
      try {
        const update = await pool.query(
          `UPDATE repositories
           SET webhook_id = $1, updated_at = NOW()
           WHERE github_id = $2
           RETURNING id`,
          [existingWebhook.id, repoId]
        );
        if (update.rowCount === 0) {
          console.warn(`[WARN] Repo not found for github_id=${repoId} when updating webhook_id`);
        }
      } catch (dbErr) {
        console.error('[ERROR] Failed to persist existing webhook_id:', dbErr.message);
      }

      return res.json({
        success: true,
        webhook_id: existingWebhook.id,
        webhook_url: existingWebhook.config.url,
        events: existingWebhook.events,
        already_existed: true,
      });
    }

    // Register new webhook on GitHub
    const webhookConfig = {
      name: 'web',
      active: true,
      events: ['pull_request'],
      config: {
        url: webhookUrl,
        content_type: 'json',
        insecure_ssl: '0',
      },
    };

    // Add secret if configured
    if (process.env.WEBHOOK_SECRET) {
      webhookConfig.config.secret = process.env.WEBHOOK_SECRET;
    }

    const webhookResponse = await axios.post(
      `https://api.github.com/repos/${repository_full_name}/hooks`,
      webhookConfig,
      {
        headers: {
          Authorization: `Bearer ${github_token}`,
          Accept: 'application/vnd.github+json',
        },
      }
    );

    const webhook = webhookResponse.data;
    console.log(`New webhook created for ${repository_full_name}, ID: ${webhook.id}`);

    // Persist webhook details to DB if we have the repository row
    try {
      const update = await pool.query(
        `UPDATE repositories
         SET webhook_id = $1, updated_at = NOW()
         WHERE github_id = $2
         RETURNING id`,
        [webhook.id, repoId]
      );
      if (update.rowCount === 0) {
        console.warn(`[WARN] Repo not found for github_id=${repoId} when updating webhook_id`);
      }
    } catch (dbErr) {
      console.error('[ERROR] Failed to persist webhook_id:', dbErr.message);
    }

    res.json({
      success: true,
      webhook_id: webhook.id,
      webhook_url: webhook.config.url,
      events: webhook.events,
      already_existed: false,
    });
  } catch (error) {
    const status = error.response?.status;
    const tokenInvalid = status === 401 || status === 403 || status === 404;
    console.error('Webhook registration error:', error.response?.data?.message || error.message);
    res.status(status || 500).json({
      error: 'Failed to register webhook',
      details: error.response?.data?.message || error.message,
      errors: error.response?.data?.errors || [],
      token_invalid: tokenInvalid,
    });
  }
});

// Receive webhook events from GitHub
router.post('/github', express.raw({ type: 'application/json' }), async (req, res) => {
  const signature = req.headers['x-hub-signature-256'];
  const event = req.headers['x-github-event'];

  console.log(`\n=== Webhook Event Received ===`);
  console.log(`Event: ${event}`);
  console.log(`Signature: ${signature ? 'Present' : 'Missing'}`);

  // Verify signature (reject when secret is set but signature is missing or invalid)
  if (!verifySignature(req.body, signature)) {
    console.error('[ERROR] Invalid or missing webhook signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Parse the payload
  const payload = JSON.parse(req.body.toString());

  // Only process pull_request events
  if (event !== 'pull_request') {
    console.log(`[IGNORE] Ignoring ${event} event`);
    return res.status(200).json({ message: 'Event ignored' });
  }

  // Extract PR information
  const action = payload.action; // opened, synchronize, closed, etc.
  const pr = payload.pull_request;
  const repository = payload.repository;

  console.log(`Action: ${action}`);
  console.log(`Repository: ${repository.full_name}`);
  console.log(`PR: #${pr.number} - ${pr.title}`);

  try {
    // Get repository from database
    const repoResult = await pool.query(
      'SELECT id FROM repositories WHERE github_id = $1',
      [repository.id]
    );

    if (repoResult.rows.length === 0) {
      console.log('[WARN] Repository not found in database');
      return res.status(200).json({ message: 'Repository not connected' });
    }

    const repositoryId = repoResult.rows[0].id;

  // Build a privacy-safe payload snapshot for audit/debug (strip large fields/PII)
  const sanitizedPayload = {
    action,
    repository: {
      id: repository.id,
      full_name: repository.full_name,
    },
    pull_request: {
      number: pr.number,
      head_ref: pr.head?.ref,
      base_ref: pr.base?.ref,
    },
    sender: payload.sender ? { login: payload.sender.login, id: payload.sender.id } : null,
  };

  // Log webhook event (store sanitized payload, not full GitHub payload)
  await pool.query(
    `INSERT INTO webhook_events (repository_id, event_type, action, pr_number, pr_title, pr_url, branch_name, sender_username, payload)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      repositoryId,
      event,
      action,
      pr.number,
      pr.title,
      pr.html_url,
      pr.head.ref,
      payload.sender.login,
      JSON.stringify(sanitizedPayload)
    ]
  );
    console.log(`[LOG] Webhook event logged: ${action} on PR #${pr.number}`);

    console.log(`=============================\n`);

    // Respond to GitHub
    res.status(200).json({
      success: true,
      message: 'Webhook received and processed'
    });

  } catch (error) {
    console.error('[ERROR] Error processing webhook:', error);
    console.error(`=============================\n`);
    res.status(500).json({ error: 'Failed to process webhook' });
  }
});

// Delete/unregister webhook for a repository. Only the control plane may call it: an
// unauthenticated caller holding a leaked user token could otherwise silence a
// repository's analysis by deleting its webhook.
router.post('/unregister', ensureInternalAuth, async (req, res) => {
  const { repository_full_name, webhook_id, github_token } = req.body;

  if (!repository_full_name || !webhook_id || !github_token) {
    return res.status(400).json({
      error: 'Missing required fields: repository_full_name, webhook_id, github_token'
    });
  }

  try {
    await axios.delete(
      `https://api.github.com/repos/${repository_full_name}/hooks/${webhook_id}`,
      {
        headers: {
          Authorization: `Bearer ${github_token}`,
          Accept: 'application/vnd.github+json',
        },
      }
    );

    console.log(`Webhook ${webhook_id} deleted for ${repository_full_name}`);

    res.json({
      success: true,
      message: 'Webhook deleted successfully',
    });
  } catch (error) {
    console.error('Webhook deletion error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({
      error: 'Failed to delete webhook',
      details: error.response?.data?.message || error.message,
    });
  }
});

module.exports = router;
