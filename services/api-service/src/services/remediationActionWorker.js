const { GitHubRemediationClient } = require('./githubRemediationClient');
const remediationDb = require('../db/remediation');
const policy = require('./remediationPolicy');
const metrics = require('./remediationMetrics');
const logger = require('../utils/logger');
const { withSpan } = require('../utils/telemetry');

function basePayload(action, job) {
  return { installation_id: job.installation_id, repository_full_name: job.repository_full_name, actor_login: action.actor_login,
    pr_number: job.pr_number, head_sha: action.head_sha, base_sha: action.base_sha, manifest_digest: action.batch_manifest_digest,
    action_id: action.id, idempotency_key: action.idempotency_key };
}
function verifiedTreeOid(candidates) {
  const tree = candidates[0]?.preview?.verified_tree_oid || candidates[0]?.file_manifest?.verified_tree_oid
    || candidates[0]?.verified_tree_oid;
  return typeof tree === 'string' && /^[0-9a-f]{40}$/i.test(tree) ? tree : null;
}
// The adapter commits whole files. A candidate stored as `{ files: [...] }`, as a bare array of
// file entries, or as a single entry all carry the same thing: the final content of each changed
// path. Anything without `contents_base64` is not a committable change and is dropped here, which
// is what `verified_full_file_manifest_unavailable` reports.
function manifestFiles(candidate) {
  const manifest = candidate?.file_manifest;
  if (Array.isArray(manifest?.files)) return manifest.files;
  if (Array.isArray(manifest)) return manifest;
  return [manifest];
}
function persistedChanges(candidates) {
  const changes = candidates.flatMap(manifestFiles);
  return changes.filter((patch) => patch && typeof patch.path === 'string' && typeof patch.contents_base64 === 'string');
}

// A revalidation failure is terminal and machine-readable. Nothing is regenerated.
async function reject(action, code, details = {}) {
  await remediationDb.updateAction(action, 'rejected', { reason: { code, ...details } });
  metrics.actionTransitions.labels('rejected').inc();
  logger.warn('Remediation action rejected during revalidation', { action_id: action.id, code });
}

function samePersistedOrder(expected, actual) {
  return Array.isArray(expected) && Array.isArray(actual) && expected.length === actual.length
    && expected.every((id, index) => id === actual[index]);
}

// Re-derives everything the consent was bound to. Any mismatch is a terminal rejection.
async function revalidate(action, material) {
  const { job, candidates, manifestDigest, orderedCandidateIds } = material;
  if (!job) return { ok: false, code: 'job_not_ready' };
  if (job.state !== 'ready') return { ok: false, code: 'job_not_ready' };
  if (job.head_sha !== action.head_sha || job.base_sha !== action.base_sha) return { ok: false, code: 'stale_head' };
  if (!manifestDigest || manifestDigest !== action.batch_manifest_digest) return { ok: false, code: 'manifest_mismatch' };
  if (!samePersistedOrder(action.candidate_ids, orderedCandidateIds)) return { ok: false, code: 'manifest_mismatch' };
  if (candidates.length !== action.candidate_ids.length) return { ok: false, code: 'manifest_mismatch' };
  if (candidates.some((candidate) => !policy.verificationLevelPermitted(candidate.verification_level))) return { ok: false, code: 'verification_level_not_permitted' };
  try {
    policy.assertApplyEnabled();
    if (action.action_type === 'apply_and_merge') policy.assertMergeEnabled();
  } catch (_) {
    return { ok: false, code: 'flag_disabled' };
  }
  return { ok: true };
}

// prepare is the live GitHub check: it re-reads the pull request head and base and the
// actor's current write permission with the installation identity.
async function liveRevalidation(client, payload) {
  try {
    const prepared = await client.prepare(payload);
    if (prepared.state === 'ready') return { ok: true, prepared };
    if (prepared.state === 'reconciling') return { ok: true, prepared };
    return { ok: false, code: prepared.reason || 'prepare_rejected', prepared };
  } catch (error) {
    const status = error.response?.status;
    if (status === 409) return { ok: false, code: 'stale_head' };
    if (status === 403) return { ok: false, code: 'permission_revoked' };
    if (status === 422) return { ok: false, code: 'unsupported_pull_request' };
    throw error;
  }
}

async function executeClaimedAction(action) {
  return withSpan('remediation.action', { stage: 'apply', action_id: action.id }, async () => executeAction(action));
}

// Records the commit, verifies the tree, then enqueues the fresh analysis for the new
// head. A failed notification leaves the action applied with verification pending.
async function enterCheckingAfterCommit(action, commitSha, treeOid, verifiedTree) {
  if (treeOid && verifiedTree && treeOid !== verifiedTree) {
    await remediationDb.updateAction(action, 'blocked', { commitSha, treeOid, reason: { code: 'applied_tree_mismatch' } });
    metrics.actionTransitions.labels('blocked').inc();
    return;
  }
  try {
    const checking = await remediationDb.enterChecking(action, { commitSha, treeOid: treeOid || verifiedTree });
    if (!checking) return;
    metrics.actionTransitions.labels('checking').inc();
    // The verification check is published for the applied head as soon as the action
    // enters checking. A publication failure is logged and retried by the reconciler;
    // it never reverts the applied state.
    try { await require('./mergeController').publishVerificationCheck(action.id); } catch (error) {
      logger.error('Applied remediation could not publish its verification check; the reconciler will retry', {
        action_id: action.id, error: error.message,
      });
    }
    // Waking the analysis worker is a notification, never a condition of the applied state.
    try { require('./prAnalysisOrchestrator').notifyAnalysisQueued(); } catch (error) {
      logger.error('Applied remediation could not notify the analysis queue; verification stays pending', {
        action_id: action.id, error: error.message,
      });
    }
  } catch (error) {
    logger.error('Applied remediation could not enqueue verification analysis; state stays applied', {
      action_id: action.id, error: error.message,
    });
  }
}

async function executeAction(action) {
  const material = await remediationDb.actionMaterial(action);
  const { job, candidates } = material;
  const client = new GitHubRemediationClient();
  const treeOid = verifiedTreeOid(candidates);

  if (action.state === 'reconciling') {
    // Reconciliation is read-only and stays available even after consent revalidation
    // would fail, so an ambiguous write can still be settled truthfully.
    if (!job) { await remediationDb.updateAction(action, 'blocked', { reason: { code: 'immutable_batch_missing_or_stale' } }); return; }
    if (!treeOid) { await remediationDb.updateAction(action, 'blocked', { reason: { code: 'verified_tree_oid_unavailable' } }); return; }
    const reconciled = await client.reconcile({ ...basePayload(action, job), verified_tree_oid: treeOid });
    if (reconciled.state === 'applied') {
      await remediationDb.updateAction(action, 'applied', { operationId: reconciled.operation_id, commitSha: reconciled.commit_sha, treeOid: reconciled.tree_oid || treeOid });
      metrics.actionTransitions.labels('applied').inc();
      await enterCheckingAfterCommit(action, reconciled.commit_sha, reconciled.tree_oid, treeOid);
    } else if (reconciled.state === 'reconciling') {
      await remediationDb.updateAction(action, 'reconciling', { operationId: reconciled.operation_id, reason: { code: 'ambiguous_write' } });
    } else {
      await remediationDb.updateAction(action, 'blocked', { reason: { code: 'reconciliation_did_not_prove_commit' } });
    }
    return;
  }

  const revalidated = await revalidate(action, material);
  if (!revalidated.ok) { await reject(action, revalidated.code); return; }
  const payload = basePayload(action, job);

  // The control plane never synthesizes file content from a model patch. A full-file
  // base64 payload and a verifier-attested tree are required before the adapter write.
  const changes = persistedChanges(candidates);
  if (!changes.length || !treeOid) {
    await remediationDb.updateAction(action, 'blocked', { reason: { code: 'verified_full_file_manifest_unavailable' } }); metrics.actionTransitions.labels('blocked').inc(); return;
  }
  const live = await liveRevalidation(client, payload);
  if (!live.ok) { await reject(action, live.code); return; }
  const prepared = live.prepared;
  if (prepared.state !== 'ready') {
    await remediationDb.updateAction(action, 'reconciling', { operationId: prepared.operation_id, reason: { code: 'ambiguous_write' } }); return;
  }
  await remediationDb.updateAction(action, 'committing', { operationId: prepared.operation_id });
  const committed = await client.commit({ ...payload, branch: prepared.branch, expected_head_oid: prepared.expected_head_oid, verified_tree_oid: treeOid,
    commit_message: `Apply verified Mitig8it remediation ${action.id}`, changes });
  if (committed.state === 'applied') {
    await remediationDb.updateAction(action, 'applied', { operationId: committed.operation_id, commitSha: committed.commit_sha, treeOid: committed.tree_oid || treeOid });
    metrics.actionTransitions.labels('applied').inc();
    await enterCheckingAfterCommit(action, committed.commit_sha, committed.tree_oid, treeOid);
  } else if (committed.state === 'reconciling') { await remediationDb.updateAction(action, 'reconciling', { operationId: committed.operation_id, reason: { code: 'ambiguous_write' } }); metrics.actionTransitions.labels('reconciling').inc(); }
  else { await remediationDb.updateAction(action, 'blocked', { operationId: committed.operation_id, reason: { code: committed.reason || 'commit_rejected' } }); metrics.actionTransitions.labels('blocked').inc(); }
}
module.exports = { GitHubRemediationClient, executeClaimedAction, executeAction, revalidate, enterCheckingAfterCommit };
