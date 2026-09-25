"""Running the real `publisher/publish.js` against a fake GitHub, from pytest.

The publisher is Node and calls into services/github-service, which needs that service's
`node_modules`. The host test job installs neither, so the service is replaced at
`MITIG8IT_GITHUB_SERVICE_ROOT` by a stub that keeps an in-memory comment store and implements
the same three-part match the real `postInlineComment` documents: same author login, same path,
same `mitig8it-finding` marker, edit in place, otherwise create.

That the real function honours that contract is github-service's own test
(`src/__tests__/analysisLifecycle.test.js`). What these harness-driven tests own is the part
that lives in the action: that the publisher sends one request per finding and no more, and that
threads for findings which have gone away are reconciled afterwards.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

PUBLISHER = Path(__file__).resolve().parents[1] / "publisher/publish.js"

# A GitHub-shaped in-memory review-comment store. `state.json` is the whole fake repository, so
# a second publish in the same directory sees exactly what the first one left behind.
STUB_OPERATIONS = r"""
'use strict';
const fs = require('fs');
const statePath = process.env.MITIG8IT_STUB_STATE;

function load() {
  try { return JSON.parse(fs.readFileSync(statePath, 'utf8')); }
  catch { return { comments: [], calls: [], nextId: 1, botLogin: 'github-actions[bot]' }; }
}
function save(state) { fs.writeFileSync(statePath, JSON.stringify(state, null, 2)); }
function record(state, name, detail) { state.calls.push({ name, ...detail }); }

// github-service's envelope rule, copied by the test from githubInternalOperations.js.
function validateEnvelope(payload) {
  const digest = payload.manifest_digest;
  if (typeof digest !== 'string' || !digest || digest.length > 64) throw new Error('manifest_digest is required');
  if (!/^[0-9a-f]{64}$/i.test(digest)) throw new Error('manifest_digest must be a SHA-256 digest');
}

module.exports = {
  submitPullRequestReview: async (p) => {
    const state = load(); record(state, 'review', { body: p.body }); save(state); return { review_id: 1 };
  },

  // The contract postInlineComment documents: find my own comment for this finding on this
  // path, edit it, and only create when there is none.
  postInlineComment: async (p) => {
    const state = load();
    const marker = String(p.body).match(/<!-- mitig8it-finding:[^>]+ -->/)?.[0];
    if (marker) {
      const existing = state.comments.find(
        (c) => c.user.login === state.botLogin && c.path === p.path && c.body.includes(marker)
      );
      if (existing) {
        const changed = existing.body !== p.body;
        if (changed) existing.body = p.body;
        record(state, 'edit', { path: p.path, marker, changed });
        save(state);
        return { comment_id: existing.id, url: 'fake', success: true };
      }
    }
    const comment = {
      id: state.nextId, path: p.path, line: p.line, body: p.body, user: { login: state.botLogin },
    };
    state.nextId += 1;
    state.comments.push(comment);
    record(state, 'create', { path: p.path, marker });
    save(state);
    return { comment_id: comment.id, url: 'fake', success: true };
  },

  publishFindingFixSections: async (p) => {
    validateEnvelope(p);
    const state = load(); record(state, 'fixes', { sections: p.sections.length }); save(state);
    return { published: p.sections.length };
  },

  createCheckRun: async (p) => {
    const state = load();
    record(state, 'check', { title: p.title, conclusion: p.conclusion, summary: p.summary });
    save(state);
    return { check_run_id: 3 };
  },
};
"""

STUB_IDENTITY = "'use strict';\nmodule.exports = { useProvider: () => {} };\n"


class Publisher:
    """One fake repository the publisher can be run against more than once."""

    def __init__(self, root: Path, graphql_url: str | None = None):
        self.root = root
        self.graphql_url = graphql_url
        services = root / "github-service/src/services"
        services.mkdir(parents=True, exist_ok=True)
        (services / "githubInternalOperations.js").write_text(STUB_OPERATIONS, encoding="utf-8")
        (services / "githubIdentity.js").write_text(STUB_IDENTITY, encoding="utf-8")
        self.state_path = root / "state.json"
        self.reset()

    def reset(self, bot_login: str = "github-actions[bot]") -> None:
        self.state_path.write_text(
            json.dumps({"comments": [], "calls": [], "nextId": 1, "botLogin": bot_login}),
            encoding="utf-8",
        )

    def state(self) -> dict:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def calls(self) -> list:
        return self.state()["calls"]

    def clear_calls(self) -> None:
        state = self.state()
        state["calls"] = []
        self.state_path.write_text(json.dumps(state), encoding="utf-8")

    def run(self, request: dict) -> subprocess.CompletedProcess:
        request_path = self.root / "request.json"
        request_path.write_text(json.dumps(request), encoding="utf-8")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "MITIG8IT_GITHUB_SERVICE_ROOT": str(self.root / "github-service"),
            "MITIG8IT_STUB_STATE": str(self.state_path),
        }
        if self.graphql_url:
            env["GITHUB_GRAPHQL_URL"] = self.graphql_url
        return subprocess.run(
            ["node", str(PUBLISHER), str(request_path)],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )


def node_available() -> bool:
    return shutil.which("node") is not None
