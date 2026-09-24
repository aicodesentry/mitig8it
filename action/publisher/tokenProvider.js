// The identity the action publishes as: the workflow's own GITHUB_TOKEN.
//
// Installed into the github-service's identity seam so that every publishing function in that
// service runs unmodified. Each of the four answers differs from the App's for a reason:
//
//   token                      the workflow token, already scoped to this repository by the
//                              permissions block. There is no JWT and no token exchange, so no
//                              credential of ours is ever present in the runner.
//   botLogin                   comments made with a workflow token are authored by
//                              `github-actions[bot]`. The App's `<slug>[bot]` does not exist here.
//   ownsCheckRun               a workflow token leaves no app id to match on, so a check run is
//                              ours when its name is ours. Within one repository the name is
//                              unique to this action.
//   assertRepositoryAccess     the App enumerates an installation's repositories because one
//                              installation spans many. A workflow token is issued for exactly
//                              one repository, so the proof is that the envelope names the
//                              repository the workflow is running in, and nothing else.
//   assertActorWritePermission the App checks the actor because a human clicked Apply. Nothing
//                              in the action is actor-initiated: it posts a review and never
//                              writes to the repository, so there is no actor to authorise.

const CHECK_RUN_NAME = 'Mitig8it Security Review';

function createWorkflowTokenProvider({ token, repositoryFullName, botLogin = 'github-actions[bot]' }) {
  if (!token) throw new Error('a workflow token is required');
  if (!repositoryFullName) throw new Error('a repository is required');
  const expected = String(repositoryFullName).toLowerCase();

  return {
    kind: 'workflow_token',

    async token() {
      return token;
    },

    async botLogin() {
      return botLogin;
    },

    ownsCheckRun(check) {
      return check?.name === CHECK_RUN_NAME;
    },

    async assertRepositoryAccess({ envelope, OperationError }) {
      if (String(envelope.repository_full_name).toLowerCase() !== expected) {
        throw new OperationError(
          'The workflow token is scoped to a different repository than the one requested', 403
        );
      }
    },

    async assertActorWritePermission() {
      // Nothing the action publishes is actor-initiated. See the note above.
    },
  };
}

module.exports = { createWorkflowTokenProvider, CHECK_RUN_NAME };
