// Who the publishing code is acting as, and how it recognises its own work.
//
// The publishing functions in githubInternalOperations.js are identical whether Mitig8it runs
// as an installed GitHub App or as a GitHub Action in someone else's runner. What differs is
// four things, and only these four:
//
//   1. where the token comes from     - an App JWT exchanged for an installation token, or the
//                                       workflow's own GITHUB_TOKEN
//   2. what login its comments carry  - `<app-slug>[bot]`, or `github-actions[bot]`
//   3. how it recognises its check    - the App's id on the check run, or the check's name
//   4. how repository access is proven - enumerating the installation's repositories, or the
//                                       single repository the workflow is already running in
//
// Rather than fork the publishing code, those four are named here as a provider. The default is
// the App, with the same calls and the same predicates it has always made, so nothing about the
// App's behaviour changes. `useProvider` swaps in another; `resetProvider` restores the default.
//
// This module deliberately requires nothing from githubInternalOperations.js. The two helpers a
// provider needs for its HTTP work are passed in at call time, which keeps the require graph
// acyclic and lets a provider be tested on its own.

const githubAppAuth = require('./githubAppAuth');

const APP_PROVIDER_KIND = 'github_app';

const appProvider = {
  kind: APP_PROVIDER_KIND,

  async token(installationId) {
    return githubAppAuth.getInstallationToken(installationId);
  },

  async botLogin() {
    return githubAppAuth.getAppBotLogin();
  },

  // A check run posted by a different app may carry the same name. The App identifies its own
  // by the app id that created it, which no other installation can forge.
  ownsCheckRun(check) {
    return String(check.app?.id) === String(process.env.GITHUB_APP_ID);
  },

  // The installation token is scoped to the claimed installation. Enumerating its accessible
  // repositories protects against a caller mixing repository IDs across installations,
  // including selected-repository installations.
  async assertRepositoryAccess({ envelope, token, githubRequest, OperationError }) {
    const repository = await githubRequest('get', `https://api.github.com/repos/${envelope.owner}/${envelope.repo}`, token);
    if (repository.data?.full_name?.toLowerCase() !== envelope.repository_full_name.toLowerCase()) {
      throw new OperationError('Repository is not accessible through this installation', 403);
    }
    let repositoryFound = false;
    for (let page = 1; page <= 10; page += 1) {
      const response = await githubRequest('get',
        `https://api.github.com/installation/repositories?per_page=100&page=${page}`, token);
      const repositories = response.data?.repositories;
      if (!Array.isArray(repositories)) throw new OperationError('Invalid installation repository response', 502);
      repositoryFound = repositories.some((candidate) => candidate.full_name?.toLowerCase() === envelope.repository_full_name.toLowerCase());
      if (repositoryFound || repositories.length < 100) break;
    }
    if (!repositoryFound) throw new OperationError('Repository is not enabled for this installation', 403);
  },

  async assertActorWritePermission({ envelope, token, githubRequest, OperationError }) {
    const permission = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/collaborators/${encodeURIComponent(envelope.actor_login)}/permission`, token);
    if (!['write', 'admin'].includes(permission.data?.permission)) {
      throw new OperationError('Actor does not currently have write permission for this repository', 403);
    }
  },
};

let activeProvider = appProvider;

function useProvider(provider) {
  if (!provider) throw new Error('a GitHub identity provider is required');
  for (const method of ['token', 'botLogin', 'ownsCheckRun', 'assertRepositoryAccess', 'assertActorWritePermission']) {
    if (typeof provider[method] !== 'function') {
      throw new Error(`GitHub identity provider is missing ${method}()`);
    }
  }
  activeProvider = provider;
  return activeProvider;
}

function resetProvider() {
  activeProvider = appProvider;
  return activeProvider;
}

function currentProvider() {
  return activeProvider;
}

const token = (installationId) => activeProvider.token(installationId);
const botLogin = () => activeProvider.botLogin();
const ownsCheckRun = (check) => activeProvider.ownsCheckRun(check);
const assertRepositoryAccess = (context) => activeProvider.assertRepositoryAccess(context);
const assertActorWritePermission = (context) => activeProvider.assertActorWritePermission(context);

module.exports = {
  APP_PROVIDER_KIND,
  appProvider,
  useProvider,
  resetProvider,
  currentProvider,
  token,
  botLogin,
  ownsCheckRun,
  assertRepositoryAccess,
  assertActorWritePermission,
};
