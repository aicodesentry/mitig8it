// The app's own identity on GitHub, derived from the configured slug. The bot login is
// what GitHub writes into a "Commit suggestion" commit's Co-authored-by trailer and what
// authors the app's own review comments, so nothing here may be a hard-coded name: an
// installation of a differently named app must recognise its own commits, not ours.

const DEFAULT_GITHUB_APP_SLUG = 'mitig8it';

function resolveGithubAppSlug() {
  const raw = (process.env.GITHUB_APP_SLUG || '').trim();
  const lowered = raw.toLowerCase();

  if (!raw || lowered.includes('replace_me') || lowered.includes('your_') || lowered === 'github_app_slug') {
    return DEFAULT_GITHUB_APP_SLUG;
  }

  const match = raw.match(/github\.com\/apps\/([^/]+)/i);
  if (match?.[1]) return match[1];

  return raw;
}

function appBotLogin() {
  return `${resolveGithubAppSlug()}[bot]`;
}

module.exports = { resolveGithubAppSlug, appBotLogin, DEFAULT_GITHUB_APP_SLUG };
