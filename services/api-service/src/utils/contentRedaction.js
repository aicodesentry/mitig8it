const SOURCE_SECRET_PATTERNS = [
  // Named credential assignments in source, configuration, logs, or test output.
  /(\b(?:api[_-]?key|password|passwd|secret|token|credential|authorization)\b["']?\s*[:=]\s*["'`])([^"'`\r\n]+)(["'`])/gi,
  // Common provider token shapes, bearer values, and URL passwords.
  /\b(?:sk[-_][A-Za-z0-9_-]{10,}|AIza[A-Za-z0-9_-]{10,}|(?:gh[pousr]_|github_pat_|glpat-|xox[baprs]-|xapp-)[A-Za-z0-9_-]{10,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b/g,
  /(\bBearer\s+)[A-Za-z0-9._~+/-]{4,}/gi,
  /([A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s:/]+:)[^\s/@]+(@)/g,
];
const PRIVATE_KEY_BLOCK = /-----BEGIN (?:[A-Z ]* )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]* )?PRIVATE KEY-----/g;

function redactRepositoryContent(content) {
  let redacted = String(content).replace(PRIVATE_KEY_BLOCK, (block) =>
    block.split(/(\r?\n)/).map((part) => (/^\r?\n$/.test(part) ? part : '[REDACTED_PRIVATE_KEY]')).join('')
  );
  redacted = redacted.replace(SOURCE_SECRET_PATTERNS[0], '$1[REDACTED_SECRET]$3');
  redacted = redacted.replace(SOURCE_SECRET_PATTERNS[1], '[REDACTED_SECRET]');
  redacted = redacted.replace(SOURCE_SECRET_PATTERNS[2], '$1[REDACTED_SECRET]');
  return redacted.replace(SOURCE_SECRET_PATTERNS[3], '$1[REDACTED_SECRET]$2');
}

module.exports = { redactRepositoryContent };
