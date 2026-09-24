'use strict';
// `.mitig8it.yml`: what a repository asks not to be reviewed.
//
// One key so far, `exclude`, a list of globs. A path it matches is never analysed: it is dropped
// before the scanner sees it, so no finding, no comment and no fix can come from it.
// Intentionally vulnerable fixtures, vendored trees and generated output are what this is for.
//
// The Action reads the same file in action/orchestrator/repo_config.py, and the two have to
// agree exactly: a repository that excludes a directory must see the same files skipped whether
// the App or the Action reviewed the pull request. The glob dialect is therefore written down
// once, in contracts/repository-configuration-v1.json, and both implementations are tested
// against its cases rather than against each other's behaviour.
//
// The file comes out of the repository under review, so it is untrusted input. It can only ever
// remove files from the analysis, never add anything to it or change how anything is scanned,
// and a file that does not parse is reported rather than obeyed: excluding nothing and saying so
// is safe, while excluding everything because a quote was unbalanced is not.

const YAML = require('yaml');

const CONFIG_FILENAME = '.mitig8it.yml';
// A configuration file is a short list of globs. Anything larger is not one, and reading it into
// a YAML parser is work a pull request should not be able to ask for.
const MAX_CONFIG_BYTES = 64000;
const MAX_PATTERNS = 200;
const MAX_PATTERN_CHARS = 500;

class ConfigError extends Error {}

// The repository-relative form both sides match against: no leading `./` or `/`.
function normalizePath(path) {
  let text = String(path == null ? '' : path).replace(/\\/g, '/').trim();
  while (text.startsWith('./')) text = text.slice(2);
  return text.replace(/^\/+/, '');
}

function escapeLiteral(character) {
  return character.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// One glob as a regular expression, over the dialect the contract file states. `**` is only a
// globstar when it is a whole segment; `a**b` is two ordinary stars, which the per-character
// branch below already handles by never letting `*` cross a separator.
function translate(pattern) {
  const parts = [];
  const segments = pattern.split('/');
  segments.forEach((segment, index) => {
    const first = index === 0;
    const last = index === segments.length - 1;
    if (segment === '**') {
      if (first && last) parts.push('.*');
      else if (first) parts.push('(?:.*/)?'); // `**/x` matches `x` at the root too.
      else if (last) {
        // `a/**` matches `a` itself as well as everything under it.
        parts[parts.length - 1] = parts[parts.length - 1].replace(/\/$/, '');
        parts.push('(?:/.*)?');
      } else parts.push('(?:.*/)?');
      return;
    }
    for (const character of segment) {
      if (character === '*') parts.push('[^/]*');
      else if (character === '?') parts.push('[^/]');
      else parts.push(escapeLiteral(character));
    }
    if (!last) parts.push('/');
  });
  return parts.join('');
}

// The matcher for one pattern, or null when the pattern is empty and matches nothing.
function compilePattern(pattern) {
  const cleaned = normalizePath(pattern);
  if (!cleaned) return null;
  let body = translate(cleaned);
  if (!cleaned.includes('*') && !cleaned.includes('?')) {
    // A plain name is a file or a directory, so it also covers everything underneath it.
    body = `${body}(?:/.*)?`;
  }
  return new RegExp(`^${body}$`);
}

// The compiled `exclude` list. Empty when there is no file, or the file named nothing.
class Exclusions {
  constructor(patterns = []) {
    this.patterns = [...patterns];
    this.matchers = this.patterns.map(compilePattern).filter(Boolean);
  }

  get empty() {
    return this.matchers.length === 0;
  }

  matches(path) {
    const candidate = normalizePath(path);
    return this.matchers.some((matcher) => matcher.test(candidate));
  }

  // { kept, excluded }, in the order given.
  partition(paths) {
    const kept = [];
    const excluded = [];
    for (const path of paths || []) {
      if (this.matches(path)) excluded.push(path);
      else kept.push(path);
    }
    return { kept, excluded };
  }
}

// `.mitig8it.yml` as an Exclusions. Throws ConfigError when the text is not one.
function parse(text) {
  const source = String(text == null ? '' : text);
  if (Buffer.byteLength(source, 'utf8') > MAX_CONFIG_BYTES) {
    throw new ConfigError(`${CONFIG_FILENAME} is larger than ${MAX_CONFIG_BYTES} bytes`);
  }
  let document;
  try {
    document = YAML.parse(source);
  } catch (error) {
    throw new ConfigError(`${CONFIG_FILENAME} is not valid YAML: ${String(error.message).split('\n')[0]}`);
  }
  if (document === null || document === undefined) return new Exclusions();
  if (typeof document !== 'object' || Array.isArray(document)) {
    throw new ConfigError(`${CONFIG_FILENAME} must be a mapping, with \`exclude\` as one of its keys`);
  }
  const raw = document.exclude;
  if (raw === null || raw === undefined) return new Exclusions();
  if (!Array.isArray(raw)) throw new ConfigError('`exclude` must be a list of globs, one per line');
  if (raw.length > MAX_PATTERNS) throw new ConfigError(`\`exclude\` names more than ${MAX_PATTERNS} globs`);
  const patterns = [];
  for (const entry of raw) {
    if (typeof entry !== 'string') {
      throw new ConfigError(`\`exclude\` contains ${entry === null ? 'null' : typeof entry} where a glob was expected`);
    }
    if (entry.length > MAX_PATTERN_CHARS) {
      throw new ConfigError(`an \`exclude\` glob is longer than ${MAX_PATTERN_CHARS} characters`);
    }
    patterns.push(entry);
  }
  return new Exclusions(patterns);
}

// The one sentence the check summary carries. null when nothing was excluded.
function exclusionSummary(count) {
  if (!(count > 0)) return null;
  return `${count} file${count === 1 ? '' : 's'} excluded by ${CONFIG_FILENAME}`;
}

// The same fact in the shape the analysis limitation list uses.
function exclusionLimitation(count) {
  const message = exclusionSummary(count);
  return message ? { kind: 'path_exclusion', message } : null;
}

module.exports = {
  CONFIG_FILENAME,
  ConfigError,
  Exclusions,
  compilePattern,
  exclusionLimitation,
  exclusionSummary,
  normalizePath,
  parse,
};
