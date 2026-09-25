// The App's half of `.mitig8it.yml`, against the contract both halves are built from.
//
// contracts/repository-configuration-v1.json states the glob dialect and the parse rules once.
// action/tests/test_repository_config.py runs the same cases through the Action's
// implementation. Neither side is tested against the other's behaviour, because then the first
// one to drift would take the other with it; both are tested against the written contract, so a
// change in either has to change the contract first, and the change shows up in one diff on
// both sides.

const path = require('path');
const contract = require(path.resolve(__dirname, '../../../contracts/repository-configuration-v1.json'));
const repositoryConfig = require('../src/services/repositoryConfig');

describe('the exclusion dialect the contract states', () => {
  for (const testCase of contract.match_cases) {
    test(testCase.name, () => {
      const exclusions = new repositoryConfig.Exclusions(testCase.patterns);
      for (const excluded of testCase.excluded) {
        expect([excluded, exclusions.matches(excluded)]).toEqual([excluded, true]);
      }
      for (const kept of testCase.kept) {
        expect([kept, exclusions.matches(kept)]).toEqual([kept, false]);
      }
    });
  }
});

describe('the parse rules the contract states', () => {
  for (const testCase of contract.parse_cases) {
    test(testCase.name, () => {
      if (testCase.valid) {
        expect(repositoryConfig.parse(testCase.yaml).patterns).toEqual(testCase.patterns);
      } else {
        expect(() => repositoryConfig.parse(testCase.yaml)).toThrow(repositoryConfig.ConfigError);
      }
    });
  }
});

describe('partition and the sentence the summary carries', () => {
  test('partition keeps the order it was given', () => {
    const exclusions = new repositoryConfig.Exclusions(['a/**']);
    expect(exclusions.partition(['a/1.js', 'b/1.js', 'a/2.js', 'b/2.js'])).toEqual({
      kept: ['b/1.js', 'b/2.js'],
      excluded: ['a/1.js', 'a/2.js'],
    });
  });

  test('the sentence counts and names the file', () => {
    expect(repositoryConfig.exclusionSummary(0)).toBeNull();
    expect(repositoryConfig.exclusionSummary(1)).toBe('1 file excluded by .mitig8it.yml');
    expect(repositoryConfig.exclusionSummary(34)).toBe('34 files excluded by .mitig8it.yml');
    expect(repositoryConfig.exclusionLimitation(34)).toEqual({
      kind: 'path_exclusion',
      message: '34 files excluded by .mitig8it.yml',
    });
  });

  test('an oversized file is refused rather than parsed', () => {
    const huge = `exclude:\n${'  - a/**\n'.repeat(20000)}`;
    expect(() => repositoryConfig.parse(huge)).toThrow(/larger than/);
  });

  test('an excluded path can only remove files, never add one', () => {
    // The file comes out of the repository under review. The only power it has is subtraction.
    const exclusions = new repositoryConfig.Exclusions(['**']);
    expect(exclusions.partition(['a.js', 'b/c.js'])).toEqual({ kept: [], excluded: ['a.js', 'b/c.js'] });
  });
});

describe("this repository's own file", () => {
  test('the deliberately vulnerable corpora are excluded', () => {
    const fs = require('fs');
    const root = path.resolve(__dirname, '../../..');
    const exclusions = repositoryConfig.parse(fs.readFileSync(path.join(root, '.mitig8it.yml'), 'utf8'));

    for (const path of [
      'benchmarks/remediation/fixtures/sql-parameterized-001/db.js',
      'benchmarks/vulnerable-corpus/anything.py',
      'benchmarks/tier1-precision/cases.json',
      'benchmarks/tier2-precision/cases.json',
      'docs/validation/tier2-coverage-2026-09.md',
      'action/tests/fixtures/pull_request_opened.json',
    ]) {
      expect([path, exclusions.matches(path)]).toEqual([path, true]);
    }
    for (const path of ['services/api-service/src/index.js', 'docs/README.md', 'scripts/replay/prodfilters.py']) {
      expect([path, exclusions.matches(path)]).toEqual([path, false]);
    }
  });
});
