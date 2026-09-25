# Repository Configuration

A repository configures Mitig8it with a `.mitig8it.yml` file at its root. The file is optional.
A repository without one is reviewed in full.

The App and the Action read the same file and apply it identically, so moving between them does
not change which files are reviewed.

## Excluding paths

```yaml
exclude:
  - benchmarks/fixtures/**
  - vendor/**
  - docs/generated/*.md
```

An excluded path is never analysed. It is dropped from the changed-file list before any content
is fetched, so nothing downstream can produce a finding, an inline comment or a fix suggestion
for it. Exclusion is not suppression: there is no hidden finding to review later, because the
file was never scanned.

The check run summary states how many files were excluded, for example
`34 files excluded by .mitig8it.yml`. A reader who sees no finding on a directory is entitled to
know whether it was clean or skipped.

Excluded files are not counted towards the 200-file review cap, so excluding a large generated
tree lets a pull request that touches it still be reviewed in full.

### What to exclude

Code that is meant to be insecure, and code nobody in the repository can fix:

- security test fixtures and vulnerable-by-design corpora
- vendored dependencies and generated output not already covered by the built-in
  `dist/` and `node_modules` filters
- fixture data that is not source

Excluding your application code does not make it safe. It makes it unreviewed.

## Glob syntax

Patterns match the whole repository-relative path with `/` separators, and matching is
case-sensitive.

| Pattern | Matches |
| --- | --- |
| `*` | any run of characters except `/` |
| `?` | exactly one character except `/` |
| `**` | zero or more whole path segments |
| `a/**` | `a` and everything under it |
| `**/vendor/**` | a `vendor` directory at any depth, including the root |
| `build` | the file or directory `build`, and everything under it |

A pattern with no wildcard names a file or a directory, so `build` also excludes
`build/main.js`. A leading `./` or `/` is ignored. Everything else is literal: a `.` or a `+` in
a pattern matches that character and nothing else.

The dialect is stated once, in
[`contracts/repository-configuration-v1.json`](../../contracts/repository-configuration-v1.json),
and both implementations are tested against its cases rather than against each other:

- App: `services/api-service/src/services/repositoryConfig.js`, tested by
  `services/api-service/tests/repositoryConfig.test.js`
- Action: `action/orchestrator/repo_config.py`, tested by
  `action/tests/test_repository_config.py`

## When the file cannot be used

The file comes out of the repository under review, so it is treated as untrusted input. It can
only ever remove files from the analysis: there is no key that adds a file, changes how one is
scanned, or alters what is posted.

A file that is not valid YAML, is not a mapping, has an `exclude` that is not a list of strings,
or is larger than 64 KB is refused. The run then excludes nothing, reviews the whole pull
request, and says why in the log and as a workflow annotation. Failing towards a complete review
is the safe direction; silently reviewing nothing because a quote was unbalanced is not.

An unknown top-level key is ignored rather than refused, so a file written for a newer version
still works.

## Limits

| Limit | Value |
| --- | --- |
| File size | 64 KB |
| Patterns | 200 |
| Pattern length | 500 characters |

## This repository's own file

The repository that ships Mitig8it excludes its own deliberately vulnerable corpora, because a
finding on one of them is the product working rather than a defect. See
[`.mitig8it.yml`](../../.mitig8it.yml) at the root.
