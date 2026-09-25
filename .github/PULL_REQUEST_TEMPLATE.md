# What this changes

<!-- One or two sentences. The subject line of the commit is usually enough. -->

# Why

<!-- What went wrong without it, or what it makes possible. -->

# Evidence

Fill in what applies and delete the rest. A change that touches behaviour needs at least one line
here, and "the tests pass" is not one: say which suite, and paste the counts.

**Suites run**

```
make test
```

<!-- Paste the result. If you ran one target, say which: make test-frontend, and so on. -->

**Benchmarks**, if this touches a rule, a template, a proof generator, the posting policy, or the
corpus:

```
make bench
```

<!-- Paste the summary table. Compare it against the reference output in
     docs/validation/README.md and say what moved. -->

**If this adds or changes a rule**

- Rule id:
- Findings over the corpus, and how many were adjudicated:
- Measured precision:
- Posting decision, and why the policy gives that answer:
- Cases added to `benchmarks/tier1-precision/cases.json` or `benchmarks/tier2-precision/cases.json`:
- Where the measurement is written down under `docs/validation/`:

**If this adds or changes a fixture or a repair family**

- Fixture ids:
- Result under `--adapter reference`:
- Result under `--adapter engine-local`:
- `summary.unexpected_failures` is empty: yes / no, and if no, the `known-failures.json` entry
- What the generated proof does, and what makes it fail on the original code:

**If this changes a number that appears in the README or in a document**

- Which document, and which line:

# What this does not do

<!-- The honest part. What you left, what you could not measure, what you are unsure about.
     A PR that says "recall for this class is still 0.4 and here is why" is worth more than one
     that does not mention recall. -->

# Checklist

- [ ] No em-dashes, in the code or in the commit messages.
- [ ] No `Co-Authored-By` trailer naming a model, and no "generated with" line.
- [ ] Any new number in the documentation links to the run that produced it.
- [ ] Anything development-grade is described as development-grade.
