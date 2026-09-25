# Prove before post

A design note on why Mitig8it will not show you a fix it has not tested, what that test does, what
it does not establish, and what the measurements say it has cost.

## The problem with a suggested fix

A security scanner that only reports findings puts the whole cost on the reader: they have to
decide whether the finding is real, then work out what to do about it. Tools that also suggest a
fix move some of that cost, and introduce a worse one. A suggestion that looks right and is wrong
is more expensive than no suggestion at all, because it arrives with the authority of the tool
behind it and lands in a one-click button.

The failure is not hypothetical. A repair that parameterises a query and changes the placeholder
syntax for the wrong driver produces code that fails at runtime rather than at review. A repair
that contains a path by joining it to a base directory, but drops the check that the result stays
inside that directory, closes nothing while looking like it did. Both are the sort of change a
reviewer approves at a glance.

So the rule is: the product does not show you a fix it has not tested. Not a fix it believes in, or
one that pattern-matches something known to be safe. One it ran.

## What the proof is

For a finding the engine can repair, it does four things in order.

1. **Write a regression test for this specific finding.** Not a generic test for the weakness
   class: one that drives the vulnerable code path in this file, with an input that exercises the
   defect. The generator needs to be able to name the sink and to reach it, which is the constraint
   the rest of this note is mostly about.
2. **Run that test against the original code and require it to fail.** This is the step that does
   the work, and it is the one that is easy to leave out. A test that passes before the fix proves
   nothing about the fix. If the test does not fail here, the engine stops and reports nothing.
3. **Apply the repair and run the test again, requiring it to pass.**
4. **Run a second, separate check on both trees, requiring it to pass on both.** The regression
   test says the vulnerability is closed. This one says the code still does what it did: the repair
   did not close the hole by breaking the feature.

Only a candidate that clears all four is posted, as a GitHub suggestion block under the finding it
repairs, with a line saying what was verified. Anything else is either reported as a finding with
no fix, or not reported at all.

Nothing merges. The suggestion becomes a commit when a person clicks **Commit suggestion**, and
the App holds no write access to code: it asks GitHub for Contents read, Pull requests read and
write, Checks read and write, and Metadata read, and no code path exists that would commit, push
or merge. The Action refuses to start at all if the workflow grants it `contents: write`. The
proof is what makes a suggestion worth reading; the permission model is what makes the choice
still yours.

## What the proof is not

Read the verified line literally, because it is written literally.

**It is not an isolated sandbox.** The test runs as ordinary subprocesses, in the repair container
or in your runner, with no network, kernel or filesystem isolation. Every candidate the product
has produced, in the App and in the Action alike, is labelled `development_unverified`. The
comment says "development sandbox" rather than "isolated sandbox" for that reason. The isolated
Cloud Run Job driver is written and the `isolated_job` level exists; whether Cloud Run permits the
user namespace it depends on is decided by a smoke test that has not run.

**It is not a proof of correctness.** It is two test results. The repair closes the specific defect
the finding named, and the behaviour check still passes. It does not establish that the repair is
idiomatic, that it is the change your codebase would have made, or that the file has no other
vulnerability in it. It says nothing about a second SQL injection three lines down that no rule
matched.

**It is not a proof that the finding was real.** The proof is downstream of detection. If a rule
fires on safe code, the engine will usually refuse to repair it, because there is no test that can
fail on code with nothing wrong with it. Usually is not always, which is why the posting policy
measures rules separately: see [../validation/vulnerable-corpus-2026-09.md](../validation/vulnerable-corpus-2026-09.md).

**It is not a statement about your whole pull request.** A finding the tiers do not detect is not
a finding, and recall is the weaker half of the measurement.

## What the numbers say it has cost

Insisting on the proof costs coverage, and it has cost more of it than it looks like it should.
The September 2026 run over 23 vulnerable repositories is the record.

Of 1819 findings, 245 were in a supported repair family with the file available. Of those:

| | Findings |
| --- | ---: |
| The template can write a patch for | 33 |
| The service can write a proof for | 37 |
| Both, so a deterministic candidate is possible | 23 |
| Verified end to end | **8** |

Two obstacles were removed over this period. The templates used to need an enclosing Express route
and then an enclosing function; they now fall back to module scope. TypeScript used to be
unloadable in the sandbox; it now loads through Node's own type stripper. Between them those
changes cleared 249 refusals. The end-to-end count went from 8 to 8, both times.

That is the honest headline and it is the useful one. The refusals moved down to the next obstacle
rather than disappearing, and the constraint is the proof, not the patch. The largest single group
is 60 findings refused as `module_scope_source_not_controllable`: the sink runs at import and the
value reaching it comes from a call no test can set, so there is no test that fails before the fix.
Refusing those 60 is the correct answer, not a gap. A proof that cannot fail before the fix proves
nothing after it.

The eight that do verify are all `hardcoded_credential`.

The GitHub Action trial on ten real repositories says the same thing from the user's side: 65
comments posted, 63 of them true positives, and one fix in the whole trial. The report is
[../validation/action-trial-2026-09.md](../validation/action-trial-2026-09.md).

The authored corpus tells you something different and smaller. 55 fixtures pass under both
adapters with no unexpected failures, which says the fixtures, the grader and the pipeline agree
with each other. It is not a measurement of repair quality, and 55 authored cases cannot establish
a rate. [../../benchmarks/remediation/README.md](../../benchmarks/remediation/README.md) says so at
more length.

## What would make it stronger

In the order that would change the most.

**Run the proof in an isolated job.** This is the one that changes what the verified line is
allowed to say. Until it lands, the strongest claim available is that a test ran, not that it ran
somewhere untrusted code cannot escape.

**Reach the shapes that are refused for a fixable reason.** Of the current refusals,
`path_module_not_required` (65 findings) is files that build a path with string concatenation
rather than `path.join`, which the template needs by name. `function_parameters_not_plain_names`
(23 on the proof side, 22 on the template side) is destructured or defaulted parameters a generated
call cannot line up with. Neither is a reason to refuse in principle; both are the generator not
being general enough yet.

**Give the snapshot its dependency tree.** A module written with `import`/`export` gets the real
`express` or `pg` rather than the built-in fakes, which are injected through the CommonJS loader,
so its proof fails rather than passing. That is a ceiling rather than a defect, and it is recorded
in `services/remediation-service/contracts/test-harness-v1.md`.

**Grow the corpus and have it reviewed by someone else.** The release manifest asks for 120
externally reviewed cases, 20 supported per family, 30 negatives and 30 adversarial. No family
reaches 20, and there are no external review signatures at all. Until there are, a pass rate from
the corpus is a statement about those files.

**Measure what happens after posting.** Nothing currently records, across live installations, how
often a proven fix is committed, dismissed, or committed and then reverted. That is the number
that would tell us whether the proof means to a maintainer what it means to us, and it is the one
we do not have.

---

Related reading: [../architecture/security-guardrails.md](../architecture/security-guardrails.md)
for what the sandbox does and does not enforce,
[../architecture/limitations.md](../architecture/limitations.md) for the V1 limits, and
[../../ROADMAP.md](../../ROADMAP.md) for what is open.
