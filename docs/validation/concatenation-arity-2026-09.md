# A concatenated sink was only found when it had few enough pieces

Measured 2026-09-28, on the pull request that found it.

## What was wrong

Forty-two rule clauses across six language packs asked whether a string literal sat at one
particular operand position of a concatenation. `$CURSOR.execute("..." + $INPUT)` binds when
the argument's outermost `+` has a literal on its left. A longer string does not have that
shape: `a + b + c + d` parses as `((a + b) + c) + d`, so the outermost left operand of a
four-piece string is itself a concatenation, and the clause cannot bind.

The consequence was a detection gate on how many pieces an author happened to write the bug
in. This statement was reported by nothing:

```python
cursor.execute("SELECT * FROM orders WHERE status = '" + status + "' ORDER BY " + sort_column)
```

Four pieces, two injected values, no unusual construction. In the same file a two-piece and a
three-piece sink were both reported, so the silence was not a scoping or filtering decision.
It was the rule failing to bind.

The picture per language, established by running each pack over a fixture holding the same
statement written at two through six pieces:

| Pack | Reported before | Reported after |
| --- | --- | --- |
| Python, `cursor.execute` concatenation | 2 and 3 pieces | 2 to 6 pieces |
| Python, `os.system` concatenation | 2 to 6 pieces | 2 to 6 pieces |
| JavaScript, `db.query` concatenation | 2 pieces | 2 to 6 pieces |
| JavaScript, `exec` and `execSync` concatenation | 2 pieces | 2 to 6 pieces |
| PHP, `mysqli_query` concatenation | 2 pieces | 2 to 6 pieces |
| Java, `executeQuery` concatenation | 2 pieces | 2 to 6 pieces |
| Go, `db.Query` concatenation | 2 pieces | 2 to 6 pieces |
| C#, `SqlCommand` and `CommandText` concatenation | none | 2 to 6 pieces |

Python's `os.system` rule was the one that already worked, because it was written with
ellipsis operands rather than a pinned literal. C# reported none of them: its only
concatenation clause required the three-piece form, and the two-piece and four-piece shapes
both fell outside it.

JavaScript is the one to read twice. Its SQL and command rules held the two-piece clause
alone, so a three-piece string was already enough to pass unseen, and three pieces is what you
get the moment a value is interpolated in the middle of a string rather than at its end.

## The change

Each clause now uses the deep expression operator:

```yaml
- pattern: $CURSOR.execute(<... "..." + $INPUT ...>)
```

This asks whether a literal is concatenated with something anywhere inside the argument
instead of at one position in it. That is a property of the argument, so the number of pieces
stops mattering. Forty-two clauses were converted and two that collapsed into duplicates of a
sibling were removed.

The operand-ellipsis form that Python's `os.system` rule uses was tried first and rejected: it
works in Python but matches nothing in JavaScript, and it does not match a two-piece string in
either, so it would have needed a second clause per sink. The deep expression form behaves the
same way in every language tested here.

## What it cost

Nothing measurable, on everything that was measured:

| Gate | Before | After |
| --- | --- | --- |
| Tier 1 precision gate | 91 of 91 | 91 of 91 |
| Tier 2 precision gate | 163 of 163 | 163 of 163 |
| Remediation corpus, reference adapter | 63 of 63 | 63 of 63 |
| Remediation corpus, engine-local adapter | 63 of 63 | 63 of 63 |
| Analysis service suite | 1902 passed | 1902 passed |

The tier 2 gate is the one that matters here, because its 163 cases are built from 155
findings adjudicated by hand and include the suppression cases that exist to catch a rule that
starts matching something it should not. None of them changed. A broader clause could have
been paid for in false positives and was not, on this evidence.

One line in the trial fixture began matching two rules instead of one, `os.system` interpolation
and `os.system` command injection. The clusterer folds it: five raw tier 2 findings became four
after `cluster_findings`, so no second comment reaches a reviewer.

This is not a recall measurement. Recall is measured on the vulnerable corpus, which downloads
23 repositories and replays them, and that has not been re-run since this change; the figure in
[vulnerable-corpus-2026-09.md](vulnerable-corpus-2026-09.md) still describes the rules as they
were. What is established here is that eight sink families in six languages now report a
concatenation of any length, and that nothing the existing gates measure got worse.

## How it was found, and what else that pull request said

A pull request was opened on a test repository holding four files: three with deliberate
defects and one, `safe_orders.py`, written as the correct version of the same four operations.
Fourteen findings, twelve posted as inline comments, three carrying a verified fix.

Adjudicated by hand:

| Verdict | Count | What they were |
| --- | --- | --- |
| True positive | 9 | Three workflow findings, a hardcoded credential, SQL injection and command injection each reported by both tiers, and `eval` on a caller-supplied string. |
| False positive | 2 | One statement in `safe_orders.py`, reported by a tier 1 and a tier 2 rule, where the interpolated identifier is checked against an allowlist two lines above and the user value is passed as a bound parameter. |
| Unsure | 1 | A `pathlib` join in `safe_orders.py` whose name was validated for containment earlier in the function, but not on the path the finding names. |

Three defects in the vulnerable files were reported by nothing. Two were the arity defect this
document is about and both are now reported. The third is a path traversal assembled into a
local variable and then opened:

```python
path = EXPORT_ROOT + "/" + filename
with open(path) as handle:
```

Written inline, `open(EXPORT_ROOT + "/" + filename)` is reported. Through the variable it is
not, because matching is sink-only and there is no taint tracking to carry the value from one
statement to the next. That is the documented limitation and this is what it costs on ordinary
code: one statement of indirection.

The two false positives are a different problem, and the more expensive one for trust: a rule
that fires on the corrected form tells a reader that the change it just asked for is also a
defect. Both come from a rule that cannot see the guard protecting the value, the allowlist
membership test in one case and the containment check in the other. A `pattern-not-inside`
clause scoped to the enclosing function suppresses both correctly in a probe, and leaves the
unguarded form reported. That is not in this change, and it is the next thing to do here.

## Reproducing

```sh
cd services/analysis-service/src && python -m pytest tests/test_concatenation_arity.py -q
```

The test holds the same statement written at two through six pieces for each sink family in
each language, plus the parameterised counterpart that must stay silent. It asserts the
property rather than the fix, so a rule rewritten some other way passes it unchanged and a
rule that reacquires a position-pinned clause fails it. Against the rules as they were it
fails seven of its eight language cases.
