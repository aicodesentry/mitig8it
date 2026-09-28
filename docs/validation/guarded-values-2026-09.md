# Three rules that reported correct code

Measured 2026-09-28, on the same trial pull request as
[concatenation-arity-2026-09.md](concatenation-arity-2026-09.md).

That pull request carried a file written as the correct version of four operations the other
files got wrong. Four findings posted on it. A rule that fires on the corrected form is worse
than a rule that misses: it tells a reader the change it just asked for is also a defect, and
it does that on the one file in the review where the author did the right thing.

Three of the four are addressed here. Each is a rule matching something other than what it
meant to match.

## The letter f before a quote

`cmd.injection.shell_true` is a tier 1 regex whose alternatives are the things that make a
shell call dangerous: `shell=True`, a concatenation, an f-string, a backtick, a request
object. The f-string alternative was written as the two characters `f"`.

Those two characters occur in ordinary text. They occur here:

```python
subprocess.run(["tar", "-czf", str(archive), str(target)], check=True)
```

`"-czf"` ends an argument in the letter f, and the next character is a quote. The rule
reported an argument list with no shell, at critical severity, as command injection. Any
command whose flags end in f does this, and `tar -czf` is not a rare way to write a tar
command.

The alternative is now `(?<![A-Za-z0-9_])f["']`, which requires the f to begin a token. A real
f-string is preceded by a bracket, a space, a comma or an equals sign, so it still matches, and
the single-quoted form `f'...'` now matches too, which it never did before.

## An f-string with nothing in it

`sql.injection.raw_query` asked for an f-string containing a SQL keyword:

```
f['"].*(?:SELECT|INSERT|UPDATE|DELETE)\s+
```

Nothing in that requires an interpolation. `f"SELECT id, status FROM orders"` is a constant
query written with an f prefix, which is a habit rather than a defect, and it was reported as
SQL injection. The branch now ends in `.*\{`, so it asks for an interpolation to exist before
it calls the query built.

## A value that was checked two lines above

An identifier cannot be a bound parameter. A dynamic `ORDER BY` column therefore has to be
interpolated, and the way to make that safe is to check it against an allowlist first:

```python
if sort_column not in ALLOWED_SORT:
    raise ValueError("unsupported sort column")
cursor.execute(
    f"SELECT * FROM orders WHERE status = ? ORDER BY {sort_column}",
    (status,),
)
```

The user value is bound. The interpolated name can only be one of three constants. This is the
correct way to write it, and `cwe-89.py-execute-fstring-direct` reported it, advising the
reader to do what the code already did.

The rule now carries two `pattern-not-inside` clauses that withdraw the finding when the
enclosing function tests the interpolated name for membership, in either direction. The clause
binds the same metavariable, so a membership test on some other variable does not suppress
anything. The unguarded form is still reported, and there is a benchmark case for each.

## What is left

The same statement is still reported by the tier 1 rule, because tier 1 is a regex pass and an
allowlist two lines above is not a thing a regex can see. On the trial file that leaves one
false positive where there were two, on the same line, from the two tiers.

The fourth finding on that file is not fixed and is not counted as a false positive here. It
is a `pathlib` join whose name was validated for containment earlier in the function but not
on the path the finding names. Suppressing it would need the rule to know which value was
checked, not merely that a check occurred somewhere in the function, and a clause that
suppressed on the weaker condition would hide a genuinely unguarded path in any function that
guards a different one. It is recorded as unsure rather than argued either way.

## What it cost

| Gate | Before | After |
| --- | --- | --- |
| Tier 1 precision gate | 91 of 91, from 39 adjudicated findings | 91 of 91, from 43 |
| Tier 2 precision gate | 163 of 163, from 155 adjudicated findings | 165 of 165, from 157 |
| Remediation corpus, reference adapter | 63 of 63 | 63 of 63 |
| Remediation corpus, engine-local adapter | 63 of 63 | 63 of 63 |

Four cases were added to the tier 1 set and two to the tier 2 set: each suppression is pinned
by a case that must not fire and by a case that must, so neither fix can quietly grow into
silence on a real defect.

On the trial file itself, what posts falls from four findings to two, and nothing that posts
on the three vulnerable files is lost.
