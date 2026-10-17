# One hop of data flow

Written 2026-10-17, against the 23 snapshots and 171 labels of
[vulnerable-corpus-2026-09.md](vulnerable-corpus-2026-09.md).

Three gaps that document measured share one missing question: where did this value come from,
and was it escaped on the way.

* **Command injection, one variable away.** systeminformation (CVE-2026-50289) and all three
  electerm labels (CVE-2026-49255) build a command string on one line and run it on the next.
  `cwe-78.js-exec-interpolated` needs the interpolation inside the call, and widening it to
  `exec($VAR)` for any variable is the shape the corpus write-up says ends at a precision of
  0.02.
* **Path traversal.** The broad tier 1 rule, `path.traversal.user_path`, is quarantined at 0.43
  because a regex cannot tell a request-controlled path from the brace of an options object.
* **HTML built by interpolation.** `cwe-79.js-html-string-interpolated` fired 678 times and is
  quarantined at 0.47, because it cannot see `escapeHtml(...)` or `escape.xml(...)` around a
  value, and cannot tell data from markup that was already built.

Each needs a rule that follows a value from a source to a sink and stops at a sanitizer. The
scanner's taint mode does that within one function. Before this change 8 of the 177 rules used
it, and none of them was in a coverage file.

## What changed

Five taint rules, in the two coverage files beside the pattern rules they extend:

| Rule | Taint variant of | Family |
| --- | --- | --- |
| `cwe-78.js-exec-tainted` | `cwe-78.js-exec-interpolated` | `command_arguments` |
| `cwe-78.py-subprocess-tainted` | `cwe-78.py-subprocess-shell-interpolated`, `cwe-78.py-os-system-interpolated` | `command_arguments` |
| `cwe-22.js-fs-tainted-path` | `path.traversal.user_path` (tier 1) | `path_containment` |
| `cwe-22.py-open-tainted-path` | `path.traversal.user_path` (tier 1), `cwe-22.py-open-request-path` | `path_containment` |
| `cwe-79.js-html-tainted-interpolation` | `cwe-79.js-html-string-interpolated` | none |

**All five are quarantined.** The posting policy in
[analysis-service.md](../services/analysis-service.md) lets a rule post on measured precision of
at least 0.8 over three adjudicated findings, or with no findings when its pattern is sink-only
and makes no data-flow assumption. A taint rule is a data-flow assumption, so the second clause
does not apply, and nobody has adjudicated a finding of these rules, so the first does not
either. Each rule carries `posting_evidence` saying so and `precision_evidence` reading
"unmeasured on the corpus, taint variant of" the rule above. No quarantined rule was deleted
or renamed, and nothing that posted before posts differently now.

Each rule declares `analysis_scope: taint-intraprocedural`, a source, sink and sanitizer
description, and the sink metavariable, so `opengrep_runner` sets `is_taint_based` and builds
the source-to-sink trace. `tests/test_tier2_rule_metadata.py` now fails on a taint rule in a
coverage file that leaves any of those out.

### Sources

| Rules | Sources |
| --- | --- |
| both command rules | request fields (`req.params/query/body/headers`, `request.args/form/values/json/get_json()/headers/cookies`, Django `request.GET/POST`), `process.argv`, `sys.argv`, a Flask route's own parameters, and **a value interpolated or concatenated into a string** |
| both path rules | the same request fields, `request.files`, argv, Flask route parameters |
| HTML | request fields and cookies, the page's own URL (`location.*`, `document.URL`, `document.referrer`, `window.name`), and `getAttribute(...)` |

The interpolated-value source on the command rules is what makes them a one-hop extension of
the interpolated pattern rules rather than new rules: the pattern rules already report any
value interpolated into a shell string inside the call, and these follow that same value one
assignment further. Without it neither CVE in the brief is reachable, because systeminformation's
`file` and electerm's `localFolderPath` are function parameters, not request fields. A command
built inside the call is excluded from the sink, because that is the pattern rules' shape and
they post on their own evidence; these rules report only what those cannot see.

`getAttribute` is the HTML rule's one non-request source, and it is there because defuddle's CVE
arrives through it: an attribute value is decoded text, and putting it back into markup
unescaped re-opens whatever the page had encoded.

### Sanitizers

* Command: shell-quote's `quote`, `shlex.quote`, `shlex.join`, an allowlist `includes`/`has`/`in`
  test or a full-match regex test (inside the passing branch, or after a rejecting one), and any
  function named `sanitize*`, `escape*` or `quote*`. A value whose own name says it was escaped
  (`ifaceSanitized`) is not a source.
* Path: a `path.resolve` or `realpathSync` result (Python: `realpath`, `abspath`, `.resolve()`)
  tested with `startsWith`/`startswith`/`is_relative_to`, inside the passing branch or after a
  rejecting one; `safe_join` and `secure_filename`. A `startsWith` on the raw input is not
  containment, because `/srv/../etc/passwd` starts with `/srv/`, and `path.basename` is not a
  sanitizer, consistent with `PATH_CONTAINMENT` in
  `services/remediation-service/src/families.py`: `path.basename('..')` is `..`.
* HTML: `escapeHtml`, `escape.xml`, `he.encode`, `DOMPurify.sanitize`, `encodeURIComponent`,
  `sanitizeHtml`, `filterXSS`, the Handlebars, Mustache, lodash and validator escapers, and any
  function named `escape*`, `sanitize*` or `encode*`.

The name-based sanitizers are a heuristic and are written down as one. They can only remove
findings, so their cost is recall, never precision. They were added because the first
version of the command rule reported five lines of systeminformation's `network.js` whose
interface name had been through the library's own `util.sanitizeString`.

## The benchmark

`benchmarks/tier2-precision/cases.json` grows by 20 cases, from 157 to 177.

| Rule | True positives | No-finding cases |
| --- | --- | --- |
| `cwe-78.js-exec-tainted` | electerm's two-line shape; a request field run as the whole command; systeminformation's labelled line, lifted | got's `RegExp.prototype.exec` line; systeminformation's sanitized interface name, lifted; shell-quote, a rejecting allowlist and a constant, authored |
| `cwe-78.py-subprocess-tainted` | a Flask handler building `ping` | `shlex.quote`, a rejecting allowlist, an argument list, authored |
| `cwe-22.js-fs-tainted-path` | a `req.query` read through a join; `path.basename` as the only guard | juice-shop's constant `fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })`, lifted; resolve and `startsWith` in both forms, authored |
| `cwe-22.py-open-tainted-path` | whoogle's labelled `os.path.join(..., request.args.get('name'))`, lifted; a Flask route parameter through pathlib | realpath and `startswith`, `safe_join`, `secure_filename`, authored |
| `cwe-79.js-html-tainted-interpolation` | an interpolated `<img src="${src}">` returned from a helper; defuddle's labelled `og:image` line, lifted | defuddle's escaped link card, lifted; dicebear's `escape.xml` components, lifted; `he.encode`, `encodeURIComponent` and a JSON body, authored |

The defuddle no-finding case reads its values with the same `getAttribute` that the CVE does,
so it stays silent because `escapeHtml` is honoured, not because nothing is tainted. Removing
the escapers from it makes the rule fire on both lines; the same is true of the shell-quote and
allowlist case. The dicebear case is silent with or without its escaper, because no source in
the rule reaches a component's colours, and its note says so.

Authored no-finding cases are new to this file, whose README asked for lifted lines only. The
README now makes one exception, for a taint rule's sanitizers, and every such case says
`Authored, not lifted` at the start of its note.

## What the five rules find on the corpus

The five rules were run on their own, with the pinned scanner (semgrep 1.173.0) and the
production `--timeout 30` and `--max-target-bytes 500000`, over every `.js`, `.jsx`, `.mjs`,
`.cjs`, `.ts`, `.tsx` and `.py` file of the 23 cached snapshot trees, skipping `node_modules`
and `dist`. This is not the replay: it does not batch, does not apply the replay's vendored
directory filter or `should_fetch_content`, and runs no tier 1. It answers one question, which
labels these rules reach and how many findings that costs, and it answers it in four minutes
rather than the replay's hours.

**32 findings, 7 labels reached under an expected class.**

| Rule | Findings | Repositories |
| --- | ---: | --- |
| `cwe-78.js-exec-tainted` | 15 | systeminformation |
| `cwe-79.js-html-tainted-interpolation` | 8 | juice-shop 5, defuddle 3 |
| `cwe-22.py-open-tainted-path` | 5 | whoogle 2, dosage 2, pygoat 1 |
| `cwe-22.js-fs-tainted-path` | 3 | juice-shop |
| `cwe-78.py-subprocess-tainted` | 1 | pygoat |

| Label | Rule | Reached before this change |
| --- | --- | --- |
| `cve-systeminformation-cmdi-networkinterfaces` | `cwe-78.js-exec-tainted` | no |
| `pygoat-command-injection-cmd-lab` | `cwe-78.py-subprocess-tainted` | no |
| `cve-defuddle-xss-substack-ogimage` | `cwe-79.js-html-tainted-interpolation` | only by the quarantined `cwe-79.js-html-string-interpolated` |
| `cve-defuddle-xss-x-article` | `cwe-79.js-html-tainted-interpolation` | only by the quarantined `cwe-79.js-html-string-interpolated` |
| `cve-whoogle-config-path-join` | `cwe-22.py-open-tainted-path` | not by a tier 2 rule on main |
| `pygoat-path-traversal-ssrf-lab` | `cwe-22.py-open-tainted-path` | not by a tier 2 rule on main |
| `juice-path-vulncodesnippet-key` | `cwe-22.js-fs-tainted-path` | yes, by `cwe-22.path-traversal-fs` |

The "before" column comes from two places, and the difference matters. The command and HTML
rows are from the recall baseline that `feat/recall-ratchet` generated, which is main plus five
path rules, so for those classes it is main. The two path rows were checked by running main's
own tier 2 rule files on the two labelled files, which found nothing of the path class on the
labelled lines; tier 1 was not run for them, and the only broad tier 1 path rule is
quarantined. `feat/recall-ratchet` reaches both with a pattern rule of its own, so once it
lands these two are not new reach.

So the honest headline is **two labels no rule reached before, and two more that only a
quarantined rule reached**, for 32 findings. None of it reaches a reviewer until the rules are
measured, because all five are quarantined.

### What is still missed, and why

* **All three electerm labels.** The command is built in `rmrf`, `mv` and `cp`, and run by
  `run(cmd)` and `runWinCmd(cmd)`, which are local wrappers around node-bash and a promisified
  `exec`. An intraprocedural rule cannot follow a value into a function defined beside it.
  The scanner has an interprocedural mode for this, and turning it on changes every taint rule
  in the tree and its cost, so it is a separate change, not part of this one.
* **Two defuddle labels and both dicebear labels.** defuddle's `src` arrives through
  `this.getLargestSrc(img)` and its YouTube description through a method parameter; dicebear's
  values are the caller's options. None is a source an intraprocedural rule can name without
  becoming "any parameter", which is the 0.02 shape again.

### What the 32 findings look like, unadjudicated

Nothing below is a verdict, and nothing was written to `adjudications.json`. It is here so the
person who measures these rules knows where to look first.

* systeminformation accounts for all 15 of the JavaScript command findings. Besides the CVE
  line, three in `wifi.js` interpolate an interface name or SSID the caller passes, unsanitized,
  into `nmcli` and `wpa_cli`, which is the CVE's shape. The other eleven interpolate values the
  library computed itself: device names from its own disk listing into `smartctl` (five),
  process ids into `cat /proc/<pid>/stat` (three), the path `which ip` printed, the
  `nvidia-smi` path it located, and the command a Windows helper was handed. Expect this
  rule's precision to be decided by how those eleven are read.
* `cwe-79.js-html-tainted-interpolation` reports juice-shop's chat route writing
  `data: ${JSON.stringify(...)}` to a server-sent event stream. That is `res.write` on a
  response that is not HTML, and is the likeliest false-positive class for the `res.*` sinks.
  Its third defuddle finding, `hackernews.ts:210`, is `getAttribute('href')` into
  `<a href="${url}">` unescaped, the CVE's own shape in a file the fix did not touch.
* Two of the five Python path findings are dosage opening a lock file named from `sys.argv`. A
  command-line tool's own arguments are its user's, not an attacker's, and argv as a source is
  worth questioning on that evidence.

## Cost

Taint rules are slower than pattern rules, and the first version of the HTML rule was slow
enough to matter. On dvpwa's 366 KB `materialize.js` it took 7.5 seconds of match time, and in a
parallel scan of the tree it and the command rule both hit the 30 second per-rule timeout,
which the runner records as a file it could not analyse. The cost was the template sink
binding every expression in the file to a metavariable before testing it; a template pattern
with the tag test as a regex beside it reports the same lines in 1.6 seconds.

With that change the corpus scan reported no per-rule timeouts and took 237 seconds for all 23
trees. On `materialize.js` alone, the whole rule directory took 20 and 32 seconds of wall clock
on main and 29 and 49 seconds on this branch, in two runs each on a laptop that was doing
nothing else. Those numbers move by half between runs, so read them as "taint rules add a
noticeable fraction on a large file", not as a ratio.

### Fixpoint timeouts are silent

The scanner also gives up on individual functions. The clean corpus scan recorded 35
`Fixpoint timeout` warnings across five repositories (systeminformation 13, electerm 9,
defuddle 9, juice-shop 3, dvpwa 1), and main's own rule directory records
one on `materialize.js` too, so this is not new with these rules, only more frequent. When it
happens, the taint result for that function is dropped. Two scans of the same trees under
different machine load reported 31 and 32 findings, and the missing one was a juice-shop
`res.send` the rule reports every time the file is scanned alone.

semgrep 1.173.0 reports these under `time.fixpoint_timeouts`, not under `errors`.
`opengrep_runner._classify_scanner_errors` already lists `Fixpoint timeout` as a resource
limit, but it reads only `errors`, so in production a function the taint engine gave up on is
indistinguishable from a function with nothing in it. That is a pre-existing gap that these
rules make larger; it is recorded here rather than fixed, because it changes what the runner
reports for every taint rule in the tree.

## What is not measured

* **Precision, for all five rules.** No finding has been adjudicated. That is why they are
  quarantined.
* **The replay.** The numbers above are a direct scan of the five rules. The replay applies
  the production file filters, batches, and runs tier 1 alongside, and its recall table is the
  one the corpus document reports.
* **Anything in a pull request.** These are whole trees.
* **The interprocedural mode.** Not tried in production configuration; see electerm above.
* **Cost under the production batch.** The 120 second batch wall clock was not exercised with
  a batch made of large vendored files.
* **Which findings a fixpoint timeout hid.** The scan cannot say, by construction.

## How to measure it

The corpus replay, which is what a `precision_evidence` line for these rules has to name:

```sh
PY=~/.pyenv/versions/3.11.6/bin/python

# every repository and ref in the corpus, quarantined rules included so they are recorded
$PY - <<'EOF' > /tmp/corpus-refs.txt
import json
for repo in json.load(open("benchmarks/vulnerable-corpus/labels.json"))["repositories"]:
    print(repo["repo"], repo["ref"])
EOF
while read -r repo ref; do
  $PY scripts/replay/replay.py --snapshot --include-quarantined \
      --repo "$repo" --ref "$ref" --out "results/${repo//\//__}.json"
done < /tmp/corpus-refs.txt

# recall, and the reading list for precision: every finding on a labelled line under an
# unexpected class plus a seeded sample of the unlabelled
$PY scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
    --emit-queue /tmp/queue.json

# precision and recall once the verdicts are in adjudications.json
$PY scripts/replay/score.py results/*.json --labels benchmarks/vulnerable-corpus/labels.json \
    --adjudications benchmarks/vulnerable-corpus/adjudications.json --out /tmp/score.md
```

The seeded sample reads 40 of all unlabelled findings, and these five rules produce 32 of
several thousand, so the sample will reach few of them. Reading all 32 is cheaper than drawing
a sample large enough to.

The tests this branch ran, from `services/analysis-service/src`:

```sh
python -m pytest tests/test_tier2_precision_benchmark.py tests/test_tier2_rule_metadata.py -q
python -m pytest tests/test_opengrep_runner.py tests/test_opengrep_batching.py \
    tests/test_opengrep_unparseable_files.py tests/test_rule_metadata.py \
    tests/test_rule_posting_policy.py tests/test_template_rules_are_path_scoped.py \
    tests/test_workflow_rules_are_path_scoped.py tests/test_secrets_and_workflow_rules.py -q
```
