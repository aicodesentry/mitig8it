# Third-party scanner rules: licence review

Mitig8it is a paid service whose value derives substantially from the security rules it
runs. That makes the licence of any rule we did not write ourselves a product question,
not a formality. This page records what was checked before the tier 2 rule set was
widened in September 2026, what the answer was, and what we did about it.

**Outcome: no third-party rule content is used.** Every rule in
`services/analysis-service/src/opengrep_rules/` is original work of this repository. The
two obvious sources were both checked and both are excluded. Nothing was copied,
adapted, or translated from either.

## What was checked

All fetches on 2026-09-24.

### github.com/opengrep/opengrep-rules: excluded

`https://raw.githubusercontent.com/opengrep/opengrep-rules/main/LICENSE` is eleven lines
and is **not** plain LGPL-2.1. It is LGPL 2.1 with the Commons Clause condition attached:

> "Commons Clause" License Condition v1.0
>
> Without limiting other conditions in the License, the grant of rights under the License
> will not include, and the License does not grant to you, the right to Sell the Software.
>
> For purposes of the foregoing, "Sell" means practicing any or all of the rights granted
> to you under the License to provide to third parties, for a fee or other consideration
> (including without limitation fees for hosting or consulting/ support services related
> to the Software), a product or service whose value derives, entirely or substantially,
> from the functionality of the Software.
>
> Software: semgrep-rules (https://github.com/semgrep/semgrep-rules)
> License: LGPL 2.1 (GNU Lesser General Public License, Version 2.1)
> Licensor: Semgrep, Inc. (https://semgrep.dev)

A hosted security review that charges for scanning is exactly the case the Commons Clause
names: a service, for a fee, whose value derives substantially from the functionality of
the rules. The condition is not about distribution mechanics, so the usual observation
that a SaaS deployment never conveys a copy does not reach it. It bars the commercial use
outright.

Three further facts make this unambiguous rather than arguable:

* The fork never replaced the licence file. It still names `semgrep-rules` as the Software
  and Semgrep, Inc. as the Licensor. The commit history on that path has three commits, the
  most recent from May 2024, so the file predates the fork and was carried across unchanged.
* The README scopes the rules itself: "These rules are intended for research, testing &
  benchmarking." It makes no claim that they are cleared for production use, and it does
  not relicense anything.
* GitHub's own licence classifier reports `NOASSERTION` for the repository rather than
  LGPL-2.1, which is what the Commons Clause encumbrance produces. The repository is
  archived.

There are no per-directory licence files and no per-file licence headers anywhere in the
tree, so there is no subset of the repository under different terms that could be used
instead. The root licence governs all of it.

### github.com/semgrep/semgrep-rules: excluded

The whole licence file on `develop` is one line: "Semgrep Rules License v1.0. For more
details, visit https://semgrep.dev/legal/rules-license". As with the fork, there is one
licence file at the root, no per-directory split and no per-file headers, so every rule in
the repository is under those terms today. The historical LGPL-2.1 state ended with the
December 2024 relicensing; the pre-relicensing text is what the opengrep fork still carries.

The Semgrep Rules License v1.0 restricts use twice over:

> You may use the rules only for your own internal business purposes.

> This license does not allow you to distribute the rules, or to make them available to
> others as a service.

Semgrep's own documentation states the intent without hedging: "Vendors cannot use
Semgrep-maintained rules in competing products or SaaS offerings." This is a flat
prohibition on our use case.

### LGPL-2.1, for the record

If an unencumbered LGPL-2.1 rule source is ever found, these are the obligations that
would attach, so the next person does not have to redo the reading:

* Keep the copyright and licence notice on every copied file, and ship the licence text
  with any copy that is distributed (LGPL-2.1 §2).
* A file that is edited must carry a prominent notice saying it was changed and when
  (§1). Tuning a rule's pattern or adding our metadata is such a change.
* The "work that uses the library" distinction (§5-6) is written for linking and does not
  transfer cleanly to rule data. A copied rule file is the library itself and carries the
  obligations above whatever the surrounding service does.
* The obligations are triggered by distribution. A pure hosted service that returns only
  findings arguably never distributes the rules; an on-premises agent or CLI that bundles
  them plainly does, and then §1 and §2 apply in full. This is a real distinction and not
  a settled one, which is a reason to prefer rules we own.

None of this is currently in force, because no LGPL-2.1 rule file is present in the tree.

## What we did instead

Every rule in `services/analysis-service/src/opengrep_rules/` is written here. The rule
classes in `javascript_coverage.yml` and `python_coverage.yml` were chosen from the OWASP
Top 10 and the CWE Top 25, which are public taxonomies and carry no licence obligation,
and each pattern was written against fixtures in `benchmarks/tier2-precision/` rather than
derived from an existing rule file. A pattern that matches the same sink as a public rule
does so because there is one way to name `child_process.exec`, not because it was copied.

If a future change wants to import a rule from anywhere, the rule for doing so is:

1. Read the licence at the source's root and check for per-directory and per-file licences.
2. Record the licence, its exact restrictions and its obligations in this file **before**
   the copy.
3. Copy the file whole, keep its licence header, and add the notice of modification the
   licence requires if the rule is edited.
4. If the licence restricts commercial use, hosting, or availability as a service in any
   form, or if the answer is unclear, do not copy it. Write the rule instead.
