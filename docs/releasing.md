# Releasing

What a version number promises, how a release is cut, and what the owner has to do by hand.

Nothing here has been run. `.github/workflows/release.yml` exists, its gates and its ordering have
tests, and no `v*.*.*` tag has ever been pushed to this repository. The first release is the first
time this procedure runs, which is why the dry run is the default and why step 2 below is a dry run.

## The versioning policy

The versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html), applied to the
things a user's workflow file depends on and not to the review itself. The distinction matters
enough to be stated twice, because it is the surprising half.

### Stable: a major bump, announced, with a migration note

- **The action's inputs.** Names, meanings and defaults: `github-token`, `fail-on`, `post-fixes`,
  `model-api-key`, `model-provider`, `model`, `max-files`. Removing one, renaming one, or changing
  a default in a way that changes behaviour is a major bump. `fail-on: none` staying the default is
  part of the promise: installing a security review must never break a merge on the day it is
  installed.
- **The action's outputs.** `findings`, `critical`, `high`, `fixes`, `conclusion`, and what each
  one means.
- **The `.mitig8it.yml` format.** The keys, the glob syntax, and the rule that an excluded path is
  dropped before any content is fetched. A file that works on 1.0.0 works on every 1.x.
- **The permissions the action requires**, and its refusal to run with `contents: write`.
- **The check run name**, `Mitig8it Security Review`, because a required status check is configured
  by name and renaming it would silently stop blocking.

### Not stable: any release may change these

- **The rule sets.** Rules are added, widened, narrowed and removed between patch releases.
- **Measured precision and recall.** These are measurements, not commitments. They are expected to
  move, and every published figure names the run that produced it.
- **Which findings post.** A rule whose measured precision falls below 0.8 over at least three
  adjudicated findings is quarantined: it still runs and is still counted, and nothing it produces
  reaches a reviewer. A quarantine can be applied or lifted in a patch release.
- **The wording of a comment, a review body or a check summary.** A patch release may rewrite any
  of it. A test that greps our review text will break, and that is not a breaking change.
- **Which repairs are attempted, and the verification level a fix reports.**
- **The contents of the image**: the scanner version, the Python and Node versions, the size.

A consequence worth saying out loud: **a minor or patch release can change what your pull requests
report.** More findings, fewer findings, different wording. If that is not acceptable, pin the
digest and upgrade deliberately.

## How a user pins

| Ref | What it promises | When to use it |
| --- | --- | --- |
| `@v1` | The newest 1.x. The stable surface above does not change under you | The documented default |
| `@v1.0.0` | One release, frozen, until you bump it by hand | You want to choose when rules change |
| `@<40-character sha>` | One commit. Nobody can move it, including us | You pin everything, and our own rule agrees with you |

`@v1` is a tag, and a tag is a thing its owner can move: that is what moving `v1` on every 1.x
release means. So `cwe-1357.gha-third-party-action-unpinned`, this product's own rule, would flag
`@v1` in your workflow, and it is right to. The quickstart shows `@v1` because it is the form a
reader can retype, with a comment saying what the stronger pin is and how to get one:

```sh
gh api repos/aicodesentry/mitig8it/commits/v1 --jq .sha
```

`@main` is not offered, and a test fails if any documented install ever names a branch again.

## Cutting a release

Two paths. **The dispatch is the recommended one**, and the reason is in the next section.

### 1. Prepare, on a pull request

1. Move everything under `## [Unreleased]` in `CHANGELOG.md` into a new `## [X.Y.Z] - YYYY-MM-DD`
   section, with the date you intend to release on. The release refuses to run while the date reads
   `unreleased`, and nothing in this repository will invent one for you.
2. Check the section is the topmost released one. The release refuses a version that is documented
   below a newer one, because then the tag and the notes disagree about what is being released.
3. Merge it to `main` and let CI go green. The release refuses a commit on which the `CI` or
   `Action image` workflow has not concluded successfully.

### 2. Dry run

Actions, Release, Run workflow, version `X.Y.Z`, **dry run checked** (it is the default).

Every gate runs, the image is built and tested, the SBOM is generated, and nothing is pushed. The
job summary lists what a real release would have done. This is how the machinery is exercised
without releasing anything, and it is worth doing before the first real release and before any
release that follows a change to this workflow.

### 3. Release

Either:

- **Dispatch** (recommended): the same form, **dry run unchecked**. No tag exists yet, so the
  workflow creates `vX.Y.Z` on the release commit and moves `vX`. Nothing is ever moved out from
  under anybody.
- **Tag push**: `git tag vX.Y.Z && git push origin vX.Y.Z`. The workflow runs, and then
  **force-moves the tag you just pushed** onto the release commit it created. Read the next section
  before using this path.

### 4. Afterwards, by hand

1. **Make the package public.** A new `ghcr.io` package is private, and a private package means
   every user's pull fails and silently falls back to building from source: the review is identical
   and the cold start is the one this release was meant to fix. Packages, `mitig8it-action`, Package
   settings, Change visibility, Public. Check it with `docker logout ghcr.io && docker pull`.
2. **Verify the attestation**, as a user would:
   `gh attestation verify oci://ghcr.io/aicodesentry/mitig8it-action:X.Y.Z --owner aicodesentry`.
3. **Read the release page.** The notes are the changelog's own section, so anything wrong there was
   wrong in the changelog.
4. **Time a cold run.** Install `@vX` on a fresh repository and read the job log. Until this is
   done, no cold-start number for a released ref exists, and none should be published.
5. Open the next `## [Unreleased]` section.

## Why the release creates a commit of its own

`uses: aicodesentry/mitig8it/action@v1` makes GitHub check this repository out at the tag and run
`action/action.yml` from it. For the action to pull its image by digest rather than resolve a mutable
registry tag at review time, the digest has to be in the tree at that ref. The digest does not exist
until the image is built, and the image is built after the tag is pushed. Something has to give.

What gives is the tag. The workflow builds, pushes, writes `action/released-image.env` on a commit
whose parent is the commit being released, and points `vX.Y.Z` and `vX` at that commit. The release
commit is reachable from the tags and from nowhere else; `main` is left alone, so no workflow ever
pushes to a protected branch.

On the dispatch path there is no tag to move: the workflow creates it. On the tag-push path the tag
already exists, and the workflow force-updates it within the minute. Anyone who fetched `vX.Y.Z`
between the push and the update would hold a different commit than the release, which is harmless
and annoying to explain. That is the whole reason the dispatch is recommended.

## What `released-image.env` is for

On `main` its three values are empty, and that is the correct state: an unreleased ref has no
published image, so the action builds from source there exactly as it always did. The release
workflow fills it in on the release commit. `action/README.md` has the table of which refs pull and
which build, and the four conditions that have to hold before a pull is attempted.

A test asserts the committed file stays empty, because a filled-in file on `main` plus a tag on an
older commit is the one combination that could make a released ref pull a stale image.

## The Marketplace answer

**`action/action.yml` cannot be listed on the GitHub Marketplace where it is.** The Marketplace
requires the action's metadata file at the **root of the repository**: "Each repository must contain
a single action metadata file (`action.yml` or `action.yaml`) at the root." A metadata file in a
subfolder works perfectly well for `uses:` and is not listed.

So there are two separate questions, and only the first is answered by the work in this repository.

### Pinnable and installable: done

`uses: aicodesentry/mitig8it/action@v1` works today, from a release, with a published image, a
provenance attestation and an SBOM. Nothing about the Marketplace is required for a user to install
the action, and nothing below blocks a release.

### Listed on the Marketplace: an owner decision, because the action would have to move

The requirements, and where this repository stands:

| Requirement | Status |
| --- | --- |
| The repository is public | Yes |
| `action.yml` at the repository root | **No.** It is at `action/action.yml` |
| A unique `name` in the metadata | `Mitig8it Security Review`. Uniqueness is checked at publish time against every listed action, every GitHub user and organisation name, and GitHub's own reserved names. Unknown until the draft is validated |
| `branding.icon` and `branding.color` | Yes: `shield`, `green` |
| A README describing the action | Yes: `action/README.md`, which would have to move with it |
| The owner has accepted the Marketplace Developer Agreement | Owner action. The publish checkbox is disabled until they have |
| Two-factor authentication on the publishing account | Owner action |

The owner's steps, once the move below is made: open the metadata file on GitHub, click **Draft a
release** from the banner, tick **Publish this Action to the GitHub Marketplace**, resolve whatever
the metadata validator reports, choose a primary and an optional secondary category, give it the
version tag and a title, and publish. Publishing requires two-factor authentication on the account.

### Exactly what moving `action.yml` to the root would break

Every item is a real edit, not a risk:

1. **`github.action_path` becomes the checkout root.** Every path in `action.yml` is written
   relative to it, and `${{ github.action_path }}/..` is currently the repository root. At the root
   it becomes the parent of the checkout, which on a runner is `/home/runner/work/<repo>`, so the
   build context, the cache-key hashing and `released-image.env` all resolve to the wrong place.
2. **`build-image.sh` derives the build context from its own location** (`SCRIPT_DIR/..`). Either
   the script moves to the root, where `..` is wrong for the same reason, or it stops deriving the
   context and is given it. `test_action_definition.py` asserts the current derivation literally.
3. **`uses: ./action` in `.github/workflows/mitig8it-self-review.yml` becomes `uses: ./`**, and a
   test asserts the current value.
4. **The install string changes** from `aicodesentry/mitig8it/action@v1` to
   `aicodesentry/mitig8it@v1`, in four documented places plus the release notes the workflow
   generates. Every existing `/action@v1` pin breaks, so the move is itself a major bump.
5. **`action/README.md` is the Marketplace listing's description** and would have to move to the
   root README or be merged into it. The root README is the repository's front page and describes
   the App as well as the Action.
6. **`.github/workflows/action-build.yml` path filters** and every `working-directory: action` in
   CI change.
7. **A second metadata file at the root of a repository that also holds two services, a frontend
   and the infrastructure** invites the reading that the repository is the action. The Marketplace
   listing would be for the action; the repository is the product.

A cleaner alternative, and the one worth considering before moving anything: publish the action from
its own small repository that contains only `action.yml`, a README and a thin `uses:` of the image
this workflow already publishes. That keeps the monorepo's layout, keeps the existing pin working,
and gives the Marketplace the root metadata file it requires. It is a decision about distribution
rather than a defect, so it is recorded here and in `ROADMAP.md` and not acted on.
