import { Lock } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import Header from '../components/Header'
import Footer from '../components/Footer'
import CtaPair from '../components/CtaPair'
import FixPipeline from '../components/FixPipeline'

/*
 * Every line on this page is sourced from the repository:
 *  - reads: services/github-service/src/services/githubInternalOperations.js
 *           (fetchPullRequestFiles, fetchRemediationSnapshot,
 *           assertInstallationRepositoryAndActor) and
 *           services/api-service/src/services/repoProfiler.js
 *  - writes: githubInternalOperations.js (createCheckRun,
 *            submitPullRequestReview, buildFixSection, publishRemediationComment)
 *  - verification level: README.md "Status" and
 *    services/remediation-service/src/verification/verifier.py
 *  - model calls: services/remediation-service/src/engine.py,
 *    services/analysis-service/src/llm_client.py, docs/getting-started/environment.md
 *  - data: services/api-service/migrations/*.sql
 *  - access: docs/getting-started/github-app.md,
 *    services/github-service/src/middleware/internalAuth.js, README.md
 */

const reads = [
  'The pull request diff, capped at 200 changed files.',
  'The changed files and the files they depend on, capped.',
  'Manifests and config files, capped at fifteen, for framework detection.',
  'Nothing outside the installed repositories.',
]

const writes = [
  'A check run on the commit.',
  'Review comments on the changed lines.',
  'Suggestion blocks under each finding.',
  'A residual report after a human applies a fix.',
  'Nothing to your code: the App holds no write access to repository contents.',
]

const modelCalls = [
  'Template fixes make no model call and charge zero tokens.',
  'Triage runs on gemini-2.5-flash-lite or gpt-4o-mini; repair on gpt-4o.',
  'Secret paths are excluded; API keys are stripped from logs.',
  'Repair models see only the snapshot of changed files and their dependents.',
]

const dataKept = [
  'Findings with severity, confidence and evidence.',
  'Remediation jobs, attempts and actions.',
  'Verification runs and evidence digests.',
  'Run history and audit logs.',
  'Uninstalling the App deletes all of it for that installation within 24 hours.',
]

const access = [
  'Contents read-only. Pull requests and checks read/write. Metadata read-only.',
  'Write actions require an actor with repository write access.',
  'Services authenticate to each other with a shared constant-time secret.',
  "A fix reaches the branch only through GitHub's Commit suggestion button, under your identity.",
]

const sectionHeading = 'text-2xl font-semibold tracking-tight text-white sm:text-3xl'

const FactList = ({ items }) => (
  <ul className="mt-8 grid gap-px overflow-hidden rounded-2xl border border-neutral-800 bg-neutral-800 sm:grid-cols-2">
    {items.map((item) => (
      <li key={item} className="flex items-start gap-3 bg-neutral-950 px-5 py-4">
        <span
          className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400"
          aria-hidden="true"
        />
        <span className="text-sm leading-6 text-neutral-400">{item}</span>
      </li>
    ))}
  </ul>
)

export default function SecurityPage() {
  const { loginWithGitHub, user } = useAuth()

  return (
    <div className="min-h-screen bg-neutral-950 text-white">
      <Header />

      <main>
        {/* Hero */}
        <section className="relative overflow-hidden">
          <div className="pointer-events-none absolute inset-x-0 top-0 h-[360px] bg-[radial-gradient(ellipse_60%_100%_at_50%_0%,rgba(16,185,129,0.10),transparent_70%)]" />

          <div className="relative mx-auto max-w-6xl px-4 pt-20 sm:px-6 sm:pt-28 lg:px-8">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="text-balance text-4xl font-bold leading-[1.05] tracking-tight text-white sm:text-5xl">
                What Mitig8it reads, writes, and keeps
              </h1>
              <p className="mx-auto mt-6 max-w-xl text-base leading-7 text-neutral-400">
                The exact boundaries of the app, stated plainly.
              </p>
            </div>
          </div>
        </section>

        {/* Reads */}
        <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <h2 className={sectionHeading}>What it reads</h2>
          <FactList items={reads} />
        </section>

        {/* Writes */}
        <section className="border-t border-neutral-800">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
            <h2 className={sectionHeading}>What it writes</h2>
            <FactList items={writes} />

            <div className="mt-px flex items-center gap-3 rounded-2xl border border-emerald-400/30 bg-emerald-400/10 px-5 py-4">
              <Lock className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
              <p className="text-sm font-medium text-emerald-100">
                It never commits or merges on its own.
              </p>
            </div>
          </div>
        </section>

        {/* Verification */}
        <section className="border-t border-neutral-800">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
            <h2 className={sectionHeading}>How a fix is verified</h2>

            <FixPipeline className="mt-10" />

            <p className="mt-10 max-w-2xl text-sm leading-6 text-neutral-400">
              Verification runs in a development-grade local sandbox, without kernel isolation. Each
              fix says so in its Details.
            </p>
          </div>
        </section>

        {/* Model calls */}
        <section className="border-t border-neutral-800">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
            <h2 className={sectionHeading}>Model calls</h2>
            <FactList items={modelCalls} />
          </div>
        </section>

        {/* Data kept */}
        <section className="border-t border-neutral-800">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
            <h2 className={sectionHeading}>Data kept</h2>
            <FactList items={dataKept} />
            <p className="mt-6 text-sm leading-6 text-neutral-500">
              Each row is scoped to its GitHub installation.
            </p>
          </div>
        </section>

        {/* Access */}
        <section className="border-t border-neutral-800">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
            <h2 className={sectionHeading}>Access</h2>
            <FactList items={access} />
          </div>
        </section>

        {/* Close */}
        <section className="mx-auto max-w-6xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8">
          <div className="rounded-2xl border border-neutral-800 bg-neutral-900 px-6 py-14 text-center sm:px-16">
            <h2 className={sectionHeading}>Try it on one repository</h2>
            <div className="mt-8">
              <CtaPair user={user} onLogin={loginWithGitHub} />
            </div>
            <p className="mt-8 text-sm text-neutral-500">
              Report a security issue to{' '}
              <a
                href="mailto:support@mitig8it.com"
                className="font-medium text-emerald-400 transition hover:text-emerald-300"
              >
                support@mitig8it.com
              </a>
            </p>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  )
}
