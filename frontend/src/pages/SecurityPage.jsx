import { Link } from 'react-router'
import { Database, GitBranch, Lock, ScanSearch, ShieldCheck } from 'lucide-react'
import Header from '../components/Header'
import Footer from '../components/Footer'
import { useAuth } from '../contexts/AuthContext'
import ProductSurface from '../components/ProductSurface'
import StatusBadge from '../components/StatusBadge'

const timeline = [
  {
    step: '01',
    title: 'Code enters the review pipeline',
    icon: GitBranch,
    summary: 'Mitig8it analyzes pull request changes through a staged security workflow instead of a single opaque pass.',
    bullets: [
      'Tier 1 runs deterministic pattern checks for fast first-pass coverage.',
      'Tier 2 adds structural analysis to inspect riskier code paths and stronger signals.',
      'Tier 3 triages, clusters, and suppresses weaker duplicates before output reaches the pull request.',
    ],
    accent: 'emerald',
  },
  {
    step: '02',
    title: 'Findings are shaped into review output',
    icon: ScanSearch,
    summary: 'The pipeline is designed to increase signal before a developer ever sees a comment.',
    bullets: [
      'Findings keep severity, confidence, and supporting evidence attached.',
      'Clustering reduces repeated comments on the same underlying issue.',
      'AI is additive to triage and explanation, not a replacement for deterministic analysis or human approval.',
    ],
    accent: 'sky',
  },
  {
    step: '03',
    title: 'User data stays inside clear boundaries',
    icon: Database,
    summary: 'Mitig8it only needs review-related repository and pull request data to generate GitHub-native output and preserve run history.',
    bullets: [
      'Review evidence persists so findings, reports, and audit trails stay explainable.',
      'Data kept: uninstalling the App deletes all stored data for that installation within 24 hours.',
      'It cannot push to your repository: the App does not hold write access to code.',
    ],
    accent: 'amber',
  },
  {
    step: '04',
    title: 'Access and platform controls secure the workflow',
    icon: Lock,
    summary: 'Security depends on scoped permissions, authenticated service boundaries, and explicit review controls.',
    bullets: [
      'GitHub App installations and repository permissions limit which repos Mitig8it can access.',
      'Authentication, session handling, and request validation protect dashboard and review flows.',
      'Internal services communicate through authenticated boundaries rather than open, unauthenticated hops.',
    ],
    accent: 'rose',
  },
]

const accentClasses = {
  emerald: {
    chip: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-200',
    dot: 'bg-emerald-300',
    card: 'border-emerald-400/20',
    line: 'bg-emerald-400/30',
    icon: 'text-emerald-200',
  },
  sky: {
    chip: 'border-sky-400/30 bg-sky-400/10 text-sky-200',
    dot: 'bg-sky-300',
    card: 'border-sky-400/20',
    line: 'bg-sky-400/30',
    icon: 'text-sky-200',
  },
  amber: {
    chip: 'border-amber-400/30 bg-amber-400/10 text-amber-200',
    dot: 'bg-amber-300',
    card: 'border-amber-400/20',
    line: 'bg-amber-400/30',
    icon: 'text-amber-200',
  },
  rose: {
    chip: 'border-rose-400/30 bg-rose-400/10 text-rose-200',
    dot: 'bg-rose-300',
    card: 'border-rose-400/20',
    line: 'bg-rose-400/30',
    icon: 'text-rose-200',
  },
}

const trustSurface = [
  {
    title: '3-tier PR review pipeline',
    status: 'live',
    description: 'Deterministic checks, structural analysis, and final triage already shape the findings that reach GitHub.',
  },
  {
    title: 'GitHub-native review output',
    status: 'live',
    description: 'Severity, confidence, and supporting evidence are attached to each review comment today.',
  },
  {
    title: 'Suggested remediation',
    status: 'progress',
    description: 'Explanation quality is being extended so findings guide the next engineering action more clearly.',
  },
  {
    title: 'One-click fix flows',
    status: 'live',
    description: "Fixes arrive as GitHub suggestions. GitHub's Commit suggestion button applies them under your identity; the App holds no write access to code.",
  },
]

export default function SecurityPage() {
  const { loginWithGitHub, user } = useAuth()

  return (
    <div className="min-h-screen bg-neutral-950 text-white">
      <Header />

      <main>
        <section className="border-b border-neutral-800/60">
          <div className="mx-auto max-w-6xl px-4 py-14 sm:px-6 lg:px-8 lg:py-16">
            <div className="max-w-3xl">
              <p className="text-xs font-semibold uppercase tracking-[0.28em] text-neutral-500">
                Security
              </p>
              <h1 className="mt-3 text-4xl font-semibold tracking-tight text-white sm:text-5xl">
                How Mitig8it generates findings and protects review data
              </h1>
              <p className="mt-5 max-w-2xl text-base leading-8 text-neutral-300">
                Trust comes from understanding the review pipeline, the data boundaries around it, and the controls that secure the workflow.
              </p>
            </div>

            <div className="mt-8 flex flex-wrap gap-3">
              <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/25 bg-emerald-400/10 px-4 py-2 text-sm text-emerald-200">
                <ShieldCheck className="h-4 w-4" />
                3-tier review pipeline
              </div>
              <div className="inline-flex items-center gap-2 rounded-full border border-neutral-700 bg-neutral-900 px-4 py-2 text-sm text-neutral-300">
                Review data boundaries
              </div>
              <div className="inline-flex items-center gap-2 rounded-full border border-neutral-700 bg-neutral-900 px-4 py-2 text-sm text-neutral-300">
                Scoped access controls
              </div>
            </div>
          </div>
        </section>

        <section className="py-16">
          <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
            <div className="grid gap-8 lg:grid-cols-[0.78fr_1.22fr]">
              <div className="lg:sticky lg:top-24 lg:self-start">
                <p className="text-xs font-semibold uppercase tracking-[0.28em] text-neutral-500">
                  Security timeline
                </p>
                <h2 className="mt-3 text-3xl font-semibold tracking-tight text-white">
                  One flow from code change to protected review output
                </h2>
                <p className="mt-4 max-w-md text-sm leading-7 text-neutral-400">
                  Instead of long security prose, this page explains the review system as a sequence: how findings are produced, what data is handled, and where the controls apply.
                </p>
              </div>

              <div className="relative">
                <div className="absolute left-[19px] top-6 bottom-6 hidden w-px bg-neutral-800 md:block" />
                <div className="space-y-6">
                  {timeline.map((item) => {
                    const Icon = item.icon
                    const accent = accentClasses[item.accent]

                    return (
                      <div key={item.step} className="relative md:pl-14">
                        <div className={`absolute left-0 top-5 hidden h-10 w-10 items-center justify-center rounded-full border border-neutral-950 md:flex ${accent.dot}`}>
                          <span className="text-sm font-bold text-neutral-950">{item.step}</span>
                        </div>

                        <div className={`rounded-3xl border bg-neutral-900/92 p-6 shadow-[0_18px_60px_rgba(0,0,0,0.28)] ${accent.card}`}>
                          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                            <div className="space-y-3">
                              <div className="flex flex-wrap items-center gap-3">
                                <div className={`flex h-11 w-11 items-center justify-center rounded-2xl border border-white/5 bg-neutral-950 ${accent.icon}`}>
                                  <Icon className="h-5 w-5" />
                                </div>
                                <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] ${accent.chip}`}>
                                  Step {item.step}
                                </span>
                                <StatusBadge status={item.step === '03' ? 'live' : 'live'} />
                              </div>
                              <div>
                                <h3 className="text-2xl font-semibold text-white">{item.title}</h3>
                                <p className="mt-3 max-w-2xl text-sm leading-7 text-neutral-300">{item.summary}</p>
                              </div>
                            </div>
                          </div>

                          <div className="mt-6 grid gap-3 sm:grid-cols-1">
                            {item.bullets.map((bullet) => (
                              <div key={bullet} className="rounded-2xl border border-neutral-800 bg-neutral-950/95 px-4 py-4 text-sm leading-7 text-neutral-300">
                                {bullet}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          </div>
        </section>

        <ProductSurface
          eyebrow="Security posture"
          title="What the trust story should make explicit"
          intro="Security pages should not sound like policy filler. They should explain what is already running, what is being extended, and how user data stays within clear product boundaries."
          items={trustSurface}
        />

        <section className="border-t border-neutral-800/60 py-16">
          <div className="mx-auto max-w-3xl px-4 text-center sm:px-6 lg:px-8">
            <div className="rounded-3xl border border-neutral-800 bg-neutral-900/95 px-8 py-10 shadow-[0_24px_80px_rgba(0,0,0,0.28)]">
              <h2 className="text-2xl font-semibold tracking-tight text-white">
                See the review workflow in action
              </h2>
              <p className="mt-3 text-sm leading-7 text-neutral-400">
                The examples page shows how findings move from pull request analysis into GitHub-native review output.
              </p>
              <div className="mt-6 flex justify-center">
                {user ? (
                  <Link
                    to="/dashboard"
                    className="rounded-lg bg-white px-6 py-2.5 text-sm font-semibold text-neutral-950 shadow-sm transition hover:bg-neutral-200"
                  >
                    Open workspace
                  </Link>
                ) : (
                  <button
                    onClick={loginWithGitHub}
                    className="rounded-lg bg-white px-6 py-2.5 text-sm font-semibold text-neutral-950 shadow-sm transition hover:bg-neutral-200"
                  >
                    Get started
                  </button>
                )}
              </div>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  )
}
