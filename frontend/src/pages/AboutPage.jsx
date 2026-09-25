import { GitPullRequest, Lock, ShieldCheck, Workflow } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import Header from '../components/Header'
import Footer from '../components/Footer'
import CtaPair from '../components/CtaPair'
import ProductSurface from '../components/ProductSurface'
import StatusBadge from '../components/StatusBadge'

const principles = [
  {
    icon: GitPullRequest,
    title: 'Start in the pull request',
    description: 'Findings land where code is already being reviewed.',
  },
  {
    icon: ShieldCheck,
    title: 'Fix, do not just flag',
    description: 'Every finding ships with a proven, one-click fix.',
  },
  {
    icon: Workflow,
    title: 'Keep developers in control',
    description: 'Nothing is applied or merged without a human.',
  },
]

const liveSurface = [
  {
    title: 'Inline findings',
    status: 'live',
    description: 'Severity, confidence, CWE on the changed line.',
  },
  {
    title: 'Verified fixes',
    status: 'live',
    description: 'Each fix proven by a generated regression test.',
  },
  {
    title: 'One-click apply',
    status: 'live',
    description: "GitHub's Commit suggestion button, under your identity.",
  },
  {
    title: 'Re-analysis after apply',
    status: 'live',
    description: 'Residual report posted when the fix lands.',
  },
]

const staged = ['More languages and rule families', 'Merge-when-ready (parked, human approval required)']

const sectionHeading = 'text-2xl font-semibold tracking-tight text-white sm:text-3xl'

export default function AboutPage() {
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
                Why Mitig8it exists
              </h1>
              <p className="mx-auto mt-6 max-w-xl text-base leading-7 text-neutral-400">
                Security review belongs in the pull request, with the fix attached.
              </p>
            </div>
          </div>
        </section>

        {/* Principles */}
        <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <div className="grid gap-8 sm:grid-cols-3 sm:gap-6">
            {principles.map(({ icon: Icon, title, description }) => (
              <div key={title}>
                <span className="flex h-10 w-10 items-center justify-center rounded-full border border-emerald-400/25 bg-emerald-400/10">
                  <Icon className="h-4 w-4 text-emerald-400" aria-hidden="true" />
                </span>
                <h2 className="mt-4 text-base font-semibold text-white">{title}</h2>
                <p className="mt-1 text-sm leading-6 text-neutral-400">{description}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Live today */}
        <ProductSurface
          title="Live today"
          items={liveSurface}
          footnote={{ icon: Lock, text: 'Nothing is applied or merged automatically.' }}
        />

        {/* Staged */}
        <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <h2 className={sectionHeading}>Staged</h2>

          <ul className="mt-8 grid gap-px overflow-hidden rounded-2xl border border-neutral-800 bg-neutral-800 sm:grid-cols-2">
            {staged.map((item) => (
              <li
                key={item}
                className="flex items-center justify-between gap-3 bg-neutral-950 px-5 py-4"
              >
                <span className="text-sm text-neutral-300">{item}</span>
                <StatusBadge status="progress" className="shrink-0" />
              </li>
            ))}
          </ul>
        </section>

        {/* Close */}
        <section className="mx-auto max-w-6xl px-4 pb-20 sm:px-6 sm:pb-24 lg:px-8">
          <div className="rounded-2xl border border-neutral-800 bg-neutral-900 px-6 py-14 text-center sm:px-16">
            <h2 className={sectionHeading}>Try it on one repository</h2>
            <div className="mt-8">
              <CtaPair user={user} onLogin={loginWithGitHub} />
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  )
}
