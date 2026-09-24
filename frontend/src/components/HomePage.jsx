import { Link } from 'react-router'
import {
  ArrowRight,
  Braces,
  Check,
  Download,
  FileDiff,
  GitPullRequest,
  KeyRound,
  Lock,
  MousePointerClick,
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import Header from './Header'
import Footer from './Footer'
import ProductSurface from './ProductSurface'
import PullRequestReviewPreview from './PullRequestReviewPreview'

const GitHubIcon = () => (
  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
    <path
      fillRule="evenodd"
      d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
      clipRule="evenodd"
    />
  </svg>
)

const primaryAction =
  'inline-flex items-center justify-center gap-2 rounded-lg bg-white px-5 py-2.5 text-sm font-semibold text-neutral-950 transition hover:bg-neutral-200'
const secondaryAction =
  'inline-flex items-center justify-center gap-2 rounded-lg border border-neutral-800 px-5 py-2.5 text-sm font-medium text-neutral-300 transition hover:border-neutral-600 hover:text-white'

const CtaPair = ({ user, onLogin }) => (
  <div className="flex flex-col justify-center gap-3 sm:flex-row">
    {user ? (
      <Link to="/dashboard" className={primaryAction}>
        Open workspace
        <ArrowRight className="h-4 w-4" />
      </Link>
    ) : (
      <button onClick={onLogin} className={primaryAction}>
        <GitHubIcon />
        Start with GitHub
      </button>
    )}
    <Link to="/examples" className={secondaryAction}>
      See sample review
    </Link>
  </div>
)

const heroBullets = [
  'Inline on the risky line',
  'Fix proven by a regression test',
  'Nothing merges without you',
]

const steps = [
  {
    number: '01',
    icon: Download,
    title: 'Install the GitHub App',
    line: 'Connect one repo, or run it as a GitHub Action in your own CI; nothing leaves your runner.',
  },
  {
    number: '02',
    icon: GitPullRequest,
    title: 'Open a pull request',
    line: 'Findings land inline on the lines that introduced them.',
  },
  {
    number: '03',
    icon: MousePointerClick,
    title: 'Apply the verified fix',
    line: 'One click on the suggestion. You stay in control of merge.',
  },
]

const pipeline = [
  { node: 'Detect', label: 'Rules, AST scan, model triage' },
  { node: 'Generate', label: 'Template first, model when needed' },
  { node: 'Prove', label: 'Regression test in a sandbox' },
  { node: 'Publish', label: 'Suggestion block under the finding' },
  { node: 'You apply', label: 'Commit it, merge stays yours' },
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
    description: 'GitHub suggestion or per-finding Apply in the workspace.',
  },
  {
    title: 'Re-analysis after apply',
    status: 'live',
    description: 'Residual report posted when the fix lands.',
  },
]

const trustItems = [
  { icon: FileDiff, text: 'Reads only the diff and the files it depends on' },
  { icon: KeyRound, text: 'Secrets redacted before any model call' },
  { icon: Braces, text: 'JavaScript and Python today; more families staged' },
]

const sectionHeading = 'text-2xl font-semibold tracking-tight text-white sm:text-3xl'

const HomePage = () => {
  const { loginWithGitHub, user } = useAuth()

  return (
    <div className="min-h-screen bg-neutral-950 text-white">
      <Header />

      <main>
        {/* Hero */}
        <section className="relative overflow-hidden">
          <div className="pointer-events-none absolute inset-x-0 top-0 h-[420px] bg-[radial-gradient(ellipse_60%_100%_at_50%_0%,rgba(16,185,129,0.10),transparent_70%)]" />

          <div className="relative mx-auto max-w-6xl px-4 pt-20 sm:px-6 sm:pt-28 lg:px-8">
            <div className="mx-auto max-w-4xl text-center">
              <span className="inline-flex items-center gap-2 rounded-full border border-neutral-800 px-3 py-1 text-xs font-medium text-neutral-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                GitHub App · Security review with verified fixes
              </span>

              <h1 className="mt-6 text-balance text-4xl font-bold leading-[1.05] tracking-tight text-white sm:text-5xl lg:text-[3.5rem]">
                Findings that come with fixes.
                <span className="block text-neutral-500">Applied by you, in the PR.</span>
              </h1>

              <p className="mx-auto mt-6 max-w-xl text-base leading-7 text-neutral-400 sm:text-lg sm:leading-8">
                Mitig8it finds exploitable code in every pull request, proves a fix, and posts it as
                a one-click suggestion.
              </p>

              <div className="mt-8">
                <CtaPair user={user} onLogin={loginWithGitHub} />
              </div>

              <ul className="mt-8 flex flex-wrap justify-center gap-x-6 gap-y-3 text-sm text-neutral-500">
                {heroBullets.map((item) => (
                  <li key={item} className="inline-flex items-center gap-2">
                    <Check className="h-4 w-4 text-emerald-400" aria-hidden="true" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>

        {/* The product itself */}
        <section className="mx-auto max-w-6xl px-4 pt-14 sm:px-6 sm:pt-16 lg:px-8">
          <figure className="m-0">
            <PullRequestReviewPreview />
            <figcaption className="mt-4 text-center text-sm text-neutral-500">
              Mirrors a real review on a test pull request. Nothing here is mocked up beyond the
              layout.
            </figcaption>
          </figure>
        </section>

        {/* Three steps */}
        <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <h2 className={sectionHeading}>Three steps</h2>

          <div className="mt-8 grid gap-8 sm:grid-cols-3 sm:gap-6">
            {steps.map(({ number, icon: Icon, title, line }) => (
              <div key={number}>
                <span className="flex h-10 w-10 items-center justify-center rounded-full border border-emerald-400/25 bg-emerald-400/10">
                  <Icon className="h-4 w-4 text-emerald-400" aria-hidden="true" />
                </span>
                <p className="mt-4 font-mono text-xs text-neutral-600">{number}</p>
                <h3 className="mt-1 text-base font-semibold text-white">{title}</h3>
                <p className="mt-1 text-sm leading-6 text-neutral-400">{line}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Pipeline */}
        <section className="border-t border-neutral-800">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
            <h2 className={sectionHeading}>How a fix earns its place</h2>

            <ol className="relative mt-10 grid gap-8 sm:grid-cols-5 sm:gap-4">
              <span
                className="pointer-events-none absolute left-[11px] top-3 bottom-3 w-px bg-neutral-800 sm:hidden"
                aria-hidden="true"
              />
              <span
                className="pointer-events-none absolute left-[10%] right-[10%] top-3 hidden h-px bg-neutral-800 sm:block"
                aria-hidden="true"
              />

              {pipeline.map((item, index) => (
                <li
                  key={item.node}
                  className="relative flex gap-4 sm:flex-col sm:items-center sm:gap-0 sm:text-center"
                >
                  <span
                    className={`relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border bg-neutral-950 ${
                      index === pipeline.length - 1
                        ? 'border-emerald-400 bg-emerald-400/15'
                        : 'border-emerald-400/40'
                    }`}
                    aria-hidden="true"
                  >
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                  </span>
                  <div className="min-w-0 sm:mt-4">
                    <p className="text-sm font-semibold text-white">{item.node}</p>
                    <p className="mt-1 text-sm leading-6 text-neutral-500">{item.label}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* Live today */}
        <ProductSurface
          title="Live today"
          items={liveSurface}
          footnote={{ icon: Lock, text: 'Nothing is applied or merged automatically.' }}
        />

        {/* Trust */}
        <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <h2 className={sectionHeading}>Built to be trusted</h2>

          <div className="mt-8 grid gap-6 sm:grid-cols-3">
            {trustItems.map(({ icon: Icon, text }) => (
              <div key={text} className="flex items-start gap-3">
                <Icon className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
                <p className="text-sm leading-6 text-neutral-400">{text}</p>
              </div>
            ))}
          </div>

          <Link
            to="/security"
            className="mt-8 inline-flex items-center gap-2 text-sm font-medium text-emerald-400 transition hover:text-emerald-300"
          >
            Read the security page
            <ArrowRight className="h-4 w-4" />
          </Link>
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

export default HomePage
