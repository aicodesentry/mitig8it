import { Link, useSearchParams } from 'react-router'
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
import CtaPair from './CtaPair'
import FixPipeline from './FixPipeline'
import ProductSurface from './ProductSurface'
import PullRequestReviewPreview from './PullRequestReviewPreview'

const heroBullets = [
  'High-confidence findings on the risky line',
  'Evidence-backed fixes when proof passes',
  'Explicit abstention when proof does not pass',
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

const liveSurface = [
  {
    title: 'Inline findings',
    status: 'live',
    description: 'Severity, confidence, CWE on the changed line.',
  },
  {
    title: 'Verified fixes',
    status: 'live',
    description: 'A fix is published only when its configured evidence policy passes.',
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

const trustItems = [
  { icon: FileDiff, text: 'Reads only the diff and the files it depends on' },
  { icon: KeyRound, text: 'Model calls see only the changed files and their dependents' },
  { icon: Braces, text: 'JavaScript and Python today; more families staged' },
]

const sectionHeading = 'text-2xl font-semibold tracking-tight text-white sm:text-3xl'

const HomePage = () => {
  const { loginWithGitHub, user } = useAuth()
  const [searchParams] = useSearchParams()
  const signInError = searchParams.get('error')

  return (
    <div className="min-h-screen bg-neutral-950 text-white">
      <Header />

      <main>
        {signInError && (
          <div className="mx-auto max-w-6xl px-4 pt-6 sm:px-6 lg:px-8">
            <div role="alert" className="rounded-lg border border-red-900 bg-red-950/60 px-4 py-3 text-sm text-red-200">
              Sign-in failed. GitHub returned: {signInError}. Try signing in again.
            </div>
          </div>
        )}

        {/* Hero */}
        <section className="relative overflow-hidden">
          <div className="pointer-events-none absolute inset-x-0 top-0 h-[420px] bg-[radial-gradient(ellipse_60%_100%_at_50%_0%,rgba(16,185,129,0.10),transparent_70%)]" />

          <div className="relative mx-auto max-w-6xl px-4 pt-20 sm:px-6 sm:pt-28 lg:px-8">
            <div className="mx-auto max-w-4xl text-center">
              <span className="inline-flex items-center gap-2 rounded-full border border-neutral-800 px-3 py-1 text-xs font-medium text-neutral-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                GitHub App · Security review with evidence-backed fixes
              </span>

              <h1 className="mt-6 text-balance text-4xl font-bold leading-[1.05] tracking-tight text-white sm:text-5xl lg:text-[3.5rem]">
                Findings that come with fixes.
                <span className="block text-neutral-500">Applied by you, in the PR.</span>
              </h1>

              <p className="mx-auto mt-6 max-w-xl text-base leading-7 text-neutral-400 sm:text-lg sm:leading-8">
                Mitig8it reviews changed code for high-confidence security issues. When it can prove
                a fix, it posts a one-click suggestion; otherwise it records why it abstained.
              </p>

              <div className="mt-8">
                <CtaPair user={user} onLogin={loginWithGitHub} />
              </div>

              <ul className="mt-8 flex flex-wrap justify-center gap-x-6 gap-y-3 text-sm text-neutral-400">
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
            <figcaption className="mt-4 text-center text-sm text-neutral-400">
              A representative review built from the same finding, suggestion, and evidence fields
              the GitHub integration publishes. See Examples for a captured pull request.
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
                <p className="mt-4 font-mono text-xs text-neutral-400">{number}</p>
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

            <FixPipeline className="mt-10" />
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
