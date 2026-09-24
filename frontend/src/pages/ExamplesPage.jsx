import { Link } from 'react-router'
import Header from '../components/Header'
import Footer from '../components/Footer'
import { useAuth } from '../contexts/AuthContext'
import ProductSurface from '../components/ProductSurface'
import StatusBadge from '../components/StatusBadge'

const REVIEW_SCREENSHOT_PATH = '/proof/github-pr-xss-review.png?v=2'

const mobileCallouts = [
  {
    id: 'flagged',
    number: '1',
    title: 'Flagged code',
    status: 'live',
    body: 'Mitig8it anchors the review to the exact changed lines that introduced the risk.',
  },
  {
    id: 'confidence',
    number: '2',
    title: 'CWE + confidence',
    status: 'live',
    body: 'The review shows what the issue is and how confident the detection is.',
  },
  {
    id: 'fix',
    number: '3',
    title: 'Verified fix',
    status: 'live',
    body: 'The fix is proven by a generated regression test, then posted as a one-click suggestion.',
  },
]

const exampleSurface = [
  {
    title: 'Flagged code in the diff',
    status: 'live',
    description: 'The finding is anchored to the exact lines reviewers are already discussing in the pull request.',
  },
  {
    title: 'CWE + confidence',
    status: 'live',
    description: 'Mitig8it keeps taxonomy and confidence attached so reviewers can judge signal quickly.',
  },
  {
    title: 'Verified fixes',
    status: 'live',
    description: 'Each fix is proven by a generated regression test before it is posted.',
  },
  {
    title: 'One-click apply',
    status: 'live',
    description: "GitHub's Commit suggestion button, under your identity.",
  },
]

export default function ExamplesPage() {
  const { loginWithGitHub, user } = useAuth()

  return (
    <div className="min-h-screen bg-neutral-950 text-white">
      <Header />

      <main>
        <section className="border-b border-neutral-800/60">
          <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 lg:px-8 lg:py-14">
            <div className="max-w-3xl">
              <p className="text-xs font-semibold uppercase tracking-[0.26em] text-neutral-500">
                Examples
              </p>
              <h1 className="mt-3 text-4xl font-semibold tracking-tight text-white sm:text-5xl">
                What Mitig8it writes in GitHub
              </h1>
              <p className="mt-4 max-w-2xl text-base leading-7 text-neutral-350 text-neutral-400">
                A real pull request review, annotated so teams can see what is live today and what is still being added to the workflow.
              </p>
            </div>

            <div className="mt-8 rounded-[28px] border border-neutral-800 bg-neutral-900/92 p-5 shadow-[0_24px_80px_rgba(0,0,0,0.32)] lg:p-6">
              <div className="flex items-center justify-between border-b border-neutral-800 pb-4">
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-neutral-500">
                    Actual GitHub review output
                  </p>
                  <h2 className="mt-2 text-xl font-semibold text-white">
                    High-severity pull request finding
                  </h2>
                </div>
                <span className="rounded-full border border-red-400/30 bg-red-400/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-red-200">
                  Vulnerability review
                </span>
              </div>

              <div className="mt-5 hidden overflow-visible lg:block">
                <div className="relative mx-auto w-[760px] overflow-visible">
                  <div className="overflow-hidden rounded-2xl border border-neutral-800">
                    <img
                      src={REVIEW_SCREENSHOT_PATH}
                      alt="Mitig8it GitHub pull request review showing a high-severity XSS finding"
                      className="block w-full"
                      loading="eager"
                    />
                  </div>

                  <div className="pointer-events-none absolute inset-x-0 top-[8.7%] h-[18.3%] border-y border-red-400/45 bg-red-500/22" />

                  <svg
                    className="pointer-events-none absolute inset-0 overflow-visible"
                    viewBox="0 0 760 543"
                    fill="none"
                  >
                    <circle cx="104" cy="102" r="5" fill="#86efac" stroke="#0a0a0a" strokeWidth="2" />
                    <path d="M-12 102 H96" stroke="#86efac" strokeWidth="2" />

                    <circle cx="430" cy="258" r="5" fill="#86efac" stroke="#0a0a0a" strokeWidth="2" />
                    <path d="M438 258 H812" stroke="#86efac" strokeWidth="2" />

                    <circle cx="518" cy="354" r="5" fill="#fcd34d" stroke="#0a0a0a" strokeWidth="2" />
                    <path d="M526 354 H678 V409 H730" stroke="#fcd34d" strokeWidth="2" />
                  </svg>

                  <div className="absolute -left-[220px] top-[54px] w-52 rounded-3xl border border-emerald-400/30 bg-neutral-950 px-4 py-4 shadow-[0_18px_42px_rgba(0,0,0,0.38)]">
                    <div className="flex items-center gap-2">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-300 text-sm font-bold text-neutral-950">
                        1
                      </div>
                      <div>
                        <p className="text-base font-semibold text-white">Flagged code</p>
                        <StatusBadge status="live" className="mt-1" />
                      </div>
                    </div>
                    <p className="mt-3 text-sm leading-6 text-neutral-300">
                      Mitig8it points reviewers to the exact changed lines that introduced the risk.
                    </p>
                  </div>

                  <div className="absolute -right-[244px] top-[226px] w-56 rounded-3xl border border-emerald-400/30 bg-neutral-950 px-4 py-4 shadow-[0_18px_42px_rgba(0,0,0,0.38)]">
                    <div className="flex items-center gap-2">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-300 text-sm font-bold text-neutral-950">
                        2
                      </div>
                      <div>
                        <p className="text-base font-semibold text-white">CWE + confidence</p>
                        <StatusBadge status="live" className="mt-1" />
                      </div>
                    </div>
                    <p className="mt-3 text-sm leading-6 text-neutral-300">
                      The review shows what the issue is and how confident the detection is.
                    </p>
                  </div>

                  <div className="absolute -right-[178px] top-[360px] w-52 rounded-3xl border border-amber-400/30 bg-neutral-950 px-4 py-4 shadow-[0_18px_42px_rgba(0,0,0,0.38)]">
                    <div className="flex items-center gap-2">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-amber-300 text-sm font-bold text-neutral-950">
                        3
                      </div>
                      <div>
                        <p className="text-base font-semibold text-white">Recommended fix</p>
                        <StatusBadge status="progress" className="mt-1" />
                      </div>
                    </div>
                    <p className="mt-3 text-sm leading-6 text-neutral-300">
                      Coming soon: suggested remediation and one-click fix flows that help engineers act faster.
                    </p>
                  </div>
                </div>
              </div>

              <div className="mt-5 space-y-4 lg:hidden">
                <div className="relative overflow-hidden rounded-2xl border border-neutral-800">
                  <img
                    src={REVIEW_SCREENSHOT_PATH}
                    alt="Mitig8it GitHub pull request review showing a high-severity XSS finding"
                    className="block w-full"
                    loading="eager"
                  />
                  <div className="pointer-events-none absolute inset-x-0 top-[8.7%] h-[18.3%] border-y border-red-400/45 bg-red-500/22" />
                </div>

                <div className="grid gap-3">
                  {mobileCallouts.map((callout) => (
                    <div key={callout.id} className="rounded-2xl border border-neutral-800 bg-neutral-950 px-4 py-4">
                      <div className="flex items-center gap-2">
                        <div className={`flex h-8 w-8 items-center justify-center rounded-full text-sm font-bold text-neutral-950 ${callout.id === 'fix' ? 'bg-amber-300' : 'bg-emerald-300'}`}>
                          {callout.number}
                        </div>
                        <div>
                          <p className="text-sm font-semibold text-white">{callout.title}</p>
                          <StatusBadge status={callout.status} className="mt-1" />
                        </div>
                      </div>
                      <p className="mt-2 text-sm leading-6 text-neutral-400">{callout.body}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        <ProductSurface
          eyebrow="Capability map"
          title="The sample review should make the product boundary obvious"
          intro="Prospective teams should be able to tell which parts of the review already exist and which ones are still being built, without guessing from marketing copy."
          items={exampleSurface}
        />

        <section className="py-16">
          <div className="mx-auto max-w-3xl px-4 text-center sm:px-6 lg:px-8">
            <div className="rounded-3xl border border-neutral-800 bg-neutral-900/95 px-8 py-10 shadow-[0_24px_80px_rgba(0,0,0,0.28)]">
              <h2 className="text-2xl font-semibold tracking-tight text-white">
                Try the same flow in your own repository
              </h2>
              <p className="mt-3 text-sm leading-7 text-neutral-400">
                Install the app on one repository, open a test pull request, and compare the output against this example.
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
