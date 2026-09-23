import { Link } from 'react-router'
import { GitPullRequest, ShieldCheck, Workflow } from 'lucide-react'
import Header from '../components/Header'
import Footer from '../components/Footer'
import ProductSurface from '../components/ProductSurface'

const roadmapSurface = [
  {
    title: 'PR review comments',
    status: 'live',
    description: 'Mitig8it already operates where engineers review code: inside the pull request.',
  },
  {
    title: 'Dashboard and reports',
    status: 'live',
    description: 'Run history and review visibility already exist as part of the current product surface.',
  },
  {
    title: 'Verified fixes',
    status: 'live',
    description: 'Each fix is proven by a generated regression test before it is posted.',
  },
  {
    title: 'One-click apply',
    status: 'live',
    description: 'Fixes arrive as GitHub suggestions. Applying and merging stay human actions.',
  },
]

const principles = [
  {
    icon: GitPullRequest,
    title: 'Start in the pull request',
    description: 'Mitig8it is built around the idea that security review should happen where engineers already review code, not in a separate console after the fact.',
  },
  {
    icon: ShieldCheck,
    title: 'Stay high-signal',
    description: 'The product is designed to focus on exploitable issues and reduce noise before findings ever reach the reviewer.',
  },
  {
    icon: Workflow,
    title: 'Keep developers in control',
    description: 'Mitig8it should help teams move faster and merge safer code without taking control away from the engineer.',
  },
]

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-neutral-950 text-white">
      <Header />

      <main>
        <section className="border-b border-neutral-800/60">
          <div className="mx-auto max-w-5xl px-4 py-16 sm:px-6 lg:px-8 lg:py-20">
            <p className="text-xs font-semibold uppercase tracking-[0.28em] text-neutral-500">
              About
            </p>
            <h1 className="mt-4 max-w-4xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              Mitig8it is building a security collaborator for code review.
            </h1>
            <p className="mt-6 max-w-3xl text-base leading-8 text-neutral-300">
              The thesis is simple: real security review should happen inside the pull request, while context is still fresh and engineers can act before merge.
            </p>
          </div>
        </section>

        <section className="border-b border-neutral-800/60 bg-neutral-900/35 py-16">
          <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <p className="text-xs font-semibold uppercase tracking-[0.28em] text-neutral-500">
                Why it exists
              </p>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight text-white">
                Security tools are often too late or too noisy
              </h2>
              <div className="mt-6 space-y-4 text-sm leading-8 text-neutral-300">
                <p>
                  Many security tools surface results after merge, in separate dashboards, or in forms that force developers to context-switch. That makes the feedback slower, harder to trust, and easier to ignore.
                </p>
                <p>
                  Mitig8it is being built to close that gap by reviewing pull requests directly in GitHub and returning output that is specific enough to act on during normal code review.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="border-b border-neutral-800/60 py-16">
          <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <p className="text-xs font-semibold uppercase tracking-[0.28em] text-neutral-500">
                What makes it different
              </p>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight text-white">
                Product principles behind the workflow
              </h2>
            </div>

            <div className="mt-8 grid gap-4 md:grid-cols-3">
              {principles.map((item) => {
                const Icon = item.icon
                return (
                  <div key={item.title} className="rounded-3xl border border-neutral-800 bg-neutral-900/95 p-6 shadow-[0_16px_40px_rgba(0,0,0,0.2)]">
                    <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-neutral-950 text-neutral-200">
                      <Icon className="h-5 w-5" />
                    </div>
                    <h3 className="mt-5 text-lg font-semibold text-white">{item.title}</h3>
                    <p className="mt-3 text-sm leading-7 text-neutral-400">{item.description}</p>
                  </div>
                )
              })}
            </div>
          </div>
        </section>

        <section className="border-b border-neutral-800/60 bg-neutral-900/35 py-16">
          <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <p className="text-xs font-semibold uppercase tracking-[0.28em] text-neutral-500">
                Today and next
              </p>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight text-white">
                Live now in pull requests, expanding over time
              </h2>
              <div className="mt-6 space-y-4 text-sm leading-8 text-neutral-300">
                <p>
                  Today, Mitig8it is focused on GitHub-native pull request review: inline findings, review summaries, and workflow visibility in the dashboard.
                </p>
                <p>
                  Over time, that foundation expands into richer remediation guidance, stronger repository context, and a more capable security collaborator that still keeps developers in control.
                </p>
              </div>
            </div>
          </div>
        </section>

        <ProductSurface
          eyebrow="What exists now"
          title="The company story should map cleanly to the product surface"
          intro="Mitig8it is not trying to sound finished where it is still evolving. The public product story is stronger when current capabilities and upcoming ones are separated clearly."
          items={roadmapSurface}
        />

        <section className="py-16">
          <div className="mx-auto max-w-3xl px-4 text-center sm:px-6 lg:px-8">
            <div className="rounded-3xl border border-neutral-800 bg-neutral-900/95 px-8 py-10 shadow-[0_24px_80px_rgba(0,0,0,0.28)]">
              <h2 className="text-2xl font-semibold tracking-tight text-white">
                See the product story in the workflow itself
              </h2>
              <p className="mx-auto mt-3 max-w-lg text-sm leading-7 text-neutral-400">
                The examples and homepage show how Mitig8it turns that thesis into actual pull request review output.
              </p>
              <div className="mt-6 flex flex-col justify-center gap-3 sm:flex-row">
                <Link
                  to="/examples"
                  className="inline-flex items-center justify-center rounded-lg bg-white px-6 py-2.5 text-sm font-semibold text-neutral-950 shadow-sm transition hover:bg-neutral-200"
                >
                  Open examples
                </Link>
                <Link
                  to="/"
                  className="inline-flex items-center justify-center rounded-lg border border-neutral-700 px-6 py-2.5 text-sm font-medium text-neutral-300 transition hover:border-neutral-500 hover:text-white"
                >
                  View homepage
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  )
}
