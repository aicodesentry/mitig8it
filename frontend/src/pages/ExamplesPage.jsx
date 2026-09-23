import { useAuth } from '../contexts/AuthContext'
import Header from '../components/Header'
import Footer from '../components/Footer'
import CtaPair from '../components/CtaPair'
import ProductSurface from '../components/ProductSurface'
import PullRequestReviewPreview from '../components/PullRequestReviewPreview'

const REVIEW_SCREENSHOT_PATH = '/proof/github-pr-xss-review.png?v=2'

const capabilities = [
  {
    title: 'Inline findings',
    status: 'live',
    description: 'Anchored to the changed line that introduced the risk.',
  },
  {
    title: 'Severity and confidence',
    status: 'live',
    description: 'Severity, confidence and CWE stay attached.',
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
]

const sectionHeading = 'text-2xl font-semibold tracking-tight text-white sm:text-3xl'

export default function ExamplesPage() {
  const { loginWithGitHub, user } = useAuth()

  return (
    <div className="min-h-screen bg-neutral-950 text-white">
      <Header />

      <main>
        {/* Hero */}
        <section className="mx-auto max-w-6xl px-4 pt-20 sm:px-6 sm:pt-24 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <h1 className="text-balance text-4xl font-bold leading-[1.05] tracking-tight text-white sm:text-5xl">
              A sample review
            </h1>
            <p className="mx-auto mt-6 max-w-xl text-base leading-7 text-neutral-400">
              What a pull request looks like after Mitig8it has reviewed it.
            </p>
          </div>
        </section>

        {/* The review itself */}
        <section className="mx-auto max-w-6xl px-4 pt-12 sm:px-6 sm:pt-14 lg:px-8">
          <PullRequestReviewPreview />
        </section>

        {/* The same thing, on a real pull request */}
        <section className="mx-auto max-w-6xl px-4 pt-12 sm:px-6 sm:pt-14 lg:px-8">
          <figure className="m-0">
            <div className="overflow-hidden rounded-xl border border-neutral-800">
              <img
                src={REVIEW_SCREENSHOT_PATH}
                alt="A Mitig8it review comment on a GitHub pull request"
                className="block w-full"
                loading="lazy"
              />
            </div>
            <figcaption className="mt-4 text-center text-sm text-neutral-500">
              A real finding on the pull request that introduced it.
            </figcaption>
          </figure>
        </section>

        {/* Capabilities */}
        <div className="mt-16 sm:mt-20">
          <ProductSurface title="In every review" items={capabilities} />
        </div>

        {/* Close */}
        <section className="mx-auto max-w-6xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8">
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
