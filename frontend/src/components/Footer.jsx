import Logo from './Logo'

const Footer = ({ variant = 'landing' }) => {
  if (variant === 'dashboard') {
    return (
      <footer className="border-t border-neutral-200 dark:border-neutral-800 mt-8">
        <div className="px-8 py-4">
          <div className="flex flex-col md:flex-row justify-between items-center text-xs text-neutral-500 dark:text-neutral-400">
            <span>Mitig8it</span>
            <div className="flex gap-4 mt-2 md:mt-0">
              <a href="/privacy" className="hover:text-neutral-900 dark:hover:text-white transition-colors">Privacy</a>
              <a href="/terms" className="hover:text-neutral-900 dark:hover:text-white transition-colors">Terms</a>
            </div>
          </div>
        </div>
      </footer>
    )
  }

  return (
    <footer className="border-t border-white/5" role="contentinfo">
      <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="grid gap-10 md:grid-cols-[1.3fr_0.8fr_0.9fr]">
          <div>
            <Logo variant="dark" />
            <p className="mt-3 max-w-sm text-sm leading-7 text-neutral-500">
              Security findings with verified fixes, posted inside the pull request. Nothing merges without you.
            </p>
          </div>
          <div>
            <h4 className="mb-4 text-xs font-semibold uppercase tracking-[0.2em] text-neutral-400">Pages</h4>
            <ul className="space-y-3 text-sm text-neutral-500">
              <li><a href="/examples" className="transition-colors hover:text-white">Examples</a></li>
              <li><a href="/security" className="transition-colors hover:text-white">Security</a></li>
              <li><a href="/about" className="transition-colors hover:text-white">About</a></li>
              <li><a href="/benchmarks" className="transition-colors hover:text-white">Benchmarks</a></li>
            </ul>
          </div>
          <div>
            <h4 className="mb-4 text-xs font-semibold uppercase tracking-[0.2em] text-neutral-400">Connect</h4>
            <div className="mb-4 space-y-2 text-sm text-neutral-500">
              <p>support@mitig8it.com</p>
              <div className="flex flex-wrap gap-4 text-sm">
                <a href="/privacy" className="transition-colors hover:text-white">Privacy</a>
                <a href="/terms" className="transition-colors hover:text-white">Terms</a>
              </div>
            </div>
            <div className="flex gap-3">
              <a href="mailto:support@mitig8it.com" className="text-neutral-500 transition-colors hover:text-white" aria-label="Email">
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
                </svg>
              </a>
              <a href="https://github.com/apps/mitig8it" target="_blank" rel="noreferrer" className="text-neutral-500 transition-colors hover:text-white" aria-label="GitHub">
                <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                  <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                </svg>
              </a>
              <a href="https://www.linkedin.com/company/mitig8it" target="_blank" rel="noreferrer" className="text-neutral-500 transition-colors hover:text-white" aria-label="LinkedIn">
                <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
                </svg>
              </a>
            </div>
          </div>
        </div>

        <div className="mt-10 border-t border-white/5 pt-6 text-center text-xs text-neutral-600">
          &copy; {new Date().getFullYear()} Mitig8it. All rights reserved.
        </div>
      </div>
    </footer>
  )
}

export default Footer
