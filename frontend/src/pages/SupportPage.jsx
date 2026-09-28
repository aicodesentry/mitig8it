import { useState } from 'react'
import { HelpCircle, Mail, MessageSquare } from 'lucide-react'

const SupportPage = () => {
  const [formData, setFormData] = useState({ subject: '', message: '' })
  const [submitSuccess, setSubmitSuccess] = useState(false)

  const handleSubmit = (e) => {
    e.preventDefault()
    setSubmitSuccess(true)
    setFormData({ subject: '', message: '' })
    setTimeout(() => setSubmitSuccess(false), 5000)
  }

  const faqs = [
    {
      question: 'How do I connect a repository?',
      answer: 'Go to the Repositories page and click "Connect" next to any repo. Mitig8it will automatically start analyzing pull requests.'
    },
    {
      question: 'What languages are supported?',
      answer: 'Mitig8it analyzes pull request diffs for security vulnerabilities regardless of language or tech stack.'
    },
    {
      question: 'How does the analysis work?',
      answer: 'A 3-tier pipeline scans changed files: Tier 1 regex for fast pattern matching, Tier 2 OpenGrep for AST-level taint tracking, and Tier 3 LLM triage to filter false positives. Findings are cross-validated, mapped to CWE/OWASP/ATT&CK taxonomies, and posted as inline PR annotations with remediation guidance.'
    },
    {
      question: 'Can I customize the analysis rules?',
      answer: 'Custom rule support is on the roadmap. Today the review runs about 30 pattern rules and 177 AST rules, all written and measured in this repository, across Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#, template languages and GitHub Actions workflows.'
    },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold text-neutral-900 dark:text-white">Support</h1>
        <p className="text-sm text-neutral-500 dark:text-neutral-400">Get help and find answers to common questions</p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Contact Form */}
        <div className="rounded-xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="mb-4 flex items-center gap-2">
            <MessageSquare className="h-4 w-4 text-neutral-600 dark:text-neutral-300" />
            <h2 className="text-lg font-semibold text-neutral-900 dark:text-white">Contact support</h2>
          </div>

          {submitSuccess && (
            <div className="mb-4 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 dark:border-emerald-500/30 dark:bg-emerald-500/10">
              <p className="text-sm text-emerald-800 dark:text-emerald-400">Support request submitted. We&apos;ll get back to you soon.</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Subject</label>
              <input
                type="text"
                value={formData.subject}
                onChange={(e) => setFormData({ ...formData, subject: e.target.value })}
                className="w-full rounded-lg border border-neutral-200 bg-white px-4 py-2 text-sm text-neutral-900 focus:border-neutral-500 focus:outline-none dark:border-neutral-800 dark:bg-neutral-800 dark:text-white dark:focus:border-neutral-500"
                placeholder="Brief description of your issue"
                required
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Message</label>
              <textarea
                value={formData.message}
                onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                rows="5"
                className="w-full rounded-lg border border-neutral-200 bg-white px-4 py-2 text-sm text-neutral-900 focus:border-neutral-500 focus:outline-none dark:border-neutral-800 dark:bg-neutral-800 dark:text-white dark:focus:border-neutral-500"
                placeholder="Describe your issue in detail..."
                required
              />
            </div>
            <button
              type="submit"
              className="w-full rounded-lg bg-neutral-900 px-4 py-2 text-sm font-medium text-white hover:bg-neutral-800 dark:bg-white dark:text-neutral-900 dark:hover:bg-neutral-100"
            >
              Submit request
            </button>
          </form>
        </div>

        {/* Quick help */}
        <div className="space-y-4">
          <div className="rounded-xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-neutral-900">
            <div className="mb-4 flex items-center gap-2">
              <Mail className="h-4 w-4 text-neutral-600 dark:text-neutral-300" />
              <h2 className="text-lg font-semibold text-neutral-900 dark:text-white">Reach us directly</h2>
            </div>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Email us at{' '}
              <a href="mailto:support@mitig8it.com" className="font-medium text-neutral-900 dark:text-white hover:underline">
                support@mitig8it.com
              </a>
            </p>
          </div>

          <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-5 dark:border-neutral-700 dark:bg-neutral-800/50">
            <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-200">Beta feedback welcome</h3>
            <p className="mt-1 text-sm text-neutral-700 dark:text-neutral-400">
              Found a bug or have a feature request? We&apos;re actively building — your feedback shapes the product.
            </p>
          </div>
        </div>
      </div>

      {/* FAQs */}
      <div>
        <div className="mb-3 flex items-center gap-2">
          <HelpCircle className="h-4 w-4 text-neutral-600 dark:text-neutral-300" />
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-white">Frequently Asked Questions</h2>
        </div>
        <div className="divide-y divide-neutral-100 rounded-xl border border-neutral-200 bg-white dark:divide-neutral-800 dark:border-neutral-800 dark:bg-neutral-900">
          {faqs.map((faq, index) => (
            <div key={index} className="px-5 py-4">
              <h4 className="text-sm font-semibold text-neutral-900 dark:text-white">{faq.question}</h4>
              <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">{faq.answer}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default SupportPage
