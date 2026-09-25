import { useEffect, useState } from 'react'
import { Check } from 'lucide-react'

/*
 * A faithful, static reproduction of what Mitig8it posts on a pull request:
 * the changed line, the finding, the proven fix as a GitHub suggestion block.
 * Colours are GitHub's dark canvas values so the surface reads as GitHub, not
 * as marketing chrome.
 */
const GH = {
  canvas: '#0d1117',
  raised: '#161b22',
  border: '#30363d',
  text: '#c9d1d9',
  muted: '#8b949e',
  removedBg: 'rgba(248,81,73,0.15)',
  removedMark: '#f85149',
  addedBg: 'rgba(63,185,80,0.15)',
  addedMark: '#3fb950',
  commit: '#238636',
}

const RISKY_LINE = `const result = await pool.query("SELECT id, status, total FROM orders WHERE id = '" + req.params.id + "'");`
const FIXED_LINE =
  "const result = await pool.query('SELECT id, status, total FROM orders WHERE id = $1', [req.params.id]);"

const CONTEXT_LINES = [
  { number: 41, marker: ' ', text: "app.get('/orders/:id', async (req, res) => {" },
  { number: 42, marker: ' ', text: '  const pool = getPool();' },
  { number: 43, marker: '+', text: `  ${RISKY_LINE}` },
]

/* diff -> finding -> suggestion -> verified + actions */
const STEP_COUNT = 4
const STEP_DELAY_MS = 400

const codeStyle = {
  fontFamily: 'var(--font-mono, ui-monospace, "SF Mono", Menlo, Consolas, monospace)',
}

const prefersReducedMotion = () => {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  } catch {
    return false
  }
}

const revealStyle = (shown) => ({
  opacity: shown ? 1 : 0,
  transform: shown ? 'translateY(0)' : 'translateY(8px)',
  transition: 'opacity 380ms ease, transform 380ms ease',
})

const DiffRow = ({ number, marker, text }) => {
  const added = marker === '+'
  const removed = marker === '-'
  const background = added ? GH.addedBg : removed ? GH.removedBg : 'transparent'
  const markColor = added ? GH.addedMark : removed ? GH.removedMark : GH.muted

  return (
    <div className="flex items-start" style={{ background }}>
      <span
        className="shrink-0 select-none px-3 py-1 text-right text-[11px] leading-5 tabular-nums"
        style={{ ...codeStyle, color: GH.muted, minWidth: '3.25rem' }}
      >
        {number}
      </span>
      <span
        className="shrink-0 select-none py-1 pr-1 text-[12px] leading-5"
        style={{ ...codeStyle, color: markColor }}
      >
        {marker}
      </span>
      <pre
        className="min-w-0 flex-1 overflow-x-auto py-1 pr-3 text-[12px] leading-5"
        style={{ ...codeStyle, color: GH.text, margin: 0 }}
      >
        <code>{text}</code>
      </pre>
    </div>
  )
}

const SuggestionRow = ({ marker, text }) => {
  const added = marker === '+'
  return (
    <div
      className="flex items-start"
      style={{ background: added ? GH.addedBg : GH.removedBg }}
    >
      <span
        className="shrink-0 select-none py-1 pl-3 pr-2 text-[12px] leading-5"
        style={{ ...codeStyle, color: added ? GH.addedMark : GH.removedMark }}
      >
        {marker}
      </span>
      <pre
        className="min-w-0 flex-1 overflow-x-auto py-1 pr-3 text-[12px] leading-5"
        style={{ ...codeStyle, color: GH.text, margin: 0 }}
      >
        <code>{text}</code>
      </pre>
    </div>
  )
}

export default function PullRequestReviewPreview({ animate = true }) {
  const [step, setStep] = useState(() => (animate ? 0 : STEP_COUNT))

  useEffect(() => {
    if (!animate || prefersReducedMotion()) {
      setStep(STEP_COUNT)
      return undefined
    }

    setStep(0)
    const timers = []
    for (let index = 1; index <= STEP_COUNT; index += 1) {
      timers.push(window.setTimeout(() => setStep(index), index * STEP_DELAY_MS))
    }

    return () => {
      timers.forEach((timer) => window.clearTimeout(timer))
    }
  }, [animate])

  return (
    <div
      className="overflow-hidden rounded-xl border"
      style={{ background: GH.canvas, borderColor: GH.border }}
    >
      {/* File header */}
      <div
        className="flex items-center gap-2 border-b px-3 py-2 sm:px-4"
        style={{ background: GH.raised, borderColor: GH.border }}
      >
        <span className="text-[12px]" style={{ ...codeStyle, color: GH.text }}>
          services/orders.js
        </span>
      </div>

      {/* Diff */}
      <div style={revealStyle(step >= 1)}>
        {CONTEXT_LINES.map((line) => (
          <DiffRow key={line.number} {...line} />
        ))}
      </div>

      {/* Finding comment from the bot */}
      <div
        className="border-t px-3 py-4 sm:px-4"
        style={{ ...revealStyle(step >= 2), borderColor: GH.border }}
      >
        <div className="flex items-center gap-2">
          <span
            className="inline-block h-5 w-5 shrink-0 rounded-full"
            style={{ background: GH.addedMark }}
            aria-hidden="true"
          />
          <span className="text-[13px] font-semibold" style={{ color: GH.text }}>
            mitig8it[bot]
          </span>
        </div>

        <p className="mt-3 text-[13px] leading-5" style={{ color: GH.text }}>
          <span className="font-semibold" style={{ color: GH.removedMark }}>
            HIGH
          </span>
          <span style={{ color: GH.muted }}> · </span>
          Potential SQL injection via string concatenation
        </p>
        <p className="mt-1 text-[11px]" style={{ ...codeStyle, color: GH.muted }}>
          CWE-89 · Confidence 90%
        </p>

        {/* Suggestion block */}
        <div
          className="mt-4 overflow-hidden rounded-md border"
          style={{ ...revealStyle(step >= 3), borderColor: GH.border }}
        >
          <div
            className="border-b px-3 py-1.5 text-[12px] font-semibold"
            style={{ background: GH.raised, borderColor: GH.border, color: GH.text }}
          >
            Suggested change
          </div>
          <SuggestionRow marker="-" text={RISKY_LINE} />
          <SuggestionRow marker="+" text={FIXED_LINE} />
        </div>

        {/* Verification and actions */}
        <div style={revealStyle(step >= 4)}>
          <p
            className="mt-3 flex items-start gap-2 text-[12px] leading-5"
            style={{ color: GH.muted }}
          >
            <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" aria-hidden="true" />
            <span>
              Verified: regression test failed on the original code and passed with this change.
            </span>
          </p>

          <div className="mt-4 flex flex-wrap items-center justify-end gap-2">
            <button
              type="button"
              className="inline-flex items-center rounded-md px-3 py-1.5 text-[12px] font-semibold text-white"
              style={{ background: GH.commit }}
            >
              Commit suggestion
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
