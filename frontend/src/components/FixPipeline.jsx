/*
 * The five nodes a fix passes through before it is published. Shared by the
 * homepage and the security page so both describe the same pipeline.
 */
const pipeline = [
  { node: 'Detect', label: 'Rules, AST scan, model triage' },
  { node: 'Generate', label: 'Template first, model when needed' },
  { node: 'Prove', label: 'Regression test in a sandbox' },
  { node: 'Publish', label: 'Suggestion block under the finding' },
  { node: 'You apply', label: 'Commit it, merge stays yours' },
]

export default function FixPipeline({ className = '' }) {
  return (
    <ol className={`relative grid gap-8 sm:grid-cols-5 sm:gap-4 ${className}`.trim()}>
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
  )
}
