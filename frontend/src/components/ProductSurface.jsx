import StatusBadge from './StatusBadge'

/*
 * A compact status grid. `intro` and `footnote` are optional so the marketing
 * pages can stay wordier than the homepage, which runs title plus tiles only.
 */
export default function ProductSurface({ title, intro, items, footnote }) {
  const FootnoteIcon = footnote?.icon

  return (
    <section className="border-y border-neutral-800 bg-neutral-900/30">
      <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
        <h2 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">{title}</h2>
        {intro ? <p className="mt-3 max-w-2xl text-base leading-7 text-neutral-400">{intro}</p> : null}

        <div className="mt-8 grid gap-px overflow-hidden rounded-2xl border border-neutral-800 bg-neutral-800 sm:grid-cols-2">
          {items.map((item) => (
            <div key={item.title} className="bg-neutral-950 p-5">
              <div className="flex items-start justify-between gap-3">
                <h3 className="text-base font-semibold text-white">{item.title}</h3>
                <StatusBadge status={item.status} className="shrink-0" />
              </div>
              <p className="mt-2 text-sm leading-6 text-neutral-400">{item.description}</p>
            </div>
          ))}

          {footnote ? (
            <div className="flex items-center gap-3 bg-neutral-950 px-5 py-4 sm:col-span-2">
              {FootnoteIcon ? (
                <FootnoteIcon className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
              ) : null}
              <p className="text-sm text-neutral-300">{footnote.text}</p>
            </div>
          ) : null}
        </div>
      </div>
    </section>
  )
}
