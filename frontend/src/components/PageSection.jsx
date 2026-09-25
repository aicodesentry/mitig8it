import { cn } from '../lib/utils'

export const PageHeader = ({
  title,
  description,
  actions,
  className,
}) => (
  <div className={cn('flex items-center justify-between', className)}>
    <div>
      <h1 className="text-2xl font-semibold text-neutral-900 dark:text-white">{title}</h1>
      {description ? (
        <p className="text-sm text-neutral-500 dark:text-neutral-400">{description}</p>
      ) : null}
    </div>
    {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
  </div>
)

// `columns` lets a row of three tiles sit beside a row of four without either being
// stretched. `item.hint` is a one-line definition of the number, for a tile whose label
// alone does not say what was counted.
export const PageStats = ({ items, columns = 4 }) => (
  <div className={cn('grid grid-cols-2 gap-3', columns === 3 ? 'lg:grid-cols-3' : 'lg:grid-cols-4')}>
    {items.map((item) => (
      <div key={item.label} className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-neutral-100 dark:bg-neutral-800">
            {item.icon}
          </div>
          <div>
            <p className="text-2xl font-semibold text-neutral-900 dark:text-white">{item.value}</p>
            <p className="text-xs text-neutral-500 dark:text-neutral-400">{item.label}</p>
          </div>
        </div>
        {item.hint ? (
          <p className="mt-2 text-xs leading-snug text-neutral-400 dark:text-neutral-500">{item.hint}</p>
        ) : null}
      </div>
    ))}
  </div>
)

export const PagePanel = ({ title, action, className, children }) => (
  <div className={cn('', className)}>
    {(title || action) ? (
      <div className="mb-3 flex items-center justify-between">
        {title ? <h2 className="text-lg font-semibold text-neutral-900 dark:text-white">{title}</h2> : null}
        {action || null}
      </div>
    ) : null}
    {children}
  </div>
)

export const EmptyPanel = ({ title, description, action, className }) => (
  <div
    className={cn(
      'rounded-xl border border-dashed border-neutral-200 px-6 py-12 text-center dark:border-neutral-800',
      className
    )}
  >
    <h3 className="text-sm font-medium text-neutral-900 dark:text-white">{title}</h3>
    <p className="mx-auto mt-1 max-w-xl text-sm text-neutral-500 dark:text-neutral-400">{description}</p>
    {action ? <div className="mt-4 flex justify-center">{action}</div> : null}
  </div>
)
