const severityColors = {
  critical: { text: 'text-red-600 dark:text-red-400', bg: 'bg-red-500' },
  high: { text: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-500' },
  medium: { text: 'text-yellow-600 dark:text-yellow-400', bg: 'bg-amber-400' },
  low: { text: 'text-neutral-600 dark:text-neutral-400', bg: 'bg-neutral-400' },
  // Findings in test code: reported, never blocking.
  info: { text: 'text-neutral-500 dark:text-neutral-400', bg: 'bg-neutral-300' },
};

const PRAnalysisModal = ({ analysis, onClose }) => {
  if (!analysis) return null;

  const total = analysis.total_findings || 0;
  const counts = analysis.severity_counts || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const hasFindings = total > 0;
  const prUrl = analysis.pr_url || `https://github.com/${analysis.repository_name}/pull/${analysis.pr_number}`;

  const duration = analysis.started_at && analysis.completed_at
    ? Math.round((new Date(analysis.completed_at) - new Date(analysis.started_at)) / 1000)
    : null;

  return (
    <div className="fixed inset-0 bg-neutral-950/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-white dark:bg-neutral-900 rounded-xl max-w-lg w-full shadow-lg" onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="px-6 pt-5 pb-4">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-lg font-semibold text-neutral-900 dark:text-white">
                PR #{analysis.pr_number}
              </h2>
              <p className="text-sm text-neutral-500 dark:text-neutral-400 mt-0.5">
                {analysis.repository_name}
              </p>
            </div>
            <button onClick={onClose} className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 -mt-1">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Severity Bar */}
        {hasFindings ? (
          <div className="px-6 pb-5">
            <div className="flex items-center gap-3 mb-4">
              {Object.entries(counts).map(([level, count]) => (
                count > 0 && (
                  <div key={level} className="flex items-center gap-1.5">
                    <span className={`h-2.5 w-2.5 rounded-full ${severityColors[level]?.bg}`} />
                    <span className={`text-sm font-medium ${severityColors[level]?.text}`}>
                      {count} {level}
                    </span>
                  </div>
                )
              ))}
            </div>

            {/* Stacked bar */}
            <div className="h-2 rounded-full bg-neutral-200 dark:bg-neutral-800 overflow-hidden flex">
              {Object.entries(counts).map(([level, count]) => (
                count > 0 && (
                  <div
                    key={level}
                    className={`${severityColors[level]?.bg}`}
                    style={{ width: `${(count / total) * 100}%` }}
                  />
                )
              ))}
            </div>

            <p className="text-sm text-neutral-500 dark:text-neutral-400 mt-3">
              {total} finding{total === 1 ? '' : 's'} detected. Review the annotated PR on GitHub for details and remediation.
            </p>
          </div>
        ) : (
          <div className="px-6 pb-5">
            <div className="flex items-center gap-2 text-green-600 dark:text-green-400">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span className="text-sm font-medium">No security issues found</span>
            </div>
          </div>
        )}

        {/* Meta */}
        <div className="px-6 pb-4">
          <div className="flex items-center gap-4 text-xs text-neutral-400 dark:text-neutral-500">
            <span className="capitalize">{analysis.status}</span>
            {duration !== null && <span>{duration}s</span>}
            {analysis.completed_at && (
              <span>{new Date(analysis.completed_at).toLocaleDateString()}</span>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-neutral-200 dark:border-neutral-800 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white"
          >
            Close
          </button>
          <a
            href={prUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-4 py-2 bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 rounded-lg hover:bg-neutral-800 dark:hover:bg-neutral-200 transition-colors text-sm font-medium"
          >
            View on GitHub
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
        </div>
      </div>
    </div>
  );
};

export default PRAnalysisModal;
