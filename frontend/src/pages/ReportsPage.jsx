import { useState, useEffect, useRef, lazy, Suspense } from 'react';
import { ArrowUpRight, ClipboardList, Clock3, ShieldAlert, Sparkles } from 'lucide-react';
import { formatRate, reportsAPI, repositoryAPI } from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import { getPrivateCacheEpoch } from '../services/privateCache';
import { Pagination } from '../components/ui/pagination';

const PRAnalysisModal = lazy(() => import('../components/PRAnalysisModal'));

const CACHE_DURATION = 5 * 60 * 1000;

const getCacheKey = (userId, page, repo, status) => {
  if (page === 1 && !repo && !status) return `reports_cache_user_${userId}_main`;
  return `reports_cache_user_${userId}_page_${page}_repo_${repo || 'all'}_status_${status || 'all'}`;
};

const ReportsPage = () => {
  const { user } = useAuth();
  return user?.id == null ? null : <AccountReports key={user.id} userId={user.id} />;
};

const AccountReports = ({ userId }) => {
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  const [analyses, setAnalyses] = useState([]);
  const [repositories, setRepositories] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [selectedRepo, setSelectedRepo] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [rulesByDismissRate, setRulesByDismissRate] = useState([]);
  const itemsPerPage = 10;

  useEffect(() => {
    let active = true;
    const epoch = getPrivateCacheEpoch();
    const isCurrent = () => active && epoch === getPrivateCacheEpoch();
    const cacheKey = getCacheKey(userId, currentPage, selectedRepo, selectedStatus);
    setLoading(true);
    setError(null);
    const load = async () => {
      try {
        const cached = localStorage.getItem(cacheKey);
        if (cached) {
          const { data, timestamp, total, repos, summaryData } = JSON.parse(cached);
          if (Date.now() - timestamp < CACHE_DURATION) {
            setAnalyses(data);
            setTotalCount(total);
            setRepositories(repos || []);
            setSummary(summaryData || null);
            setLoading(false);
          }
        }
      } catch (_error) {
        // Storage may be disabled or contain an obsolete cache; network still works.
      }
      try {
        const filters = { limit: itemsPerPage, offset: (currentPage - 1) * itemsPerPage };
        if (selectedRepo) filters.repository_id = selectedRepo;
        if (selectedStatus) filters.status = selectedStatus;
        const [analysesData, summaryData, reposData] = await Promise.all([
          reportsAPI.getPRAnalyses(filters), reportsAPI.getSummary(), repositoryAPI.getRepositories()
        ]);
        if (!isCurrent()) return;
        setAnalyses(analysesData.analyses);
        setTotalCount(analysesData.total || 0);
        setSummary(summaryData.summary);
        setRepositories(reposData.repositories);
        try {
          localStorage.setItem(cacheKey, JSON.stringify({
            data: analysesData.analyses, total: analysesData.total || 0,
            repos: reposData.repositories, summaryData: summaryData.summary, timestamp: Date.now()
          }));
        } catch (_error) { /* Caching is optional. */ }
      } catch (err) {
        if (!isCurrent()) return;
        console.error('Failed to fetch reports:', err);
        setError('Failed to load reports. Please try again.');
      } finally {
        if (isCurrent()) setLoading(false);
      }
    };
    load();
    return () => { active = false; };
  }, [userId, currentPage, selectedRepo, selectedStatus]);

  // The rule table follows the repository filter but not the page or the status filter:
  // it describes the rules themselves, not the analyses listed below it. It is read from
  // a pre-computed roll-up, so it is not cached and not paginated.
  useEffect(() => {
    let active = true;
    const epoch = getPrivateCacheEpoch();
    const load = async () => {
      try {
        const data = await reportsAPI.getQuality({
          window: 30, ...(selectedRepo ? { repositoryId: selectedRepo } : {})
        });
        if (!active || epoch !== getPrivateCacheEpoch()) return;
        setRulesByDismissRate(data.by_rule || []);
      } catch (err) {
        if (!active) return;
        console.error('Failed to fetch quality metrics:', err);
        setRulesByDismissRate([]);
      }
    };
    load();
    return () => { active = false; };
  }, [userId, selectedRepo]);

  const handleViewDetails = async (analysis) => {
    const epoch = getPrivateCacheEpoch();
    try {
      const detailsData = await reportsAPI.getPRAnalysisDetails(analysis.id);
      if (!mounted.current || epoch !== getPrivateCacheEpoch()) return;
      setSelectedAnalysis(detailsData.analysis);
      setShowModal(true);
    } catch (err) {
      console.error('Failed to fetch analysis details:', err);
    }
  };

  const getStatusBadge = (status) => {
    const badges = {
      completed: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/10 dark:text-emerald-400',
      processing: 'bg-neutral-100 text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300',
      failed: 'bg-red-100 text-red-800 dark:bg-red-500/10 dark:text-red-400',
      received: 'bg-neutral-100 text-neutral-600 dark:bg-neutral-700 dark:text-neutral-400',
    };
    return badges[status] || badges.received;
  };

  const formatDuration = (seconds) => {
    if (!seconds) return '-';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  };

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-neutral-900 dark:text-white">Reports</h1>
          <p className="text-sm text-neutral-500 dark:text-neutral-400">Analysis history across your repositories</p>
        </div>
        <a
          href="/dashboard/onboarding"
          className="inline-flex items-center gap-2 rounded-lg bg-neutral-900 px-4 py-2 text-sm font-medium text-white hover:bg-neutral-800 dark:bg-white dark:text-neutral-900 dark:hover:bg-neutral-100"
        >
          Trigger first PR
          <ArrowUpRight className="h-3.5 w-3.5" />
        </a>
      </div>

      {/* Stats row */}
      {summary && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {[
            { icon: ClipboardList, value: summary.total_analyses, label: 'Total analyses' },
            { icon: Sparkles, value: summary.completed, label: 'Completed' },
            { icon: ShieldAlert, value: summary.failed, label: 'Failed' },
            { icon: Clock3, value: summary.recent_7_days, label: 'Last 7 days' },
          ].map((stat) => (
            <div key={stat.label} className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-neutral-100 dark:bg-neutral-800">
                  <stat.icon className="h-4 w-4 text-neutral-600 dark:text-neutral-300" />
                </div>
                <div>
                  <p className="text-2xl font-semibold text-neutral-900 dark:text-white">{stat.value}</p>
                  <p className="text-xs text-neutral-500 dark:text-neutral-400">{stat.label}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 px-5 py-3 dark:border-red-500/30 dark:bg-red-500/10">
          <p className="text-sm font-medium text-red-800 dark:text-red-300">{error}</p>
        </div>
      )}

      {/* Filters */}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <select
          value={selectedRepo}
          onChange={(e) => { setSelectedRepo(e.target.value); setCurrentPage(1); }}
          className="rounded-lg border border-neutral-200 bg-white px-4 py-2 text-sm text-neutral-900 focus:border-neutral-500 focus:outline-none dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-100 dark:focus:border-neutral-500"
        >
          <option value="">All repositories</option>
          {repositories.filter((r) => r.is_active !== false).map(repo => (
            <option key={repo.github_id} value={repo.id}>{repo.full_name}</option>
          ))}
        </select>
        <select
          value={selectedStatus}
          onChange={(e) => { setSelectedStatus(e.target.value); setCurrentPage(1); }}
          className="rounded-lg border border-neutral-200 bg-white px-4 py-2 text-sm text-neutral-900 focus:border-neutral-500 focus:outline-none dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-100 dark:focus:border-neutral-500"
        >
          <option value="">All statuses</option>
          <option value="completed">Completed</option>
          <option value="processing">Processing</option>
          <option value="failed">Failed</option>
          <option value="received">Received</option>
        </select>
        {(selectedRepo || selectedStatus) && (
          <button
            onClick={() => { setSelectedRepo(''); setSelectedStatus(''); setCurrentPage(1); }}
            className="rounded-lg border border-neutral-200 px-4 py-2 text-sm font-medium text-neutral-600 hover:bg-neutral-50 dark:border-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-800"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Rules ranked by how often people reject what they report */}
      {rulesByDismissRate.length > 0 && (
        <div>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-neutral-900 dark:text-white">Rules by dismiss rate</h2>
            <p className="text-xs text-neutral-500 dark:text-neutral-400">
              Last 30 days. A high rate means the rule reports findings people reject.
            </p>
          </div>
          <div className="overflow-hidden rounded-xl border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900">
            <table className="min-w-full divide-y divide-neutral-100 dark:divide-neutral-800">
              <thead>
                <tr>
                  <th scope="col" className="px-4 py-2 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400">Rule</th>
                  <th scope="col" className="px-4 py-2 text-right text-xs font-medium text-neutral-500 dark:text-neutral-400">Findings</th>
                  <th scope="col" className="px-4 py-2 text-right text-xs font-medium text-neutral-500 dark:text-neutral-400">Dismiss rate</th>
                  <th scope="col" className="px-4 py-2 text-right text-xs font-medium text-neutral-500 dark:text-neutral-400">Apply rate</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-100 dark:divide-neutral-800">
                {rulesByDismissRate.map((rule) => (
                  <tr key={rule.rule_id}>
                    <td className="px-4 py-2 font-mono text-xs text-neutral-900 dark:text-neutral-100">{rule.rule_id}</td>
                    <td className="px-4 py-2 text-right text-sm text-neutral-600 dark:text-neutral-300">{rule.findings_new}</td>
                    <td className="px-4 py-2 text-right text-sm font-medium text-neutral-900 dark:text-white">{formatRate(rule.dismiss_rate)}</td>
                    <td className="px-4 py-2 text-right text-sm text-neutral-600 dark:text-neutral-300">{formatRate(rule.apply_rate)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Table */}
      <div>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-white">Pull Request Analyses</h2>
          {totalCount > 0 && (
            <p className="text-xs text-neutral-500 dark:text-neutral-400">
              {(currentPage - 1) * itemsPerPage + 1}–{Math.min(currentPage * itemsPerPage, totalCount)} of {totalCount}
            </p>
          )}
        </div>

        {analyses.length === 0 && !loading ? (
          <div className="rounded-xl border border-dashed border-neutral-200 px-6 py-12 text-center text-sm text-neutral-500 dark:border-neutral-800 dark:text-neutral-400">
            No analyses found. Connect a repository and open a pull request to get started.
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900">
            <table className="min-w-full divide-y divide-neutral-100 dark:divide-neutral-800">
              <thead>
                <tr className="bg-neutral-50 dark:bg-neutral-800/50">
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wider text-neutral-500">Repository</th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wider text-neutral-500">PR</th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wider text-neutral-500">Status</th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wider text-neutral-500">Started</th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wider text-neutral-500">Duration</th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wider text-neutral-500"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-100 dark:divide-neutral-800">
                {loading ? (
                  Array.from({ length: itemsPerPage }).map((_, idx) => (
                    <tr key={idx} className="animate-pulse">
                      {Array.from({ length: 6 }).map((_, i) => (
                        <td key={i} className="px-5 py-4"><div className="h-4 rounded bg-neutral-100 dark:bg-neutral-800 w-20" /></td>
                      ))}
                    </tr>
                  ))
                ) : (
                  analyses.map((analysis) => (
                    <tr key={analysis.id} className="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                      <td className="px-5 py-3 text-sm font-medium text-neutral-900 dark:text-white whitespace-nowrap">{analysis.repository_name}</td>
                      <td className="px-5 py-3 whitespace-nowrap">
                        <a href={analysis.pr_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-sm text-neutral-600 hover:text-neutral-900 dark:text-neutral-300 dark:hover:text-white">
                          #{analysis.pr_number}
                          <ArrowUpRight className="h-3 w-3" />
                        </a>
                      </td>
                      <td className="px-5 py-3 whitespace-nowrap">
                        <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold ${getStatusBadge(analysis.status)}`}>
                          {analysis.status}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">{formatDate(analysis.started_at)}</td>
                      <td className="px-5 py-3 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">{formatDuration(analysis.processing_time_seconds)}</td>
                      <td className="px-5 py-3 whitespace-nowrap">
                        <button
                          onClick={() => handleViewDetails(analysis)}
                          className="text-sm font-medium text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
            {totalCount > itemsPerPage && (
              <div className="border-t border-neutral-100 px-5 py-3 dark:border-neutral-800">
                <Pagination currentPage={currentPage} totalPages={Math.ceil(totalCount / itemsPerPage)} onPageChange={setCurrentPage} />
              </div>
            )}
          </div>
        )}
      </div>

      {showModal && selectedAnalysis && (
        <Suspense fallback={
          <div className="fixed inset-0 bg-neutral-950/50 flex items-center justify-center z-50">
            <div className="rounded-lg bg-white p-8 dark:bg-neutral-800">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-neutral-500 mx-auto" />
              <p className="mt-4 text-neutral-600 dark:text-neutral-400">Loading details...</p>
            </div>
          </div>
        }>
          <PRAnalysisModal analysis={selectedAnalysis} onClose={() => { setShowModal(false); setSelectedAnalysis(null); }} />
        </Suspense>
      )}
    </div>
  );
};

export default ReportsPage;
