jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
  scopedTransaction: jest.fn(),
}));

jest.mock('../src/db/qualityMetrics', () => ({
  installationsWithActivity: jest.fn(),
  recomputeInstallation: jest.fn(),
  readWindow: jest.fn(),
}));

const qualityMetricsDb = require('../src/db/qualityMetrics');
const metrics = require('../src/services/remediationMetrics');
const reconciler = require('../src/services/remediationReconciler');

function daily(overrides = {}) {
  return {
    findings_new: 0, fixes_published: 0, applied_in_app: 0, applied_on_github: 0,
    dismissed: 0, accepted_risk: 0, suppressed: 0, thread_resolved: 0,
    thread_resolved_without_fix: 0, fixed_by_reanalysis: 0, residual_after_apply: 0,
    ...overrides,
  };
}

async function gaugeValue(gauge, installationId, window) {
  const { values } = await gauge.get();
  return values.find((value) => value.labels.installation_id === installationId && value.labels.window === window)?.value;
}

beforeEach(() => {
  jest.clearAllMocks();
  reconciler.resetQualityMetricsClock();
  metrics.qualityApplyRate.reset();
  metrics.qualityDismissRate.reset();
  metrics.qualityResidualRate.reset();
  qualityMetricsDb.installationsWithActivity.mockResolvedValue([]);
  qualityMetricsDb.recomputeInstallation.mockResolvedValue({ rows: 0 });
  qualityMetricsDb.readWindow.mockResolvedValue([]);
});

describe('the quality_metrics reconciler step', () => {
  test('recomputes the trailing window for every active installation', async () => {
    qualityMetricsDb.installationsWithActivity.mockResolvedValue(['42', '43']);

    const summary = await reconciler.refreshQualityMetrics();

    expect(summary).toMatchObject({ installations: 2, recomputed: 2, failed: 0 });
    expect(qualityMetricsDb.recomputeInstallation).toHaveBeenCalledWith('42', { days: 35 });
    expect(qualityMetricsDb.recomputeInstallation).toHaveBeenCalledWith('43', { days: 35 });
  });

  test('runs at most once per interval', async () => {
    qualityMetricsDb.installationsWithActivity.mockResolvedValue(['42']);
    const now = Date.now();

    await reconciler.refreshQualityMetrics({ now });
    const second = await reconciler.refreshQualityMetrics({ now: now + 60000 });

    expect(second.skipped).toBe(true);
    expect(qualityMetricsDb.recomputeInstallation).toHaveBeenCalledTimes(1);
  });

  test('runs again once the interval has passed', async () => {
    qualityMetricsDb.installationsWithActivity.mockResolvedValue(['42']);
    const now = Date.now();

    await reconciler.refreshQualityMetrics({ now });
    await reconciler.refreshQualityMetrics({ now: now + reconciler.qualityMetricsIntervalMs() + 1 });

    expect(qualityMetricsDb.recomputeInstallation).toHaveBeenCalledTimes(2);
  });

  test('takes QUALITY_METRICS_INTERVAL_MS from the environment', () => {
    const previous = process.env.QUALITY_METRICS_INTERVAL_MS;
    process.env.QUALITY_METRICS_INTERVAL_MS = '120000';
    try {
      expect(reconciler.qualityMetricsIntervalMs()).toBe(120000);
    } finally {
      if (previous == null) delete process.env.QUALITY_METRICS_INTERVAL_MS;
      else process.env.QUALITY_METRICS_INTERVAL_MS = previous;
    }
  });

  test('defaults to one hour', () => {
    const previous = process.env.QUALITY_METRICS_INTERVAL_MS;
    delete process.env.QUALITY_METRICS_INTERVAL_MS;
    try {
      expect(reconciler.qualityMetricsIntervalMs()).toBe(3600000);
    } finally {
      if (previous != null) process.env.QUALITY_METRICS_INTERVAL_MS = previous;
    }
  });

  test('publishes the three gauges for each exported window', async () => {
    qualityMetricsDb.installationsWithActivity.mockResolvedValue(['42']);
    qualityMetricsDb.readWindow.mockResolvedValue([
      daily({ findings_new: 20, fixes_published: 10, applied_in_app: 5, dismissed: 5, residual_after_apply: 1 }),
    ]);

    await reconciler.refreshQualityMetrics();

    expect(await gaugeValue(metrics.qualityApplyRate, '42', '30d')).toBe(0.5);
    expect(await gaugeValue(metrics.qualityDismissRate, '42', '7d')).toBe(0.25);
    expect(await gaugeValue(metrics.qualityResidualRate, '42', '30d')).toBe(0.2);
  });

  test('exports no gauge at all for a rate with no denominator', async () => {
    qualityMetricsDb.installationsWithActivity.mockResolvedValue(['42']);
    qualityMetricsDb.readWindow.mockResolvedValue([daily({ findings_new: 4, dismissed: 1 })]);

    await reconciler.refreshQualityMetrics();

    expect(await gaugeValue(metrics.qualityDismissRate, '42', '30d')).toBe(0.25);
    expect(await gaugeValue(metrics.qualityApplyRate, '42', '30d')).toBeUndefined();
    expect(await gaugeValue(metrics.qualityResidualRate, '42', '30d')).toBeUndefined();
  });

  test('one failing installation does not stop the rest', async () => {
    qualityMetricsDb.installationsWithActivity.mockResolvedValue(['42', '43']);
    qualityMetricsDb.recomputeInstallation.mockImplementation(async (id) => {
      if (id === '42') throw new Error('deadlock detected');
      return { rows: 1 };
    });

    const summary = await reconciler.refreshQualityMetrics();

    expect(summary).toMatchObject({ installations: 2, recomputed: 1, failed: 1 });
  });
});
