const grpc = require('@grpc/grpc-js');
const requestContext = require('../src/utils/requestContext');

describe('request context', () => {
  test('identifiers reach a nested async call site without being passed to it', async () => {
    const seen = await requestContext.runWith(
      { delivery_id: 'delivery-1', analysis_run_id: 'run-1' },
      async () => {
        await new Promise((resolve) => setImmediate(resolve));
        return (async () => requestContext.current())();
      }
    );
    expect(seen).toEqual({ delivery_id: 'delivery-1', analysis_run_id: 'run-1' });
  });

  test('an identifier learned partway through joins the context already in scope', () => {
    requestContext.runWith({ delivery_id: 'delivery-1' }, () => {
      requestContext.assign({ job_id: 'job-1' });
      expect(requestContext.current()).toEqual({ delivery_id: 'delivery-1', job_id: 'job-1' });
    });
  });

  test('outbound headers carry only the fields that are actually known', () => {
    requestContext.runWith({ delivery_id: 'delivery-1' }, () => {
      expect(requestContext.toHeaders()).toEqual({ 'x-github-delivery': 'delivery-1' });
    });
    expect(requestContext.toHeaders()).toEqual({});
  });

  test('inbound headers round-trip through outbound headers', () => {
    const inbound = {
      'x-github-delivery': 'delivery-1',
      'x-analysis-run-id': 'run-1',
      'x-job-id': 'job-1',
      'x-correlation-id': 'corr-1',
    };
    requestContext.runWith(requestContext.fromHeaders(inbound), () => {
      expect(requestContext.toHeaders()).toEqual(inbound);
    });
  });

  test('gRPC metadata round-trips the same identifiers', () => {
    requestContext.runWith({ delivery_id: 'delivery-1', job_id: 'job-1' }, () => {
      const metadata = requestContext.toGrpcMetadata(grpc.Metadata);
      expect(requestContext.fromGrpcMetadata(metadata)).toEqual({
        delivery_id: 'delivery-1',
        job_id: 'job-1',
      });
    });
  });

  // An identifier arrives from GitHub and from peer services. A newline in one would
  // forge a second log line out of a single record.
  test('a newline in an identifier cannot forge a second log line', () => {
    requestContext.runWith({ delivery_id: 'abc\n{"severity":"ERROR"}' }, () => {
      expect(requestContext.current().delivery_id).toBe('abc{"severity":"ERROR"}');
    });
  });

  test('an oversized identifier is bounded rather than logged whole', () => {
    requestContext.runWith({ correlation_id: 'x'.repeat(5000) }, () => {
      expect(requestContext.current().correlation_id).toHaveLength(200);
    });
  });

  test('an empty or missing identifier is left out rather than logged as empty', () => {
    requestContext.runWith({ delivery_id: '', job_id: null, analysis_run_id: '  ' }, () => {
      expect(requestContext.current()).toEqual({});
    });
  });
});

describe('logger', () => {
  const lines = [];
  let originalLog;

  beforeAll(() => {
    originalLog = console.log;
    console.log = (line) => lines.push(line);
  });

  afterAll(() => {
    console.log = originalLog;
  });

  beforeEach(() => {
    lines.length = 0;
  });

  test('every line is one JSON object with a Cloud Logging severity', () => {
    const logger = require('../src/utils/logger');
    logger.error('something broke', { detail: 'x' });

    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0]);
    expect(entry.severity).toBe('ERROR');
    expect(entry.message).toBe('something broke');
    expect(entry.level).toBe('error');
    expect(entry.detail).toBe('x');
  });

  test('a line written inside a context carries the identifiers without being handed them', () => {
    const logger = require('../src/utils/logger');
    requestContext.runWith({ delivery_id: 'delivery-1', analysis_run_id: 'run-1' }, () => {
      logger.info('claimed');
    });

    const entry = JSON.parse(lines[0]);
    expect(entry.delivery_id).toBe('delivery-1');
    expect(entry.analysis_run_id).toBe('run-1');
    expect(entry.severity).toBe('INFO');
  });

  test('an explicit field at the call site still wins over the ambient context', () => {
    const logger = require('../src/utils/logger');
    requestContext.runWith({ analysis_run_id: 'run-1' }, () => {
      logger.warn('about another run', { analysis_run_id: 'run-2' });
    });

    expect(JSON.parse(lines[0]).analysis_run_id).toBe('run-2');
  });
});
