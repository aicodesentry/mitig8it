const grpc = require('@grpc/grpc-js');
const requestContext = require('../utils/requestContext');

describe('github service request context', () => {
  test('a gRPC call adopts the caller identifiers and logs under them', async () => {
    const lines = [];
    const originalLog = console.log;
    console.log = (line) => lines.push(line);

    try {
      const metadata = new grpc.Metadata();
      metadata.set('x-github-delivery', 'delivery-7');
      metadata.set('x-analysis-run-id', 'run-7');

      // Exactly what the gRPC server's unary wrapper does with an incoming call.
      await requestContext.runWith(requestContext.fromGrpcMetadata(metadata), async () => {
        await new Promise((resolve) => setImmediate(resolve));
        require('../utils/logger').info('fetched pull request files');
        // And what the analysis client then puts on its outbound HTTP call.
        expect(requestContext.toHeaders()).toEqual({
          'x-github-delivery': 'delivery-7',
          'x-analysis-run-id': 'run-7',
        });
      });
    } finally {
      console.log = originalLog;
    }

    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0]);
    expect(entry.severity).toBe('INFO');
    expect(entry.message).toBe('fetched pull request files');
    expect(entry.delivery_id).toBe('delivery-7');
    expect(entry.analysis_run_id).toBe('run-7');
  });

  test('an incoming HTTP request carries its identifiers to the analysis client headers', () => {
    process.env.ANALYSIS_SERVICE_INTERNAL_SECRET = 'secret';
    const fields = requestContext.fromHeaders({ 'x-github-delivery': 'delivery-8' });

    requestContext.runWith(fields, () => {
      expect(requestContext.toHeaders()).toEqual({ 'x-github-delivery': 'delivery-8' });
    });
  });

  test('a string second argument is recorded as one field, not one key per character', () => {
    const lines = [];
    const originalLog = console.log;
    console.log = (line) => lines.push(line);
    try {
      require('../utils/logger').error('analysis failed', 'connect ECONNREFUSED');
    } finally {
      console.log = originalLog;
    }
    expect(JSON.parse(lines[0]).detail).toBe('connect ECONNREFUSED');
  });

  test('a newline in the delivery header cannot forge a second log line', () => {
    const fields = requestContext.fromHeaders({ 'x-github-delivery': 'abc\nnot-a-line' });
    expect(fields.delivery_id).toBe('abcnot-a-line');
  });
});
