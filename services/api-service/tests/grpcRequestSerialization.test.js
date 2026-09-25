/**
 * Guards the wire-format contract between the generated protobuf bindings and
 * the google-protobuf runtime that api-service resolves.
 *
 * Regression: google-protobuf 4.x removed jspb.Map.prototype.serializeBinary,
 * while the generated analysis_pb.js still calls it for the
 * TriageFindingsRequest.file_patches map. Serializing a request with a
 * non-empty map threw "f.serializeBinary is not a function" at the transport
 * layer, so the analysis service never saw the request.
 */
const jspb = require('google-protobuf');
const analysisGrpc = require('../src/grpc/generated/analysis_grpc_pb');
const githubGrpc = require('../src/grpc/generated/github_grpc_pb');
const githubPb = require('../src/grpc/generated/github_pb');
const commonPb = require('../src/grpc/generated/common_pb');
const analysisPb = require('../src/grpc/generated/analysis_pb');
const { buildAnalyzeRequest, buildTriageRequest, analyzeResponseToPlain } = require('../src/clients/analysisGrpcClient');

const analysisService = analysisGrpc.AnalysisServiceService;
const githubService = githubGrpc.GitHubServiceService;

const analyzePayload = {
  repository_full_name: 'nebullii/test-only',
  pull_request_number: 120,
  commit_sha: 'a'.repeat(40),
  files: [
    {
      path: 'services/orders.js',
      patch: '@@ -1,4 +1,8 @@\n+const q = "SELECT * FROM orders WHERE id = " + id;',
      content: 'const q = 1;',
      additions: 8,
      deletions: 1,
      status: 'modified',
      raw_url: 'https://example.invalid/raw/orders.js',
      reviewable_line_spans: [{ start: 1, end: 40 }],
    },
  ],
};

const triagePayload = {
  ...analyzePayload,
  findings: [
    {
      rule_id: 'sql-injection-concat',
      severity: 'high',
      title: 'SQL injection',
      file_path: 'services/orders.js',
      line: 13,
      description: 'String concatenation in SQL',
    },
  ],
  // The map field is the part that regressed; it must be non-empty here.
  file_patches: {
    'services/orders.js': '@@ -1,4 +1,8 @@\n+const q = "SELECT";',
    'services/util.js': '@@ -1,2 +1,3 @@\n+module.exports = {};',
  },
  repo_profile: { language: 'javascript', framework: 'express' },
};

function healthRequest() {
  return new commonPb.HealthCheckRequest();
}

describe('generated gRPC request serialization', () => {
  it('exposes the jspb.Map binary serializer the generated bindings call', () => {
    expect(typeof jspb.Map.prototype.serializeBinary).toBe('function');
  });

  const analysisCases = [
    ['analyzePullRequest', () => buildAnalyzeRequest(analyzePayload)],
    ['analyzeTier1', () => buildAnalyzeRequest(analyzePayload)],
    ['analyzeTier2', () => buildAnalyzeRequest(analyzePayload)],
    ['triageFindings', () => buildTriageRequest(triagePayload)],
    ['healthCheck', healthRequest],
  ];

  it.each(analysisCases)('serializes AnalysisService.%s requests', (method, build) => {
    const definition = analysisService[method];
    expect(definition).toBeDefined();
    const serialized = definition.requestSerialize(build());
    expect(Buffer.isBuffer(serialized)).toBe(true);
    const roundTripped = definition.requestDeserialize(serialized);
    expect(roundTripped).toBeDefined();
  });

  it('round-trips the triage file_patches map without dropping entries', () => {
    const definition = analysisService.triageFindings;
    const decoded = definition.requestDeserialize(
      definition.requestSerialize(buildTriageRequest(triagePayload))
    );
    const map = decoded.getFilePatchesMap();
    expect(map.getLength()).toBe(2);
    expect(map.get('services/orders.js')).toBe(triagePayload.file_patches['services/orders.js']);
    expect(map.get('services/util.js')).toBe(triagePayload.file_patches['services/util.js']);
    expect(decoded.getFindingsList()).toHaveLength(1);
    expect(decoded.getRepoProfile()).not.toBeNull();
  });

  const githubCases = [
    ['fetchPullRequestFiles', () => {
      const request = new githubPb.FetchPullRequestFilesRequest();
      request.setRepositoryFullName('nebullii/test-only');
      request.setPullRequestNumber(120);
      request.setCommitSha('b'.repeat(40));
      request.setInstallationId(1234);
      return request;
    }],
    ['fetchFileContents', () => {
      const request = new githubPb.FetchFileContentsRequest();
      request.setRepositoryFullName('nebullii/test-only');
      request.setInstallationId(1234);
      request.setRef('main');
      request.setPathsList(['services/orders.js']);
      return request;
    }],
    ['submitPullRequestReview', () => {
      const request = new githubPb.SubmitPullRequestReviewRequest();
      request.setOwner('nebullii');
      request.setRepo('test-only');
      request.setPrNumber(120);
      request.setInstallationId(1234);
      request.setCommitSha('c'.repeat(40));
      request.setBody('summary');
      request.setEvent('COMMENT');
      const comment = new commonPb.ReviewComment();
      comment.setPath('services/orders.js');
      comment.setLine(13);
      comment.setBody('SQL injection');
      request.setCommentsList([comment]);
      return request;
    }],
    ['postInlineComment', () => {
      const request = new githubPb.PostInlineCommentRequest();
      request.setOwner('nebullii');
      request.setRepo('test-only');
      request.setPrNumber(120);
      request.setInstallationId(1234);
      request.setCommitSha('d'.repeat(40));
      request.setPath('services/orders.js');
      request.setLine(13);
      request.setBody('SQL injection');
      return request;
    }],
    ['createCheckRun', () => {
      const request = new githubPb.CreateCheckRunRequest();
      request.setOwner('nebullii');
      request.setRepo('test-only');
      request.setInstallationId(1234);
      request.setHeadSha('e'.repeat(40));
      request.setConclusion('neutral');
      request.setTitle('Mitig8it');
      request.setSummary('4 findings');
      return request;
    }],
    ['healthCheck', healthRequest],
  ];

  it.each(githubCases)('serializes GitHubService.%s requests', (method, build) => {
    const definition = githubService[method];
    expect(definition).toBeDefined();
    const serialized = definition.requestSerialize(build());
    expect(Buffer.isBuffer(serialized)).toBe(true);
    expect(definition.requestDeserialize(serialized)).toBeDefined();
  });
});

describe('test-code markers survive the wire format', () => {
  const { findingToMessage, findingToPlain } = require('../src/clients/grpcConverters');

  test('evidence_details.extra round-trips through serialization', () => {
    const message = findingToMessage({
      rule_id: 'secrets.hardcoded',
      file_path: 'test_security.py',
      severity: 'info',
      evidence_details: {
        analysis_scope: 'pattern',
        extra: { in_test_code: true, original_severity: 'critical' },
      },
    });

    const restored = commonPb.Finding.deserializeBinary(message.serializeBinary());
    const plain = findingToPlain(restored);

    expect(plain.severity).toBe('info');
    expect(plain.evidence_details.extra).toEqual({
      in_test_code: true,
      original_severity: 'critical',
    });
  });

  test('findings without markers carry no extra', () => {
    const message = findingToMessage({ rule_id: 'r', file_path: 'app.js', severity: 'high' });
    const plain = findingToPlain(commonPb.Finding.deserializeBinary(message.serializeBinary()));

    expect(plain.evidence_details.extra).toBeUndefined();
  });
});

describe('analysis limitations cross the gRPC boundary', () => {
  function limitation({ path, kind, type, message, line }) {
    const entry = new commonPb.AnalysisLimitation();
    entry.setPath(path);
    entry.setKind(kind);
    entry.setType(type);
    entry.setMessage(message);
    if (line) entry.setLine(line);
    return entry;
  }

  test('a partially parsed file reaches the orchestrator as a plain object', () => {
    const response = new analysisPb.AnalyzePullRequestResponse();
    response.setTier(2);
    response.setAnalysisLimitationsList([
      limitation({
        path: 'services/cwe-vul.py',
        kind: 'partial_parse',
        type: 'Lexical error',
        message: 'unrecognized symbol in string',
        line: 127,
      }),
      limitation({ path: 'services/huge.ts', kind: 'not_analyzed', type: 'Timeout', message: 'timed out' }),
    ]);

    const restored = analysisPb.AnalyzePullRequestResponse.deserializeBinary(response.serializeBinary());

    expect(analyzeResponseToPlain(restored).analysis_limitations).toEqual([
      {
        path: 'services/cwe-vul.py',
        kind: 'partial_parse',
        type: 'Lexical error',
        message: 'unrecognized symbol in string',
        line: 127,
      },
      { path: 'services/huge.ts', kind: 'not_analyzed', type: 'Timeout', message: 'timed out', line: null },
    ]);
  });

  test('a response without limitations maps to an empty list', () => {
    const response = new analysisPb.AnalyzePullRequestResponse();
    const restored = analysisPb.AnalyzePullRequestResponse.deserializeBinary(response.serializeBinary());
    expect(analyzeResponseToPlain(restored).analysis_limitations).toEqual([]);
  });
});
