jest.mock('axios', () => ({ post: jest.fn() }));
jest.mock('../src/db/findings', () => ({ findByFingerprint: jest.fn(), upsert: jest.fn(), markFixed: jest.fn(), getActiveSuppressions: jest.fn().mockResolvedValue([]), mergeEvidenceDetails: jest.fn(), snapshotRun: jest.fn() }));
jest.mock('../src/db/analysisRuns', () => ({ countCompletedRuns: jest.fn().mockResolvedValue(1), markCompleted: jest.fn(), markFailed: jest.fn() }));
jest.mock('../src/db/repositories', () => ({ getProfile: jest.fn().mockResolvedValue({ profile_status: 'ready', profile_data: {} }) }));
jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));
const axios = require('axios');
const findings = require('../src/db/findings');
const runs = require('../src/db/analysisRuns');
const { triggerAnalysisJob } = require('../src/services/prAnalysisOrchestrator');
const payload = { analysis_run_id: 'run1', repository_id: 'repo1', repository_full_name: 'owner/repo', installation_id: 1, pull_request_id: 'pr1', pull_request_number: 1, commit_sha: 'sha1', baseline_set: true };
const calls = (part) => axios.post.mock.calls.filter(([url]) => url.includes(part));
const drain = () => new Promise(resolve => setTimeout(resolve, 30));
beforeEach(() => { jest.clearAllMocks(); process.env.INTERNAL_SERVICE_TRANSPORT = 'http'; process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'test-secret'; axios.post.mockImplementation(async url => ({data: url.includes('/pulls/files') ? {files: [], commit_sha: 'sha1'} : url.includes('/tier') ? {findings: []} : {review_id: 1, check_run_id: 1}})); });
test.each(['tier1', 'tier2', 'tier3'])('%s outage cannot approve or reconcile findings', async tier => {
 const original = axios.post.getMockImplementation(); axios.post.mockImplementation((url,...args) => url.includes('/'+tier) ? Promise.reject(new Error('analysis unavailable')) : original(url,...args));
 triggerAnalysisJob(payload); await drain();
 expect(runs.markFailed).toHaveBeenCalled(); expect(runs.markCompleted).not.toHaveBeenCalled();
 expect(calls('/check-runs').some(([,data]) => data.conclusion === 'success')).toBe(false);
 expect(findings.markFixed).not.toHaveBeenCalled();
});
test('clean scan reconciles old findings and submits a final nonblocking review', async () => {
 triggerAnalysisJob(payload); await drain();
 expect(findings.markFixed).toHaveBeenCalledWith(expect.objectContaining({activeFingerprints: []}));
 expect(calls('/reviews/submit')).toHaveLength(1);
 expect(calls('/reviews/submit')[0][1].event).toBe('COMMENT');
 expect(runs.markCompleted).toHaveBeenCalled();
});
test('queued commit is forwarded to file retrieval', async () => {
 triggerAnalysisJob(payload); await drain(); expect(calls('/pulls/files')[0][1].commit_sha).toBe('sha1');
});
test('full-content outage cannot become a clean required scan', async () => {
 const original = axios.post.getMockImplementation();
 axios.post.mockImplementation((url,...args) => url.includes('/pulls/files') ? Promise.resolve({data:{files:[{path:'app.py',patch:'+eval(user_input)',additions:1}]}}) : url.includes('/files/content') ? Promise.reject(new Error('content unavailable')) : original(url,...args));
 triggerAnalysisJob(payload); await drain();
 expect(runs.markFailed).toHaveBeenCalled(); expect(runs.markCompleted).not.toHaveBeenCalled();
});
test('malformed file response fails closed', async () => {
 const original=axios.post.getMockImplementation(); axios.post.mockImplementation((url,...args)=>url.includes('/pulls/files')?Promise.resolve({data:{}}):original(url,...args));
 triggerAnalysisJob(payload); await drain(); expect(runs.markFailed).toHaveBeenCalled(); expect(runs.markCompleted).not.toHaveBeenCalled();
});
test('persistence failure cannot approve a run', async () => {
 findings.snapshotRun.mockRejectedValueOnce(new Error('snapshot unavailable'));
 triggerAnalysisJob(payload); await drain(); expect(runs.markFailed).toHaveBeenCalled(); expect(runs.markCompleted).not.toHaveBeenCalled();
 expect(calls('/check-runs').some(([,data])=>data.conclusion==='success')).toBe(false);
});
test('an intended inline publication failure fails the run instead of approving it', async () => {
 const finding = {id:'finding1', fingerprint:'fp1', status:'open', severity:'medium', confidence:0.9,
   title:'Unsafe eval', rule_id:'code.injection.eval', category:'code injection', file_path:'app.py',
   line_start:1, line_end:1, code_snippet:'eval(user_input)', analysis_scope:'pattern', evidence:'eval detected'};
 findings.findByFingerprint.mockResolvedValueOnce(null);
 findings.upsert.mockResolvedValueOnce(finding);
 const original = axios.post.getMockImplementation();
 axios.post.mockImplementation((url,...args) => {
   if(url.includes('/pulls/files')) return Promise.resolve({data:{files:[{path:'app.py',patch:'@@ -0,0 +1 @@\n+eval(user_input)',additions:1}]}});
   if(url.includes('/files/content')) return Promise.resolve({data:{files:[{path:'app.py',content:'eval(user_input)'}]}});
   if(url.includes('/tier')) return Promise.resolve({data:{findings:[finding]}});
   if(url.includes('/comments/inline')) return Promise.reject(new Error('invalid review line'));
   return original(url,...args);
 });
 triggerAnalysisJob(payload); await drain();
 expect(calls('/comments/inline')).toHaveLength(1);
 expect(runs.markFailed).toHaveBeenCalled();
 expect(runs.markCompleted).not.toHaveBeenCalled();
 expect(calls('/check-runs').some(([,data])=>data.conclusion==='success')).toBe(false);
});
