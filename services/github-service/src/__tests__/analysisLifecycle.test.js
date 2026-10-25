jest.mock('axios', () => jest.fn());
jest.mock('../quality-release.json', () => require('../../../../tests/fixtures/verified-quality-release.json'));
jest.mock('../services/githubAppAuth', () => ({getInstallationToken: jest.fn().mockResolvedValue('fixture-token'), getAppBotLogin: jest.fn().mockResolvedValue('fixture[bot]')}));
const axios = require('axios');
const {fetchPullRequestFiles, postInlineComment} = require('../services/githubInternalOperations');
const request = {repository_full_name:'owner/repo', pull_request_number:1, installation_id:1, commit_sha:'head-a'};
beforeEach(() => jest.clearAllMocks());
test('rejects a superseded queued head before retrieving files', async () => {
 axios.mockResolvedValue({data:{head:{sha:'head-b'}}});
 await expect(fetchPullRequestFiles(request)).rejects.toThrow(/superseded/i);
 expect(axios.mock.calls.some(([r]) => r.url.includes('/files?'))).toBe(false);
});
test('rejects head movement during pagination', async () => {
 axios.mockImplementation(async r => ({data:r.url.includes('/files?') ? [] : {head:{sha:axios.mock.calls.length === 1 ? 'head-a':'head-b'}}}));
 await expect(fetchPullRequestFiles(request)).rejects.toThrow(/superseded/i);
});
test('retry reuses an existing marked inline comment', async () => {
 axios.mockImplementation(async r => ({data:r.url.includes('/comments?') ? [{id:7, body:'<!-- mitig8it-finding:fp1 -->\nold', user:{type:'Bot',login:'fixture[bot]'}, path:'a.py', original_commit_id:'head-a', html_url:'fixture'}] : {head:{sha:'head-a'}}}));
 await postInlineComment({owner:'owner',repo:'repo',pr_number:1,installation_id:1,commit_sha:'head-a',path:'a.py',line:1,body:'<!-- mitig8it-finding:fp1 -->\nold'});
 expect(axios.mock.calls.some(([r]) => r.method === 'post')).toBe(false);
});
test('review retry reuses same completed review', async () => {
 const {submitPullRequestReview} = require('../services/githubInternalOperations');
 axios.mockImplementation(async r => ({data:r.url.includes('/reviews') ? [{id:9,commit_id:'head-a',body:'<!-- mitig8it-review --> run1',state:'COMMENTED',user:{type:'Bot',login:'fixture[bot]'}}] : {head:{sha:'head-a'}}}));
 const result = await submitPullRequestReview({owner:'owner',repo:'repo',pr_number:1,installation_id:1,commit_sha:'head-a',body:'<!-- mitig8it-review --> run1',event:'COMMENT'});
 expect(result.review_id).toBe(9);
 expect(axios.mock.calls.some(([r]) => r.method === 'post')).toBe(false);
});
test('an identical review body still posts when it carries comments the pull request lacks', async () => {
 // The Action submits its new inline comments inside the review. A run whose comments failed
 // after its body succeeded has to be able to post them on a retry rather than match the body,
 // return the old review and drop every comment on the floor.
 const {submitPullRequestReview} = require('../services/githubInternalOperations');
 axios.mockImplementation(async r => ({data:r.url.includes('/reviews') ? (r.method === 'post' ? {id:11} : [{id:9,commit_id:'head-a',body:'<!-- mitig8it-review --> run1',state:'COMMENTED',user:{type:'Bot',login:'fixture[bot]'}}]) : {head:{sha:'head-a'}}}));
 const result = await submitPullRequestReview({owner:'owner',repo:'repo',pr_number:1,installation_id:1,commit_sha:'head-a',body:'<!-- mitig8it-review --> run1',event:'COMMENT',comments:[{path:'a.py',line:3,body:'<!-- mitig8it-finding:fp1 -->\nnew'}]});
 expect(result.comments_posted).toBe(1);
 const posted = axios.mock.calls.filter(([r]) => r.method === 'post' && r.url.includes('/reviews'));
 expect(posted).toHaveLength(1);
 expect(posted[0][0].data.comments).toEqual([{path:'a.py',line:3,side:'RIGHT',body:'<!-- mitig8it-finding:fp1 -->\nnew'}]);
});
test('superseded review cannot dismiss newer blocking feedback', async () => {
 const {submitPullRequestReview} = require('../services/githubInternalOperations');
 axios.mockResolvedValue({data:{head:{sha:'head-b'}}});
 await expect(submitPullRequestReview({owner:'owner',repo:'repo',pr_number:1,installation_id:1,commit_sha:'head-a',body:'<!-- mitig8it-review --> run1',event:'COMMENT'})).rejects.toThrow(/superseded/i);
 expect(axios.mock.calls.every(([r]) => r.method === 'get')).toBe(true);
});
test('gRPC binary contract preserves queued commit SHA', () => {
 const clientPb = require('../../../api-service/src/grpc/generated/github_pb');
 const serverPb = require('../grpc/generated/github_pb');
 const request = new clientPb.FetchPullRequestFilesRequest(); request.setCommitSha('immutable-head');
 expect(serverPb.FetchPullRequestFilesRequest.deserializeBinary(request.serializeBinary()).getCommitSha()).toBe('immutable-head');
});
// A re-analysis of the same head re-renders the finding comment. The verified fix
// sections published under it belong to that finding at that head, so they survive.
const FIX_BLOCK = '<!-- mitig8it-fix:cand-1 -->\n---\n**Recommended fix (verified in a development sandbox)**\n\n```suggestion\nsafe();\n```\n<!-- /mitig8it-fix:cand-1 -->';
function inlineCommentGitHub(body) {
 const comment = {id:7, body, user:{type:'Bot',login:'fixture[bot]'}, path:'a.py', html_url:'fixture'};
 axios.mockImplementation(async r => {
  if (r.url.includes('/comments?')) return {data:[comment]};
  if (r.method === 'patch') { comment.body = r.data.body; return {data:{id:7}}; }
  return {data:{head:{sha:'head-a'}}};
 });
 return comment;
}
test('re-analysis of the same finding keeps the verified fix sections under the rewritten comment', async () => {
 const comment = inlineCommentGitHub(`<!-- mitig8it-finding:fp1 -->\nold text\n\n${FIX_BLOCK}`);
 await postInlineComment({owner:'owner',repo:'repo',pr_number:1,installation_id:1,commit_sha:'head-a',path:'a.py',line:1,body:'<!-- mitig8it-finding:fp1 -->\nnew text'});
 expect(comment.body).toBe(`<!-- mitig8it-finding:fp1 -->\nnew text\n\n${FIX_BLOCK}`);
 expect(comment.body.match(/<!-- mitig8it-fix:/g)).toHaveLength(1);
 expect(axios.mock.calls.some(([r]) => r.method === 'post')).toBe(false);
});
test('several preserved fix sections are carried over in order and an unchanged body is never written', async () => {
 const second = FIX_BLOCK.replace(/cand-1/g, 'cand-2');
 const comment = inlineCommentGitHub(`<!-- mitig8it-finding:fp1 -->\nnew text\n\n${FIX_BLOCK}\n\n${second}`);
 await postInlineComment({owner:'owner',repo:'repo',pr_number:1,installation_id:1,commit_sha:'head-a',path:'a.py',line:1,body:'<!-- mitig8it-finding:fp1 -->\nnew text'});
 expect(comment.body).toBe(`<!-- mitig8it-finding:fp1 -->\nnew text\n\n${FIX_BLOCK}\n\n${second}`);
 expect(axios.mock.calls.some(([r]) => r.method === 'patch')).toBe(false);
});
test('a fix section is never carried onto another finding, and a moved head publishes nothing at all', async () => {
 const comment = inlineCommentGitHub(`<!-- mitig8it-finding:fp1 -->\nold text\n\n${FIX_BLOCK}`);
 // Another fingerprint matches no existing comment, so a fresh one is created without it.
 await postInlineComment({owner:'owner',repo:'repo',pr_number:1,installation_id:1,commit_sha:'head-a',path:'a.py',line:1,body:'<!-- mitig8it-finding:fp2 -->\nother finding'});
 const posted = axios.mock.calls.find(([r]) => r.method === 'post');
 expect(posted[0].data.body).toBe('<!-- mitig8it-finding:fp2 -->\nother finding');
 expect(comment.body).toBe(`<!-- mitig8it-finding:fp1 -->\nold text\n\n${FIX_BLOCK}`);

 jest.clearAllMocks();
 axios.mockResolvedValue({data:{head:{sha:'head-b'}}});
 await expect(postInlineComment({owner:'owner',repo:'repo',pr_number:1,installation_id:1,commit_sha:'head-a',path:'a.py',line:1,body:'<!-- mitig8it-finding:fp1 -->\nnew text'})).rejects.toThrow(/superseded/i);
 expect(axios.mock.calls.every(([r]) => r.method === 'get')).toBe(true);
});
// The comments of findings a run no longer annotates. Informational findings in test code
// are why this exists: the analysis stopped posting them, and what earlier runs left is a
// comment with nothing behind it. The finding stays open, so nothing else removes it.
const {retireInlineComments} = require('../services/githubInternalOperations');
function reviewComments(comments) {
 const remaining = [...comments];
 axios.mockImplementation(async r => {
  if (r.url.includes('/comments?')) return {data: /[?&]page=1(&|$)/.test(r.url) ? comments : []};
  if (r.method === 'delete') { remaining.splice(remaining.findIndex(c => r.url.endsWith(`/${c.id}`)), 1); return {data:{}}; }
  return {data:{head:{sha:'head-a'}}};
 });
 return remaining;
}
const ours = (id, body) => ({id, body, user:{type:'Bot',login:'fixture[bot]'}, path:'a.py'});
test('the inline comment of a named finding is deleted and every other comment is left alone', async () => {
 const remaining = reviewComments([
  ours(1, '<!-- mitig8it-finding:fp-info -->\n**INFORMATIONAL - TEST CODE** - Hardcoded credential'),
  ours(2, '<!-- mitig8it-finding:fp-runtime -->\nSQL injection'),
  {id:3, body:'<!-- mitig8it-finding:fp-info -->\nsomeone else said this', user:{type:'User',login:'reviewer'}, path:'a.py'},
 ]);
 expect(await retireInlineComments({owner:'owner',repo:'repo',pr_number:1,installation_id:1,fingerprints:['fp-info']}))
  .toEqual({retired:1, kept:0});
 expect(remaining.map(c => c.id)).toEqual([2, 3]);
});
// A verified fix published under a finding is reviewer-visible work. Housekeeping does not
// take it away, and says it did not.
test('a comment carrying a published fix is kept', async () => {
 const remaining = reviewComments([ours(1, `<!-- mitig8it-finding:fp-info -->\nold text\n\n${FIX_BLOCK}`)]);
 expect(await retireInlineComments({owner:'owner',repo:'repo',pr_number:1,installation_id:1,fingerprints:['fp-info']}))
  .toEqual({retired:0, kept:1});
 expect(remaining.map(c => c.id)).toEqual([1]);
});
test('no fingerprints means no GitHub call at all', async () => {
 axios.mockImplementation(async () => { throw new Error('no request may be made'); });
 expect(await retireInlineComments({owner:'owner',repo:'repo',pr_number:1,installation_id:1,fingerprints:[]}))
  .toEqual({retired:0, kept:0});
 expect(axios).not.toHaveBeenCalled();
});
// The comment a published fix leaves behind once the finding is gone. It is kept, and it says
// the fix was applied, instead of reading as an open critical finding with a suggestion block
// whose content is now the line it sits on.
const {markFixesApplied, fixAppliedBody, withPreservedFixBlocks} = require('../services/githubInternalOperations');
function patchableComments(comments) {
 const patches = [];
 axios.mockImplementation(async r => {
  if (r.url.includes('/comments?')) return {data: /[?&]page=1(&|$)/.test(r.url) ? comments : []};
  if (r.method === 'patch') { patches.push({id: Number(r.url.split('/').pop()), body: r.data.body}); return {data:{}}; }
  return {data:{head:{sha:'head-a'}}};
 });
 return patches;
}
const OPEN_FINDING = '<!-- mitig8it-finding:fp-fixed -->\n**SQL injection in `query`**\nSeverity: critical\nBuild the statement with parameters.\n\n' + FIX_BLOCK;
test('the comment of a finding whose fix was applied is rewritten to say so', async () => {
 const patches = patchableComments([
  ours(1, OPEN_FINDING),
  ours(2, '<!-- mitig8it-finding:fp-open -->\n**Still here**\n\n' + FIX_BLOCK),
  ours(3, '<!-- mitig8it-finding:fp-fixed -->\n**A finding with no fix published**'),
  {id:4, body:OPEN_FINDING, user:{type:'User',login:'reviewer'}, path:'a.py'},
 ]);
 expect(await markFixesApplied({owner:'owner',repo:'repo',pr_number:1,installation_id:1,fingerprints:['fp-fixed'],head_sha:'0123456789abcdef0123456789abcdef01234567'}))
  .toEqual({applied:1, unchanged:0});
 expect(patches.map(p => p.id)).toEqual([1]);
 const body = patches[0].body;
 expect(body).toBe([
  '<!-- mitig8it-finding:fp-fixed -->',
  '<!-- mitig8it-fix-applied:cand-1 -->',
  '**Fixed: SQL injection in `query`**',
  'The re-analysis of `0123456` no longer reports this finding. The suggested fix that was here has been withdrawn, so there is nothing left to commit.',
 ].join('\n'));
 expect(body).not.toMatch(/suggestion|Severity|critical|<!-- mitig8it-fix:/);
});
test('a comment already in the applied form is left alone, so a re-run writes nothing', async () => {
 const applied = fixAppliedBody(OPEN_FINDING, 'head-a');
 const patches = patchableComments([ours(1, applied)]);
 expect(await markFixesApplied({owner:'owner',repo:'repo',pr_number:1,installation_id:1,fingerprints:['fp-fixed']}))
  .toEqual({applied:0, unchanged:1});
 expect(patches).toEqual([]);
 expect(applied).toContain('The latest re-analysis no longer reports this finding.');
});
test('housekeeping keeps an applied-form comment the way it keeps a fix block', async () => {
 const remaining = reviewComments([ours(1, fixAppliedBody(OPEN_FINDING, 'head-a'))]);
 expect(await retireInlineComments({owner:'owner',repo:'repo',pr_number:1,installation_id:1,fingerprints:['fp-fixed']}))
  .toEqual({retired:0, kept:1});
 expect(remaining.map(c => c.id)).toEqual([1]);
});
test('a finding that comes back is re-rendered over the applied form without inheriting it', () => {
 const fresh = '<!-- mitig8it-finding:fp-fixed -->\n**SQL injection in `query`**\nSeverity: critical';
 expect(withPreservedFixBlocks(fresh, fixAppliedBody(OPEN_FINDING, 'head-a'))).toBe(fresh);
});
test('marking fixes applied with no fingerprints makes no GitHub call', async () => {
 axios.mockImplementation(async () => { throw new Error('no request may be made'); });
 expect(await markFixesApplied({owner:'owner',repo:'repo',pr_number:1,installation_id:1,fingerprints:[]}))
  .toEqual({applied:0, unchanged:0});
 expect(axios).not.toHaveBeenCalled();
});
// The adapter lists every analysable file of the pull request in path order. The review
// cap (200) is applied by the control plane after the repository's `.mitig8it.yml`
// exclusions, which the adapter does not know: capping here first let excluded vendored
// files take every place under the cap, so a run could review none of the real files.
function filesPage(total) {
 // GitHub paginates 100 at a time; the filenames are deliberately out of order so the
 // test proves the sort rather than GitHub's own ordering.
 const all = Array.from({length: total}, (_, i) => ({filename: `src/file-${String(total - i).padStart(4, '0')}.py`, status: 'added', patch: '+x=1'}));
 return (url) => {
  const page = Number(/[?&]page=(\d+)/.exec(url)?.[1] || 1);
  return all.slice((page - 1) * 100, page * 100);
 };
}

test('a pull request over 200 files is listed whole, for the control plane to cap after exclusions', async () => {
 const page = filesPage(250);
 axios.mockImplementation(async r => ({data: r.url.includes('/files?') ? page(r.url) : {head: {sha: 'head-a'}}}));
 const result = await fetchPullRequestFiles(request);
 expect(result.files).toHaveLength(250);
 expect(result.limitation).toBeUndefined();
});

test('the listed files are in path order, whatever order GitHub returned', async () => {
 const page = filesPage(250);
 axios.mockImplementation(async r => ({data: r.url.includes('/files?') ? page(r.url) : {head: {sha: 'head-a'}}}));
 const first = await fetchPullRequestFiles(request);
 const paths = first.files.map(f => f.path);
 expect(paths).toEqual([...paths].sort());
 expect(paths[0]).toBe('src/file-0001.py');

 jest.clearAllMocks();
 const shuffled = filesPage(250);
 axios.mockImplementation(async r => ({data: r.url.includes('/files?') ? [...shuffled(r.url)].reverse() : {head: {sha: 'head-a'}}}));
 const second = await fetchPullRequestFiles(request);
 expect(second.files.map(f => f.path)).toEqual(paths);
});

// A changed file over 500 KB is left out of the content response, and that is the only
// reason a requested path is ever left out: the control plane reads an absent path as
// "too large", reports it as not analysed and carries on. So anything else that would
// silently drop a path is refused instead.
describe('file content size limit', () => {
 const {fetchFileContents} = require('../services/githubInternalOperations');
 const contentRequest = paths => ({repository_full_name: 'owner/repo', installation_id: 1, ref: 'head-a', paths});
 const encoded = text => Buffer.from(text, 'utf8').toString('base64');

 test('a file over 500 KB is omitted and the others are returned', async () => {
  const big = 'x'.repeat(600 * 1024);
  axios.mockImplementation(async r => ({data: r.url.includes('/contents/big.js')
   ? {size: big.length, encoding: 'base64', content: encoded(big)}
   : {size: 5, encoding: 'base64', content: encoded('ok=1\n')}}));
  const result = await fetchFileContents(contentRequest(['big.js', 'small.js']));
  expect(result.files).toEqual([{path: 'small.js', content: 'ok=1\n'}]);
 });

 test('a file over 1 MB, which GitHub returns without content, is omitted rather than read as empty', async () => {
  axios.mockImplementation(async () => ({data: {size: 2 * 1024 * 1024, encoding: 'none', content: ''}}));
  const result = await fetchFileContents(contentRequest(['huge.js']));
  expect(result.files).toEqual([]);
 });

 test('an invalid path or more than 200 paths is refused, never silently dropped', async () => {
  axios.mockImplementation(async () => ({data: {size: 1, encoding: 'base64', content: encoded('x')}}));
  await expect(fetchFileContents(contentRequest(['ok.js', '']))).rejects.toMatchObject({statusCode: 400});
  await expect(fetchFileContents(contentRequest(Array.from({length: 201}, (_, i) => `f${i}.js`))))
   .rejects.toMatchObject({statusCode: 400});
  expect(axios).not.toHaveBeenCalled();
 });
});

test('a pull request at or under 200 files declares no limitation', async () => {
 const page = filesPage(200);
 axios.mockImplementation(async r => ({data: r.url.includes('/files?') ? page(r.url) : {head: {sha: 'head-a'}}}));
 const result = await fetchPullRequestFiles(request);
 expect(result.files).toHaveLength(200);
 expect(result.limitation).toBeUndefined();
});

test('dist/ and node_modules paths are never listed as analysable', async () => {
 // 150 analysable files plus 150 that the dist/ and node_modules filters drop.
 const analysable = Array.from({length: 150}, (_, i) => ({filename: `src/${String(i).padStart(4, '0')}.py`, status: 'added', patch: '+x=1'}));
 const excluded = [
  ...Array.from({length: 75}, (_, i) => ({filename: `dist/${i}.js`, status: 'added', patch: '+x=1'})),
  ...Array.from({length: 75}, (_, i) => ({filename: `a/node_modules/${i}.js`, status: 'added', patch: '+x=1'})),
 ];
 const all = [...analysable, ...excluded];
 axios.mockImplementation(async r => {
  if (!r.url.includes('/files?')) return {data: {head: {sha: 'head-a'}}};
  const pageNumber = Number(/[?&]page=(\d+)/.exec(r.url)?.[1] || 1);
  return {data: all.slice((pageNumber - 1) * 100, pageNumber * 100)};
 });
 const result = await fetchPullRequestFiles(request);
 expect(result.files).toHaveLength(150);
 expect(result.limitation).toBeUndefined();
});

test('a deleted file is not analysable and is never listed', async () => {
 const all = [
  ...Array.from({length: 210}, (_, i) => ({filename: `del/${i}.py`, status: 'removed', patch: ''})),
  ...Array.from({length: 5}, (_, i) => ({filename: `src/${i}.py`, status: 'modified', patch: '+x=1'})),
 ];
 axios.mockImplementation(async r => {
  if (!r.url.includes('/files?')) return {data: {head: {sha: 'head-a'}}};
  const pageNumber = Number(/[?&]page=(\d+)/.exec(r.url)?.[1] || 1);
  return {data: all.slice((pageNumber - 1) * 100, pageNumber * 100)};
 });
 const result = await fetchPullRequestFiles(request);
 expect(result.files.map(f => f.path).sort()).toEqual(['src/0.py', 'src/1.py', 'src/2.py', 'src/3.py', 'src/4.py']);
 expect(result.limitation).toBeUndefined();
});
test('check retries update only this app check for the same head', async () => {
 const {createCheckRun}=require('../services/githubInternalOperations'); process.env.GITHUB_APP_ID='123';
 axios.mockImplementation(async r=>({data:r.method==='get'?{check_runs:[{id:77,head_sha:'head-a',app:{id:123},name:'Mitig8it Security Review'}]}:{id:77}}));
 await createCheckRun({owner:'owner',repo:'repo',installation_id:1,head_sha:'head-a',conclusion:'success',title:'clean',summary:'clean'});
 expect(axios.mock.calls.some(([r])=>r.method==='patch' && r.url.endsWith('/check-runs/77'))).toBe(true);
 expect(axios.mock.calls.some(([r])=>r.method==='post')).toBe(false);
});

describe('the repair snapshot and workflow files', () => {
  // nebullii/test-only#136: six workflow findings produced a job that failed its snapshot
  // stage with "Finding source is unsupported or missing from the immutable tree", because
  // the snapshot selected sources by suffix and no suffix covers a workflow. A `.yml`
  // outside `.github/workflows/` stays out: it is ordinary YAML, not a repair target.
  const isWorkflowPath = path => /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(path);

  test('a workflow file is a snapshot source and other yaml is not', () => {
    for (const carried of [
      '.github/workflows/release.yml',
      '.github/workflows/nightly.yaml',
      'packages/app/.github/workflows/ci.yml',
    ]) expect(isWorkflowPath(carried)).toBe(true);
    for (const excluded of [
      'docker-compose.yml',
      '.github/dependabot.yml',
      'k8s/deploy.yml',
      'config/workflows/pipeline.yml',
      '.github/workflows/nested/deep.yml',
    ]) expect(isWorkflowPath(excluded)).toBe(false);
  });

  test('the shipped filter carries a workflow', () => {
    const source = require('fs').readFileSync(
      require('path').join(__dirname, '../services/githubInternalOperations.js'), 'utf8');
    expect(source).toContain('isWorkflowPath(entry.path)');
    const declared = source.match(/const isWorkflowPath = path => (\/.*\/i)\.test\(path\)/);
    expect(declared).not.toBeNull();
    expect(declared[1]).toBe(String(isWorkflowPath.toString().match(/(\/.*\/i)\.test/)[1]));
  });
});
