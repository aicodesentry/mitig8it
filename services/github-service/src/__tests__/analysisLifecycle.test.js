jest.mock('axios', () => jest.fn());
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
test('oversized file scope cannot be silently truncated', async () => {
 axios.mockImplementation(async r => ({data:r.url.includes('/files?') ? Array.from({length:r.url.endsWith('page=3')?1:100},(_,i)=>({filename:`src/${i}.py`,status:'added',patch:'+x=1'})) : {head:{sha:'head-a'}}}));
 await expect(fetchPullRequestFiles(request)).rejects.toThrow(/limit/i);
});
test('check retries update only this app check for the same head', async () => {
 const {createCheckRun}=require('../services/githubInternalOperations'); process.env.GITHUB_APP_ID='123';
 axios.mockImplementation(async r=>({data:r.method==='get'?{check_runs:[{id:77,head_sha:'head-a',app:{id:123},name:'Mitig8it Security Review'}]}:{id:77}}));
 await createCheckRun({owner:'owner',repo:'repo',installation_id:1,head_sha:'head-a',conclusion:'success',title:'clean',summary:'clean'});
 expect(axios.mock.calls.some(([r])=>r.method==='patch' && r.url.endsWith('/check-runs/77'))).toBe(true);
 expect(axios.mock.calls.some(([r])=>r.method==='post')).toBe(false);
});
