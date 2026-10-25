"""Synthetic intake records only; no case is added to the evaluated corpus."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from benchmarks.remediation import corpus_intake as intake
from benchmarks.remediation.evaluate import SUPPORTED_FAMILIES
from benchmarks.remediation.release_evidence import digest, fixture_inventory, read_json


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def commit(repository, message, date):
    subprocess.run(['git', '-C', str(repository), 'add', '.'], check=True, capture_output=True)
    environment = dict(os.environ, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    subprocess.run(['git', '-C', str(repository), '-c', 'user.name=Intake Test', '-c', 'user.email=intake@example.invalid',
                    'commit', '-m', message], env=environment, check=True, capture_output=True)
    return intake.git(repository, 'rev-parse', 'HEAD').decode().strip()


def init(repository):
    repository.mkdir(parents=True)
    subprocess.run(['git', 'init', str(repository)], check=True, capture_output=True)


@pytest.fixture
def manifest():
    return read_json(intake.HERE/'release-manifest.json')


@pytest.fixture
def candidate(tmp_path):
    repository = tmp_path/'intake-repository'
    upstream = tmp_path/'local-upstream'
    init(repository)
    init(upstream)
    raw = b'def synthetic_lookup(db, user):\n    return db.execute("SELECT * FROM test_intake WHERE id=" + user)\n'
    (upstream/'source.py').write_bytes(raw)
    revision = commit(upstream, 'synthetic upstream input', '2026-01-01T00:00:00Z')
    root = repository/'candidates'
    directory = root/'test-only-candidate'
    (directory/'tests').mkdir(parents=True)
    (directory/'expected').mkdir()
    (directory/'app.py').write_bytes(raw)
    (directory/'expected/app.py').write_text('def synthetic_lookup(db, user):\n    return db.execute("SELECT * FROM test_intake WHERE id=?", (user,))\n')
    (directory/'tests/verify.py').write_text('raise RuntimeError("intake must never execute a test")\n')
    (directory/'PROVENANCE.md').write_text('Synthetic test-only labels and behavior rubric. No independent approval.\n')
    upstream_url = 'https://example.invalid/test/intake-origin'
    provenance = {'origin': 'independent_repository', 'upstream_repository': upstream_url,
        'lineage_root': upstream_url, 'upstream_revision': revision, 'collected_at': '2026-01-02T00:00:00Z',
        'case_authors': ['test-case-author'], 'oracle_authors': ['test-oracle-author'],
        'model_outputs_observed': False,
        'source_artifacts': {'app.py': {'upstream_path': 'source.py', 'sha256': sha(raw),
            'git_blob_oid': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}},
        'oracle_artifacts': {'tests/verify.py': sha((directory/'tests/verify.py').read_bytes())},
        'review_document': 'PROVENANCE.md', 'review_document_digest': sha((directory/'PROVENANCE.md').read_bytes())}
    metadata = {'schema_version': 'v1', 'id': 'test-only-case-001', 'repository_id': 'test-only-repo-001',
        'split': 'holdout', 'kind': 'supported', 'family': 'sql_parameterization', 'expected_state': 'ready',
        'source': 'app.py', 'reference_repair': 'expected/app.py', 'finding': {'id': 'test-finding'},
        'budget': {'max_tool_calls': 20, 'max_attempts': 3, 'max_input_tokens': 120000,
                   'max_output_tokens': 120000, 'max_cost_usd': 2},
        'trusted_fixture_test': {'runtime': 'python3', 'path': 'tests/verify.py', 'timeout_seconds': 10},
        'verification_checks': [{'check_id': kind, 'kind': kind, 'argv': ['python3', 'tests/verify.py', '--' + kind],
            'timeout_seconds': 10, 'expected_baseline': 'failed' if kind == 'exploit' else 'passed',
            'expected_candidate': 'passed'} for kind in ('exploit', 'behavior')],
        'intake_provenance': provenance}
    (directory/'fixture.json').write_text(json.dumps(metadata))
    return {'repository': repository, 'candidate_root': root, 'directory': directory,
            'origins': {upstream_url: str(upstream)}, 'metadata': metadata}


def prepare(candidate, manifest, baseline=None, history=None):
    return intake.preregister(manifest=manifest, baseline=baseline or {},
        candidates=fixture_inventory(candidate['candidate_root']), candidate_root=candidate['candidate_root'],
        origins=candidate['origins'], registered_at='2026-02-01T00:00:00Z', history=history)


def rewrite(candidate):
    (candidate['directory']/'fixture.json').write_text(json.dumps(candidate['metadata']))


def registered(candidate, manifest):
    registration = prepare(candidate, manifest)
    path = candidate['repository']/intake.LEDGER/'batch-001.json'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(registration))
    revision = commit(candidate['repository'], 'freeze pre-result intake', '2026-02-01T00:00:01Z')
    return registration, path, revision


def validate(candidate, manifest, registration, path, revision, evaluation=None):
    return intake.validate_registration(registration=registration, registration_path=path,
        registration_revision=revision, repository=candidate['repository'], manifest=manifest, baseline={},
        candidates=fixture_inventory(candidate['candidate_root']), candidate_root=candidate['candidate_root'],
        origins=candidate['origins'], evaluation=evaluation)


def evaluation_for(registration, revision):
    return {'registration_digest': digest(registration), 'registration_revision': revision, 'source_revision': revision,
            'started_at': '2026-03-01T00:00:00Z', 'finished_at': '2026-03-01T00:01:00Z',
            'results': [{key: case[key] for key in ('fixture_id', 'repository_id', 'split', 'kind', 'family', 'fixture_digest')}
                        | {'outcome': 'failed'} for case in registration['cases']]}


def test_real_manifest_plan_separates_case_floors_from_holdout_capacity(manifest):
    before = copy.deepcopy(manifest)
    report = intake.plan_corpus(manifest, fixture_inventory(intake.HERE/'fixtures'), SUPPORTED_FAMILIES)
    assert report['counts']['total'] == 81
    assert report['counts']['by_kind'] == {'supported': 67, 'negative': 10, 'adversarial': 4}
    assert report['counts']['by_split']['holdout']['by_kind'] == {'supported': 17, 'negative': 2, 'adversarial': 2}
    assert report['deficits']['supported_by_family'] == {'code_injection_eval': 16, 'command_arguments': 7,
        'cookie_flags': 12, 'hardcoded_credential': 10, 'password_hashing': 12, 'path_containment': 9, 'sql_parameterization': 7}
    assert report['deficits']['headline_minimum_cases'] == 39
    assert report['deficits']['effective_total_minimum'] == 200
    assert report['deficits']['additional_cases_for_family_and_kind_floors'] == 119
    assert report['deficits']['holdout_publishable_capacity'] == 15
    assert report['deficits']['additional_holdout_publication_capacity'] == 85
    assert report['deficits']['additional_cases_for_holdout_strata'] == 179
    assert report['deficits']['holdout_by_kind'] == {'negative': 28, 'adversarial': 28}
    assert sum(report['deficits']['holdout_supported_by_family'].values()) == 123
    assert report['deficits']['additional_cases_without_resplitting_or_reusing_lineage'] == 179
    assert all(item['preferred_split'] == 'holdout' for item in report['intake_requests'])
    assert report['production_ready'] is False
    assert all(case['review_approved'] is False for case in report['review_queue'])
    assert manifest == before


def test_intake_binds_real_local_git_blobs_and_never_executes_oracle(candidate, manifest):
    registration = prepare(candidate, manifest)
    assert registration['status'] == 'preregistered_pending_independent_review'
    assert registration['cases'][0]['source_digests']['app.py'] == candidate['metadata']['intake_provenance']['source_artifacts']['app.py']['sha256']
    assert registration['cases'][0]['oracle_digests']['tests/verify.py']
    assert not {'results', 'passed', 'production_ready', 'approved'}.intersection(registration)


@pytest.mark.parametrize('mutation,reason', [
    ('source_digest', 'source_digest_mismatch'), ('source_blob', 'source_blob_oid_mismatch'),
    ('oracle_digest', 'oracle_digest_mismatch'), ('review_digest', 'review_document_binding_mismatch'),
    ('missing_oracle', 'oracle_provenance_coverage_mismatch'), ('same_authors', 'case_and_oracle_authors_must_be_distinct'),
    ('outputs_seen', 'independent_pre_result_inputs_required'), ('late_collection', 'source_collected_after_preregistration'),
    ('before_commit_collection', 'source_collected_before_upstream_commit'), ('results_present', 'results_cannot_be_preregistered'),
])
def test_unproven_changed_or_post_result_inputs_are_rejected(candidate, manifest, mutation, reason):
    provenance = candidate['metadata']['intake_provenance']
    if mutation == 'source_digest':
        provenance['source_artifacts']['app.py']['sha256'] = 'sha256:' + '0'*64
    elif mutation == 'source_blob':
        provenance['source_artifacts']['app.py']['git_blob_oid'] = '0'*40
    elif mutation == 'oracle_digest':
        provenance['oracle_artifacts']['tests/verify.py'] = 'sha256:' + '0'*64
    elif mutation == 'review_digest':
        provenance['review_document_digest'] = 'sha256:' + '0'*64
    elif mutation == 'missing_oracle':
        provenance['oracle_artifacts'] = {}
    elif mutation == 'same_authors':
        provenance['oracle_authors'] = provenance['case_authors'][:]
    elif mutation == 'outputs_seen':
        provenance['model_outputs_observed'] = True
    elif mutation == 'late_collection':
        provenance['collected_at'] = '2026-03-01T00:00:00Z'
    elif mutation == 'before_commit_collection':
        provenance['collected_at'] = '2025-01-01T00:00:00Z'
    else:
        candidate['metadata']['results'] = []
    rewrite(candidate)
    with pytest.raises(intake.IntakeError, match=reason):
        prepare(candidate, manifest)


def test_no_origin_is_fetched_and_missing_local_provenance_fails(candidate, manifest):
    candidate['origins'] = {}
    with pytest.raises(intake.IntakeError, match='upstream_checkout_required_no_fetch'):
        prepare(candidate, manifest)


def test_upstream_bytes_cannot_be_replaced_even_when_claimed_hashes_are_updated(candidate, manifest):
    raw = b'print("a different source not present in the pinned upstream")\n'
    (candidate['directory']/'app.py').write_bytes(raw)
    artifact = candidate['metadata']['intake_provenance']['source_artifacts']['app.py']
    artifact.update(sha256=sha(raw), git_blob_oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
    rewrite(candidate)
    with pytest.raises(intake.IntakeError, match='upstream_source_not_regular_matching_blob'):
        prepare(candidate, manifest)


@pytest.mark.parametrize('reuse', ['id', 'lineage', 'source'])
def test_existing_cases_cannot_be_renamed_or_resplit_to_inflate_holdout(candidate, manifest, reuse):
    entry = copy.deepcopy(next(iter(fixture_inventory(candidate['candidate_root']).values())))
    if reuse != 'id':
        entry['metadata']['id'] = 'older-case'
        entry['metadata']['repository_id'] = 'older-repository'
    if reuse == 'source':
        entry['metadata'].pop('intake_provenance')  # Even a legacy source without lineage metadata is protected.
    else:
        entry['files']['app.py'] = 'sha256:' + '0'*64
    entry['metadata']['split'] = 'train'
    baseline = {entry['metadata']['id']: entry}
    with pytest.raises(intake.IntakeError, match='reused|leakage'):
        prepare(candidate, manifest, baseline=baseline)


def test_committed_registration_emits_unsigned_review_queue_and_binds_failed_results(candidate, manifest):
    registration, path, revision = registered(candidate, manifest)
    report = validate(candidate, manifest, registration, path, revision, evaluation_for(registration, revision))
    assert report['scope'] == 'intake_integrity_only' and report['production_ready'] is False
    assert report['review_queue'][0]['review_approved'] is False
    assert report['review_queue'][0]['status'] == 'awaiting_independent_review'
    assert report['review_queue'][0]['result_available'] is True


@pytest.mark.parametrize('mutation,reason', [
    ('earlier_result', 'results_not_after_committed_preregistration'), ('split', 'result_preregistered_identity_mismatch'),
    ('duplicate_result', 'intake_results_missing_duplicate_or_unexpected'), ('missing_result', 'intake_results_missing_duplicate_or_unexpected'),
    ('digest', 'evaluation_registration_binding_mismatch'),
])
def test_results_cannot_precede_or_redefine_preregistered_cases(candidate, manifest, mutation, reason):
    registration, path, revision = registered(candidate, manifest)
    evaluation = evaluation_for(registration, revision)
    if mutation == 'earlier_result':
        evaluation['started_at'] = '2026-01-01T00:00:00Z'
    elif mutation == 'split':
        evaluation['results'][0]['split'] = 'train'
    elif mutation == 'duplicate_result':
        evaluation['results'].append(copy.deepcopy(evaluation['results'][0]))
    elif mutation == 'missing_result':
        evaluation['results'] = []
    else:
        evaluation['registration_digest'] = 'sha256:' + '0'*64
    with pytest.raises(intake.IntakeError, match=reason):
        validate(candidate, manifest, registration, path, revision, evaluation)


def test_changed_case_or_oracle_invalidates_committed_registration(candidate, manifest):
    registration, path, revision = registered(candidate, manifest)
    (candidate['directory']/'expected/app.py').write_text('# changed reference repair\n')
    with pytest.raises(intake.IntakeError, match='preregistered_inputs_changed'):
        validate(candidate, manifest, registration, path, revision)


def test_uncommitted_or_rewritten_registration_is_rejected(candidate, manifest):
    registration, path, revision = registered(candidate, manifest)
    registration['registered_at'] = '2026-01-15T00:00:00Z'
    path.write_text(json.dumps(registration))
    with pytest.raises(intake.IntakeError, match='registration_not_identical'):
        validate(candidate, manifest, registration, path, revision)


def test_append_only_ledger_cannot_forget_committed_lineage(candidate, manifest):
    registration, path, revision = registered(candidate, manifest)
    assert intake.ledger_history(candidate['repository']) == [registration]
    path.unlink()
    commit(candidate['repository'], 'attempt to delete a prior registration', '2026-03-01T00:00:00Z')
    with pytest.raises(intake.IntakeError, match='committed_intake_ledger_is_not_append_only'):
        intake.ledger_history(candidate['repository'])


def test_registered_history_prevents_reusing_a_case_before_it_enters_corpus(candidate, manifest):
    previous = prepare(candidate, manifest)
    candidate['metadata']['id'] = 'renamed-new-case'
    candidate['metadata']['repository_id'] = 'renamed-new-repository'
    rewrite(candidate)
    with pytest.raises(intake.IntakeError, match='lineage_reused'):
        prepare(candidate, manifest, history=[previous])


def test_admitted_case_remains_valid_in_both_baseline_and_append_only_history(candidate, manifest):
    previous = prepare(candidate, manifest)
    intake.assert_no_reuse(fixture_inventory(candidate['candidate_root']), {}, [previous])


def test_empty_or_approval_spoofed_registration_history_is_rejected(candidate, manifest):
    previous = prepare(candidate, manifest)
    empty = dict(previous, cases=[])
    with pytest.raises(intake.IntakeError, match='empty_intake_history'):
        intake.assert_no_reuse({}, {}, [empty])
    approved = dict(previous, status='approved')
    with pytest.raises(intake.IntakeError, match='invalid_intake_history'):
        intake.assert_no_reuse({}, {}, [approved])


def test_manifest_or_frozen_baseline_change_invalidates_registration(candidate, manifest):
    registration, path, revision = registered(candidate, manifest)
    changed = dict(manifest, minimum_cases=manifest['minimum_cases'] + 1)
    with pytest.raises(intake.IntakeError, match='preregistered_inputs_changed'):
        validate(candidate, changed, registration, path, revision)


def test_later_ledger_append_does_not_redefine_an_earlier_batch(candidate, manifest):
    registration, path, revision = registered(candidate, manifest)
    later = copy.deepcopy(registration)
    later['cases'][0]['fixture_id'] = 'synthetic-later-batch'
    (path.parent/'batch-002.json').write_text(json.dumps(later))
    commit(candidate['repository'], 'append a later test-only batch', '2026-04-01T00:00:00Z')
    assert validate(candidate, manifest, registration, path, revision)['validated_cases'] == 1


def test_edited_committed_ledger_is_refused_even_under_new_commit(candidate, manifest):
    registration, path, revision = registered(candidate, manifest)
    registration['cases'][0]['split'] = 'train'
    path.write_text(json.dumps(registration))
    commit(candidate['repository'], 'attempt to edit frozen split', '2026-03-01T00:00:00Z')
    with pytest.raises(intake.IntakeError, match='committed_intake_ledger_is_not_append_only'):
        intake.ledger_history(candidate['repository'])


def test_evaluation_from_unrelated_git_history_is_not_preregistered(candidate, manifest):
    registration, path, revision = registered(candidate, manifest)
    subprocess.run(['git', '-C', str(candidate['repository']), 'checkout', '--orphan', 'unrelated-evaluation'],
                   check=True, capture_output=True)
    unrelated = commit(candidate['repository'], 'unrelated test evaluation tree', '2026-03-01T00:00:00Z')
    evaluation = evaluation_for(registration, revision)
    evaluation['source_revision'] = unrelated
    with pytest.raises(intake.IntakeError, match='local_git_provenance_unavailable'):
        validate(candidate, manifest, registration, path, revision, evaluation)


@pytest.mark.parametrize('value', ['https://user:secret@example.invalid/org/repo', 'https://example.invalid/org/repo?token=secret',
                                  'ssh://example.invalid/org/repo', 'https://example.invalid/org/../repo'])
def test_credential_urls_and_unsafe_origins_are_rejected(value):
    with pytest.raises(intake.IntakeError):
        intake.repo_url(value)


def test_symlinked_inputs_never_enter_inventory(candidate, manifest):
    target = candidate['directory']/'app.py'
    raw = target.read_bytes()
    target.unlink()
    other = candidate['repository']/'outside.py'
    other.write_bytes(raw)
    target.symlink_to(other)
    with pytest.raises(ValueError, match='fixture_symlink_not_allowed'):
        prepare(candidate, manifest)


def test_cli_plan_reads_manifest_and_emits_only_unapproved_queue(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', ['corpus_intake', 'plan'])
    assert intake.main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report['deficits']['additional_cases_for_family_and_kind_floors'] == 119
    assert report['deficits']['additional_cases_without_resplitting_or_reusing_lineage'] == 179
    assert report['production_ready'] is False


def test_cli_refuses_to_overwrite_an_intake_artifact(monkeypatch, capsys, tmp_path):
    output = tmp_path/'existing.json'
    original = 'KEEP THIS INTAKE ARTIFACT'
    output.write_text(original)
    monkeypatch.setattr('sys.argv', ['corpus_intake', 'plan', '--output', str(output)])
    assert intake.main() == 2
    report = json.loads(capsys.readouterr().out)
    assert report['reason_code'] == 'refusing_to_overwrite_intake_artifact'
    assert original not in json.dumps(report)
    assert output.read_text() == original
