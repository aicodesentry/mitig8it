"""Real temporary Git preregistration; no production cases, signatures, or approvals."""
from __future__ import annotations

import copy
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks.remediation import corpus_intake as intake
from benchmarks.remediation import release_evidence as evidence
from benchmarks.remediation.tests.test_corpus_intake import candidate, commit, manifest, prepare, registered


@pytest.fixture
def population(candidate, manifest):
    # This temporary population has no legacy static-assertion fixtures. Preserve
    # every statistical floor, but do not pretend it contains the real seed's IDs.
    manifest = copy.deepcopy(manifest)
    manifest['release_abstentions'] = {}
    registration, registration_path, registration_revision = registered(candidate, manifest)
    root = candidate['repository']
    corpus = root/'benchmarks/remediation/fixtures'
    corpus.mkdir(parents=True)
    shutil.copytree(candidate['directory'], corpus/'one')
    policy = root/'benchmarks/remediation/release/intake-origins.json'
    policy.write_text(json.dumps(candidate['origins']))
    source_revision = commit(root, 'admit previously frozen test-only inputs', '2026-02-02T00:00:00Z')
    case = registration['cases'][0]
    evaluation = {'started_at': '2026-03-01T00:00:00Z', 'finished_at': '2026-03-01T00:01:00Z',
        'preregistrations': intake.release_preregistrations(root, source_revision),
        'results': [{key: case[key] for key in ('fixture_id', 'repository_id', 'split', 'kind', 'family')}
                    | {'outcome': 'passed', 'observed_state': 'ready', 'verification_level': 'independent_sandbox'}]}
    return {'root': root, 'corpus': corpus, 'policy': policy, 'manifest': manifest, 'revision': source_revision,
            'registration': registration, 'registration_path': registration_path,
            'registration_revision': registration_revision, 'evaluation': evaluation}


def validate(population):
    return intake.validate_release_intake(repository=population['root'], fixture_root=population['corpus'],
        source_revision=population['revision'], manifest=population['manifest'], evaluation=population['evaluation'],
        origin_policy_path=population['policy'])


def test_complete_current_population_requires_actual_committed_pre_result_inputs(population):
    result = validate(population)
    assert result['fixture_count'] == 1
    assert result['population'] == 'complete_committed_preregistrations'
    assert result['registrations_digest'] == evidence.digest(population['evaluation']['preregistrations'])
    assert not {'passed', 'production_ready', 'review_approved'}.intersection(result)


def test_current_authored_seed_has_no_retroactive_intake_exception():
    revision = intake.git(intake.ROOT, 'rev-parse', 'HEAD').decode().strip()
    with pytest.raises(intake.IntakeError, match='committed_preregistration_required_for_release'):
        intake.validate_release_intake(repository=intake.ROOT, fixture_root=intake.HERE/'fixtures',
            source_revision=revision, manifest=evidence.read_json(intake.HERE/'release-manifest.json'),
            evaluation={}, origin_policy_path=intake.HERE/'release/intake-origins.json')


@pytest.mark.parametrize('mutation,reason', [
    ('missing_registration', 'evaluation_must_bind_complete_committed_preregistrations'),
    ('different_registration_digest', 'evaluation_must_bind_complete_committed_preregistrations'),
    ('different_introduction_revision', 'evaluation_must_bind_complete_committed_preregistrations'),
    ('before_registration', 'results_not_after_committed_preregistration'),
    ('missing_fixture', 'empty_fixture_inventory'),
    ('invalid_fixture', 'full_release_fixture_validation_required'),
    ('reference_changed', 'preregistered_inputs_changed'),
    ('origin_missing', 'unreadable_evidence_document'),
])
def test_signable_result_metadata_is_not_intake_proof(population, mutation, reason):
    evaluation = population['evaluation']
    if mutation == 'missing_registration':
        evaluation.pop('preregistrations')
    elif mutation == 'different_registration_digest':
        evaluation['preregistrations'][0]['digest'] = 'sha256:' + '0'*64
    elif mutation == 'different_introduction_revision':
        evaluation['preregistrations'][0]['revision'] = population['revision']
    elif mutation == 'before_registration':
        evaluation['started_at'] = '2026-01-31T00:00:00Z'
    elif mutation == 'missing_fixture':
        shutil.rmtree(population['corpus']/'one')
    elif mutation == 'invalid_fixture':
        path = population['corpus']/'one/fixture.json'
        metadata = json.loads(path.read_text())
        metadata.pop('verification_checks')
        path.write_text(json.dumps(metadata))
    elif mutation == 'reference_changed':
        (population['corpus']/'one/expected/app.py').write_text('# changed after preregistration\n')
    else:
        population['policy'].unlink()
    with pytest.raises((intake.IntakeError, evidence.ReleaseEvidenceError), match=reason):
        validate(population)


def test_registered_case_cannot_already_be_in_baseline_at_registration_commit(candidate, manifest):
    registration = prepare(candidate, manifest)
    root = candidate['repository']
    path = root/intake.LEDGER/'retroactive.json'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(registration))
    corpus = root/'benchmarks/remediation/fixtures'
    corpus.mkdir(parents=True)
    shutil.copytree(candidate['directory'], corpus/'already-seen')
    policy = root/'benchmarks/remediation/release/intake-origins.json'
    policy.write_text(json.dumps(candidate['origins']))
    revision = commit(root, 'attempt same-commit retrospective intake', '2026-02-02T00:00:00Z')
    case = registration['cases'][0]
    evaluation = {'preregistrations': intake.release_preregistrations(root, revision),
        'started_at': '2026-03-01T00:00:00Z', 'finished_at': '2026-03-01T00:01:00Z',
        'results': [{key: case[key] for key in ('fixture_id', 'repository_id', 'split', 'kind', 'family')}]}
    with pytest.raises(intake.IntakeError, match='fixture_identity_reused'):
        intake.validate_release_intake(repository=root, fixture_root=corpus, source_revision=revision,
            manifest=manifest, evaluation=evaluation, origin_policy_path=policy)


def test_unregistered_extra_fixture_cannot_inflate_signed_counts(population):
    extra = population['corpus']/'unregistered'
    shutil.copytree(population['corpus']/'one', extra)
    metadata = json.loads((extra/'fixture.json').read_text())
    metadata.update(id='unregistered-extra', repository_id='synthetic-unregistered')
    (extra/'fixture.json').write_text(json.dumps(metadata))
    row = copy.deepcopy(population['evaluation']['results'][0])
    row.update(fixture_id=metadata['id'], repository_id=metadata['repository_id'])
    population['evaluation']['results'].append(row)
    with pytest.raises(intake.IntakeError, match='unregistered_release_fixtures_forbidden_no_legacy_exception'):
        validate(population)


def test_unused_registered_population_cannot_be_cherry_picked(population):
    registration = copy.deepcopy(population['registration'])
    case = copy.deepcopy(registration['cases'][0])
    case.update(fixture_id='omitted-unfavorable-case', repository_id='omitted-repository')
    case['lineage_keys'] = sorted(['repository:omitted-repository', 'upstream:https://example.invalid/omitted/repo',
                                  'upstream_revision:'+'f'*40])
    registration['cases'].append(case)
    # An additional committed batch is mandatory even if an evaluator omits it.
    path = population['registration_path'].parent/'omitted-batch.json'
    registration['cases'] = [case]
    path.write_text(json.dumps(registration))
    population['revision'] = commit(population['root'], 'append test-only omitted population', '2026-02-03T00:00:00Z')
    population['evaluation']['preregistrations'] = intake.release_preregistrations(population['root'], population['revision'])
    with pytest.raises(intake.IntakeError, match='registered_population_missing_or_reused'):
        validate(population)


def test_historical_inventory_is_reconstructed_from_git_not_a_claimed_baseline(population):
    before = intake.inventory_at_revision(population['root'], 'benchmarks/remediation/fixtures', population['registration_revision'])
    after = intake.inventory_at_revision(population['root'], 'benchmarks/remediation/fixtures', population['revision'])
    assert before == {} and set(after) == {'test-only-case-001'}


def test_production_origin_policy_cannot_be_an_external_symlink(population):
    target = population['root']/'external-origin-policy.json'
    population['policy'].rename(target)
    population['policy'].symlink_to(target)
    with pytest.raises(intake.IntakeError, match='release_intake_origin_policy_symlink_forbidden'):
        validate(population)


def signed_bundle(population, monkeypatch, *, intake_binding=None, reviewer='independent-test-reviewer'):
    """Real ephemeral signature, deliberately insufficient statistical test population."""
    identity = {'provider_id': 'test-provider', 'model_id': 'test-model', 'configuration': {'temperature': 0},
        'sandbox_image_digest': 'registry.invalid/sandbox@sha256:'+'a'*64,
        'service_image_digest': 'registry.invalid/service@sha256:'+'b'*64}
    evaluation = population['evaluation']
    evaluation.update(schema_version='v1', suite='release', adapter='engine', provider_kind='live-provider',
                      results_kind='repair_quality', source_revision=population['revision'], evaluation_identity=identity)
    for result in evaluation['results']:
        result.update(expected_state='ready', reason=None, fixture_tests={'passed': True}, usage={}, elapsed_ms=1,
            limitations=[], repair_evidence={'candidates': [{'path': 'app.py', 'replacement_content': 'safe()\n'}],
                'request_versions': {'repair_model': identity['model_id'], 'repair_service_image': identity['service_image_digest']},
                'requested_sandbox_image_digest': identity['sandbox_image_digest'],
                'evidence': {'verification_level': 'independent_sandbox'}})
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    release = population['policy'].parent
    trust = release/'trusted-keys.json'
    trust.write_text(json.dumps({'schema_version': 'v1', 'minimum_reviewers': 1, 'max_receipt_age_seconds': 3600,
        'keys': [{'key_id': 'temporary-test-key', 'reviewer_id': reviewer, 'algorithm': 'ed25519', 'status': 'active',
                  'public_key_base64': base64.b64encode(public).decode()}]}))
    identity_path = release/'evaluation-identity.json'
    identity_path.write_text(json.dumps(identity))
    now = datetime.now(timezone.utc)
    inventory = evidence.fixture_inventory(population['corpus'])
    payload = {'schema_version': 'v1', 'purpose': evidence.PURPOSE,
        **evidence.expected_bindings(source_revision=population['revision'], manifest=population['manifest'],
            fixtures=inventory, results=evaluation['results'], intake_bindings=intake_binding, **identity),
        'issued_at': (now-timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'expires_at': (now+timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'reviews': [{'fixture_id': key, 'reviewer_id': reviewer, 'verdict': 'approved', 'fixture_digest': evidence.digest(entry),
                     'result_digest': evidence.digest(evaluation['results'][0])} for key, entry in inventory.items()]}
    receipt = {'schema_version': 'v1', 'payload': payload,
        'signatures': [{'key_id': 'temporary-test-key', 'reviewer_id': reviewer, 'algorithm': 'ed25519',
                       'signature': base64.b64encode(private.sign(evidence.signing_bytes(payload))).decode()}]}
    path = release/'evidence.json'
    path.write_text(json.dumps({'schema_version': 'v1', 'evaluation': evaluation, 'receipt': receipt}))
    (release.parent/'release-manifest.json').write_text(json.dumps(population['manifest']))
    monkeypatch.setattr(evidence, 'ROOT', population['root'])
    monkeypatch.setattr(evidence, 'TRUST_STORE', trust)
    monkeypatch.setattr(evidence, 'EVALUATION_IDENTITY', identity_path)
    monkeypatch.setattr(evidence, 'INTAKE_ORIGINS', population['policy'])
    monkeypatch.setattr(evidence, 'clean_checkout_revision', lambda: population['revision'])
    return path, receipt, identity, inventory, now


def test_valid_signed_synthetic_metadata_cannot_bypass_full_fixture_validation(population, monkeypatch):
    fixture = population['corpus']/'one/fixture.json'
    metadata = json.loads(fixture.read_text())
    metadata.pop('verification_checks')
    fixture.write_text(json.dumps(metadata))
    path, receipt, identity, inventory, now = signed_bundle(population, monkeypatch)
    # Cryptographic authentication alone deliberately remains a narrower primitive.
    assert evidence.verify_release_evidence(receipt, source_revision=population['revision'], manifest=population['manifest'],
        fixtures=inventory, results=population['evaluation']['results'], trust_store_path=evidence.TRUST_STORE, now=now,
        **identity)['scope'] == 'external_review_authentication_only'
    with pytest.raises(evidence.ReleaseEvidenceError, match='committed_intake_provenance_required:full_release_fixture_validation_required'):
        evidence.load_release_admission(path, now=now)


def test_valid_signature_cannot_bypass_missing_committed_registration(population, monkeypatch):
    path, _, _, _, now = signed_bundle(population, monkeypatch)
    population['registration_path'].unlink()
    with pytest.raises(evidence.ReleaseEvidenceError, match='committed_intake_provenance_required:dirty_or_missing_intake_ledger'):
        evidence.load_release_admission(path, now=now)


def test_production_receipt_must_sign_the_recomputed_intake_binding(population, monkeypatch):
    path, _, _, _, now = signed_bundle(population, monkeypatch, intake_binding={'invented': 'not-current-ledger'})
    with pytest.raises(evidence.ReleaseEvidenceError, match='binding_mismatch:intake'):
        evidence.load_release_admission(path, now=now)


def test_real_intake_and_signature_still_cannot_waive_statistical_floors(population, monkeypatch):
    binding = validate(population)
    path, _, _, _, now = signed_bundle(population, monkeypatch, intake_binding=binding)
    with pytest.raises(evidence.ReleaseEvidenceError, match='release_statistics_failed'):
        evidence.load_release_admission(path, now=now)


def test_trusted_case_author_still_cannot_sign_their_own_case_approval(population, monkeypatch):
    binding = validate(population)
    path, _, _, _, now = signed_bundle(population, monkeypatch, intake_binding=binding, reviewer='test-case-author')
    with pytest.raises(evidence.ReleaseEvidenceError, match='fixture_author_cannot_self_approve'):
        evidence.load_release_admission(path, now=now)
