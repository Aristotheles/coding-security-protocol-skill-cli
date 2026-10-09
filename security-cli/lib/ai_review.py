"""M6 advisory review. Never applies patches, verifies fixes or grants approval."""
import json
import re

from . import policy
from .doctor import ConfigError
from .normalize import ContractError, read_json, schema_validator
from .scan import timestamp
from .storage_io import atomic_json


def review_proposal(root, config, author, patch_request, proposal, patch, folder):
    from .ai_patch import MAX_BYTES, ProviderFailure, invoke, sha
    policies = policy.load_policy(root)
    sensitive = any(p['id'] == 'POL-006' and any(
        policy.path_matches(path, pattern) for path in proposal['changed_files'] for pattern in p['paths'])
        for p in policies)
    result = dict(advisory=True, status=None, reviewer_source=None, reviewer_trust=None,
                  confidence='REDUCED', terminal_state='human_review', attempts=[],
                  human_review_required=author['trust'] == 'restricted' or sensitive)
    request = dict(version=1, task='review', finding_id=patch_request['finding']['id'],
                   patch_source=author['id'], patch_sha256=sha(patch),
                   unified_diff=proposal['unified_diff'], patch_request=patch_request)
    schema_validator(root/'schemas/ai-review-request.schema.json').validate(request)
    validator = schema_validator(root/'schemas/ai-review-response.schema.json')
    serialized = json.dumps(request)
    # An author may inject a credential into the diff: do not forward it to review.
    credential = re.compile(r'(?i)(-----BEGIN .*PRIVATE KEY-----|(?:api[_-]?key|password|passwd|secret|token)\s*[:=]\s*[\x22\x27][^\x22\x27]+|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|sk-proj-[A-Za-z0-9_-]{30,})')
    if len(serialized.encode('utf-8')) > MAX_BYTES or credential.search(proposal['unified_diff']):
        result.update(human_review_required=True, detail='review context unsafe or exceeds bound')
        return result
    reviewers = [p for p in config['ai']['providers'] if p['enabled'] and
                 'review' in p.get('roles', ['patch','review']) and p['id'] != author['id'] and
                 not (p['adapter'] == author['adapter'] == 'codex')]
    for number, reviewer in enumerate(reviewers):
        directory = folder/('review-'+str(number))
        directory.mkdir()
        attempt = dict(provider=reviewer['id'], model=reviewer.get('model'), trust=reviewer['trust'],
                       started_at=timestamp(), response_validation='NOT_CHECKED')
        result['attempts'].append(attempt)
        try:
            response = invoke(root, reviewer, request, directory, task='review')
            if not validator.is_valid(response):
                raise ContractError('review_schema_violation')
            attempt['response_validation'] = 'SCHEMA_VALID'
            if any(response[key] != request[key] for key in ('finding_id','patch_source','patch_sha256')):
                raise ContractError('review_patch_binding_mismatch')
            if response['reviewer_source'] != reviewer['id']:
                raise ContractError('reviewer_source_mismatch')
            attempt.update(result=response['status'], response_validation='VALIDATED', fallback_reason=None)
            result.update(status=response['status'], reviewer_source=reviewer['id'],
                          reviewer_trust=reviewer['trust'], confidence='INDEPENDENT_ADVISORY',
                          response_reference=(directory/'response.json').relative_to(root).as_posix(),
                          patch_sha256=request['patch_sha256'])
            # Disagreement is a valid opinion, not a reason to hunt for an approval.
            required = result['human_review_required'] or response['status'] != 'APPROVE' or reviewer['trust'] == 'restricted'
            result.update(human_review_required=required,
                          terminal_state='human_review' if required else 'advisory_reviewed')
            break
        except (ProviderFailure, ContractError, ConfigError) as exc:
            attempt.update(result='REJECTED_OUTPUT', fallback_reason=str(exc))
        except OSError:
            attempt.update(result='REJECTED_OUTPUT', fallback_reason='tool_error')
        finally:
            metadata = directory/'provider-metadata.json'
            if metadata.is_file():
                attempt['model'] = read_json(metadata)['model']
            attempt['finished_at'] = timestamp()
            atomic_json(directory/'attempt.json', attempt)
    if result['status'] is None:
        result['detail'] = 'no valid independent reviewer; confidence reduced; human review when policy/trust requires'
    return result
