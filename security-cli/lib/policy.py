"""POL-001..007 evaluation only. No evidence producer, approval or finding closure."""
from datetime import datetime, timezone
import fnmatch
import hashlib
import math
from pathlib import Path, PurePosixPath
import sqlite3
import uuid

from .doctor import ConfigError, load_yaml, validate_config, validate_policy
from .normalize import ContractError, RUN_ID, read_json, safe_path
from .storage_io import atomic_json, store_lock
from . import store
from .gate_audit import load_audits, queued_keys

EVIDENCE = ('static_scan', 'tests', 'security_rescan', 'runtime_verify')
ACTIVE = ('OPEN', 'REOPENED', 'PATCH_PROPOSED', 'VERIFYING')
TARGETS = ('security_report', 'finding_owner', 'responsible_team', 'security_lead')


def utc_time(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ContractError('UTC timestamp required')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ContractError('invalid UTC timestamp') from exc
    if result.utcoffset().total_seconds() != 0:
        raise ContractError('UTC timestamp required')
    return result


def text(value):
    return isinstance(value, str) and bool(value.strip()) and not any(ord(c) < 32 for c in value)


def load_policy(root):
    data = load_yaml(root / '.security/policies/security-policy.yml')
    validate_policy(data)
    allowed = {
        'POL-001': {'events', 'severities', 'statuses'},
        'POL-002': {'events'}, 'POL-003': {'sbom_diff_when_enabled'},
        'POL-004': set(), 'POL-005': {'events'}, 'POL-006': {'paths'},
        'POL-007': {'severities', 'statuses', 'stages'},
    }
    for item in data['policies']:
        pid = item['id']
        if set(item) != {'id', 'name', 'action'} | allowed[pid]:
            raise ConfigError('missing or unknown policy condition fields: ' + pid)
        for key, enum in (('events', ('merge', 'release')), ('severities', ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                          ('statuses', ACTIVE)):
            if key in item and (not isinstance(item[key], list) or not item[key] or
                               any(v not in enum for v in item[key]) or len(set(item[key])) != len(item[key])):
                raise ConfigError('invalid policy filter: ' + pid)
        if pid == 'POL-003' and type(item['sbom_diff_when_enabled']) is not bool:
            raise ConfigError('invalid SBOM policy flag')
        if pid == 'POL-006':
            if not isinstance(item['paths'], list) or not item['paths'] or any(not text(p) or '\\' in p or p.startswith('/') or '..' in p.split('/') for p in item['paths']):
                raise ConfigError('invalid security-sensitive path patterns')
        if pid == 'POL-007':
            stages = item['stages']
            if not isinstance(stages, list) or len(stages) != 3:
                raise ConfigError('three escalation stages required')
            for stage in stages:
                if not isinstance(stage, dict) or set(stage) != {'days', 'targets'} or type(stage['days']) is not int:
                    raise ConfigError('invalid escalation stage')
                if not isinstance(stage['targets'], list) or not stage['targets'] or any(t not in TARGETS for t in stage['targets']) or len(set(stage['targets'])) != len(stage['targets']):
                    raise ConfigError('invalid escalation targets')
            if [s['days'] for s in stages] != [30, 60, 90] or item['action'] != 'WARNING':
                raise ConfigError('unsupported escalation timing or hard-block action')
    return data['policies']


def portable_path(value):
    if not text(value) or '\\' in value or ':' in value or value.startswith('/') or any(p in ('', '.', '..') for p in value.split('/')):
        raise ContractError('changed files must be portable project-relative paths')
    return value


def validate_context(data):
    required = {'version', 'event', 'changed_files', 'dependencies', 'patch', 'coverage', 'evidence'}
    if not isinstance(data, dict) or set(data) != required or type(data['version']) is not int or data['version'] != 1 or data['event'] not in ('merge', 'release'):
        raise ContractError('invalid gate context fields or event')
    if not isinstance(data['changed_files'], list):
        raise ContractError('changed_files must be a list')
    for p in data['changed_files']:
        portable_path(p)
    dep = data['dependencies']
    if not isinstance(dep, dict) or set(dep) != {'lockfiles_changed', 'added', 'sbom_enabled', 'sbom_diff'}:
        raise ContractError('dependency diff missing')
    if not isinstance(dep['lockfiles_changed'], list) or not isinstance(dep['added'], list) or any(not text(n) for n in dep['added']) or type(dep['sbom_enabled']) is not bool:
        raise ContractError('invalid dependency diff')
    for p in dep['lockfiles_changed']:
        portable_path(p)
        if p not in data['changed_files']:
            raise ContractError('lockfile change missing from changed_files')
    if dep['sbom_diff'] is not None and not isinstance(dep['sbom_diff'], dict):
        raise ContractError('invalid SBOM evidence reference')
    patch = data['patch']
    if not isinstance(patch, dict) or set(patch) != {'source', 'trust', 'finding_ids', 'rescan_run_id'} or patch['source'] not in ('human', 'ai', 'none') or patch['trust'] not in ('standard', 'restricted'):
        raise ContractError('invalid patch metadata')
    if not isinstance(patch['finding_ids'], list) or any(not store.SEC_ID.fullmatch(i) for i in patch['finding_ids'] if isinstance(i, str)) or any(not isinstance(i, str) for i in patch['finding_ids']):
        raise ContractError('invalid patch finding IDs')
    if patch['source'] == 'ai' and (not patch['finding_ids'] or not text(patch['rescan_run_id'])):
        raise ContractError('AI patch needs finding IDs and rescan run')
    coverage = data['coverage']
    if not isinstance(coverage, dict) or set(coverage) != {'enabled', 'before', 'after'} or type(coverage['enabled']) is not bool:
        raise ContractError('invalid coverage configuration')
    if coverage['enabled'] and any(type(coverage[k]) not in (float, int) or not math.isfinite(coverage[k]) or not 0 <= coverage[k] <= 100 for k in ('before', 'after')):
        raise ContractError('configured coverage metrics required')
    if not isinstance(data['evidence'], dict) or any(k not in EVIDENCE for k in data['evidence']):
        raise ContractError('invalid evidence classes')
    return data


def reference(root, record):
    if not isinstance(record, dict) or not text(record.get('raw_reference')) or not isinstance(record.get('sha256'), str) or len(record['sha256']) != 64:
        raise ContractError('evidence reference and SHA256 required')
    path = safe_path(root, record['raw_reference'], '.security')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != record['sha256']:
        raise ContractError('evidence reference hash mismatch')
    return path


def evidence_issues(root, context, config, now):
    issues = []
    for name in EVIDENCE:
        record = context['evidence'].get(name)
        if record is None:
            issues.append(name + ': missing')
            continue
        if not isinstance(record, dict) or record.get('type') != name or not text(record.get('source')):
            raise ContractError('invalid evidence record')
        if utc_time(record.get('timestamp')) > now:
            raise ContractError('future evidence timestamp')
        state = record.get('state')
        if state not in ('PASS', 'FAIL', 'WAIVED', 'NOT_APPLICABLE'):
            raise ContractError('unknown evidence state')
        path = reference(root, record)
        if state == 'FAIL':
            issues.append(name + ': failed')
        elif state == 'PASS':
            if name in ('static_scan', 'security_rescan'):
                # Scanner PASS is based on the actual M1/M2 evidence envelope,
                # not a caller's arbitrary PASS receipt.
                from .normalize import load_normalized
                scan_report = read_json(path)
                if not isinstance(scan_report, dict) or not isinstance(scan_report.get('run_id'), str) or not RUN_ID.fullmatch(scan_report['run_id']):
                    raise ContractError('scanner evidence needs a valid scan run')
                validated = load_normalized(root, scan_report.get('run_id'))
                expected = root / '.security/reports' / (validated['run_id'] + '-scan-report.json')
                if path != expected:
                    raise ContractError('scanner evidence must reference its scan report')
                if record['timestamp'] != validated['observed_at']:
                    raise ContractError('scanner evidence timestamp does not match scan completion')
                if name == 'security_rescan' and context['patch']['rescan_run_id'] is not None and validated['run_id'] != context['patch']['rescan_run_id']:
                    raise ContractError('patch rescan and evidence rescan differ')
                continue
            # A bare PASS string is insufficient. The referenced producer receipt
            # must agree and attest a completed deterministic tool execution.
            receipt = read_json(path)
            for key in ('type', 'state', 'timestamp', 'source'):
                if receipt.get(key) != record[key]:
                    raise ContractError('evidence/producer receipt mismatch')
            if type(receipt.get('exit_code')) is not int or receipt['exit_code'] != 0 or receipt.get('timed_out') is not False or receipt.get('completed') is not True:
                issues.append(name + ': tool did not complete successfully')
        elif name != 'runtime_verify':
            issues.append(name + ': waiver/not-applicable not permitted')
        elif state == 'NOT_APPLICABLE':
            if config['runtime_verify']['mode'] != 'not_applicable' or not text(record.get('reason')):
                issues.append(name + ': not-applicable not justified by config')
        else:
            waiver = read_json(path)
            if waiver.get('actor_type') != 'human' or not text(waiver.get('approved_by')) or not text(waiver.get('reason')) or utc_time(waiver.get('approved_at')) > now:
                issues.append(name + ': human waiver invalid')
            if any(record.get(k) != waiver.get(k) for k in ('approved_by', 'approved_at', 'reason')):
                issues.append(name + ': waiver metadata mismatch')
    return issues


def path_matches(path, pattern):
    # **/auth/** also covers root-level auth/, unlike plain fnmatch.
    return PurePosixPath(path).match(pattern) or fnmatch.fnmatchcase(path, pattern) or (pattern.startswith('**/') and fnmatch.fnmatchcase(path, pattern[3:]))


def evaluate(root, policies, findings, context, now, previous):
    matches, notifications = [], []
    by_id = {f['id']: f for f in findings}
    for f in findings:
        if utc_time(f['first_seen']) > now or utc_time(f['last_seen']) > now:
            raise ContractError('future canonical observation')
        if f['status'] == 'ACCEPTED_RISK':
            # M3 does not implement an approval/accepted-risk workflow.
            raise ContractError('accepted risk requires a human approval contract')
    patch = context['patch']
    if any(i not in by_id for i in patch['finding_ids']):
        raise ContractError('patch refers to unknown canonical finding')
    # Canonical proposal provenance cannot be downgraded by caller metadata.
    proposals = [f.get('patch_proposal') for f in findings if f.get('patch_proposal') and
                 (f['id'] in patch['finding_ids'] or f['location']['path'] in context['changed_files'])]
    if proposals:
        patch = dict(patch, source='ai')
        if any(p.get('trust') == 'restricted' for p in proposals):
            patch['trust'] = 'restricted'
        if not patch['rescan_run_id']:
            raise ContractError('AI proposal requires deterministic rescan')

    def hit(p, reason, ids=None, **extra):
        matches.append(dict(policy_id=p['id'], action=p['action'], reason=reason, finding_ids=ids or [], **extra))

    for p in policies:
        if 'events' in p and context['event'] not in p['events']:
            continue
        pid = p['id']
        if pid == 'POL-001':
            selected = [f['id'] for f in findings if f['severity'] in p['severities'] and
                        (f['status'] in p['statuses'] or f['status'] in ('PATCH_PROPOSED', 'VERIFYING'))]
            if selected:
                hit(p, 'active critical findings on release', selected)
        elif pid == 'POL-002' and patch['source'] == 'ai':
            from .normalize import load_normalized
            rescan = load_normalized(root, patch['rescan_run_id'])
            reported = {f['fingerprint'] for f in rescan['findings']}
            selected = [i for i in patch['finding_ids'] if by_id[i]['fingerprint'] in reported]
            if selected:
                hit(p, 'AI patch findings remain on validated rescan', selected)
        elif pid == 'POL-003':
            d = context['dependencies']
            if d['lockfiles_changed'] and d['added']:
                hit(p, 'new dependency with lockfile change requires human review')
                if p['sbom_diff_when_enabled'] and d['sbom_enabled']:
                    if d['sbom_diff'] is None:
                        hit(p, 'enabled SBOM diff evidence missing')
                    else:
                        reference(root, d['sbom_diff'])
        elif pid == 'POL-004' and patch['source'] == 'ai':
            c = context['coverage']
            if c['enabled'] and c['after'] < c['before']:
                hit(p, 'AI patch reduces configured coverage', delta=c['after']-c['before'])
        elif pid == 'POL-005':
            selected = []
            for f in findings:
                if f['category'] != 'hardcoded-secret':
                    continue
                rem = f.get('remediation', {})
                confirmed = rem.get('rotation_confirmed') is True and text(rem.get('confirmed_by')) and rem.get('confirmed_at') is not None
                if confirmed:
                    confirmed = utc_time(rem['confirmed_at']) <= now
                if f['status'] != 'CLOSED' or rem.get('rotation_required', True) and not confirmed:
                    selected.append(f['id'])
            if selected:
                hit(p, 'open secret or incomplete required rotation', selected, playbook='.security/playbooks/secret-leak.md')
        elif pid == 'POL-006':
            selected = [path for path in context['changed_files'] if any(path_matches(path, pat) for pat in p['paths'])]
            if selected:
                hit(p, 'security-critical path requires human review', changed_files=selected)
        elif pid == 'POL-007':
            for f in findings:
                if f['severity'] not in p['severities'] or f['status'] not in p['statuses']:
                    continue
                age = (now - utc_time(f['first_seen'])).days
                stages = [s for s in p['stages'] if age >= s['days']]
                if not stages:
                    continue
                stage = stages[-1]
                hit(p, 'stale high-risk finding', [f['id']], age_days=age, stage=stage['days'], targets=stage['targets'])
                for target in stage['targets']:
                    key = (f['id'], stage['days'], target)
                    if key not in previous:
                        notifications.append(dict(finding_id=f['id'], stage=stage['days'], target=target,
                            status='QUEUED', attempted_at=None, delivered_at=None, error=None))
                        previous.add(key)
    if patch['source'] == 'ai' and patch['trust'] == 'restricted':
        matches.append(dict(policy_id='TRUST', action='REVIEW_REQUIRED', reason='restricted-trust patch requires human review', finding_ids=patch['finding_ids']))
    if any(p.get('review') and p.get('human_review_required') for p in proposals):
        matches.append(dict(policy_id='AI_REVIEW', action='REVIEW_REQUIRED',
                            reason='canonical AI review requires human review; advisory approval cannot satisfy it',
                            finding_ids=patch['finding_ids']))
    return matches, notifications


def run_gate(root, context_file=None, event=None, _closure_proof=None):
    root = Path(root).resolve()
    now = datetime.now(timezone.utc)
    run_id = now.strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex
    report = dict(project='Coding Security Protocol', command='gate', audit_version=1,
                  run_id=run_id, timestamp=now.isoformat(timespec='seconds').replace('+00:00', 'Z'),
                  notifications=[], policies=[], evidence_issues=[], finding_closure=False)
    path = root / '.security/reports' / (run_id + '-gate-report.json')
    if not path.parent.is_dir() or path.parent.is_symlink() or not path.parent.resolve().is_relative_to(root):
        report.update(result='CONTRACT_ERROR', exit_code=50, detail='unsafe or missing gate report directory')
        return report
    try:
        with store_lock(root):
            policies = load_policy(root)
            config = validate_config(load_yaml(root / 'security.config.yml'))
            findings = store.load_findings(root)
            canonical_findings = findings
            previous = queued_keys(load_audits(root))
            if context_file is None:
                # Evaluate current findings, but no success without explicit change/evidence input.
                context = dict(version=1, event=event or 'release', changed_files=[],
                    dependencies=dict(lockfiles_changed=[], added=[], sbom_enabled=False, sbom_diff=None),
                    patch=dict(source='none', trust='standard', finding_ids=[], rescan_run_id=None),
                    coverage=dict(enabled=False, before=None, after=None), evidence={})
                issues = ['gate context missing']
            else:
                input_path = safe_path(root, str(context_file))
                context = validate_context(read_json(input_path))
                if event and context['event'] != event:
                    raise ContractError('CLI event/context event mismatch')
                report['input_reference'] = input_path.relative_to(root).as_posix()
                report['input_sha256'] = hashlib.sha256(input_path.read_bytes()).hexdigest()
                issues = []
            issues += evidence_issues(root, context, config, now)
            if _closure_proof is not None:
                from .verify import closure_candidates
                findings, proof = closure_candidates(root, _closure_proof, context)
                report.update(closure_candidates=proof['finding_ids'],
                              closure_proof_reference=_closure_proof,
                              closure_proof_sha256=hashlib.sha256(safe_path(root, _closure_proof, '.security/evidence').read_bytes()).hexdigest())
            matches, notifications = evaluate(root, policies, findings, context, now, previous)
            # A deterministic block remains a block even when other evidence is missing.
            actions = {m['action'] for m in matches}
            result = 'BLOCK' if 'BLOCK' in actions else 'VERIFY_ERROR' if issues else 'REVIEW_REQUIRED' if 'REVIEW_REQUIRED' in actions else 'PASS'
            code = {'PASS': 0, 'BLOCK': 10, 'REVIEW_REQUIRED': 20, 'VERIFY_ERROR': 60}[result]
            report.update(result=result, exit_code=code, event=context['event'], policies=matches, evidence_issues=issues,
                policy_sha256=hashlib.sha256((root / '.security/policies/security-policy.yml').read_bytes()).hexdigest())
            # Only real decisions enqueue/audit, never incomplete-evidence success.
            if result in ('PASS', 'BLOCK', 'REVIEW_REQUIRED'):
                report['notifications'] = notifications
            atomic_json(path, report)
            if result in ('PASS', 'BLOCK', 'REVIEW_REQUIRED'):
                # Prospective closure is only a policy view; never write that
                # view into the canonical-derived DB before core closure.
                store.write_index(root, canonical_findings)
                report['audit_indexed'] = True
    except ConfigError:
        report.update(result='CONFIG_ERROR', exit_code=30, detail='missing, unreadable or invalid required configuration')
    except (OSError, sqlite3.Error) as exc:
        report.update(result='TOOL_ERROR', exit_code=40, detail=type(exc).__name__)
    except Exception as exc:
        report.update(result='CONTRACT_ERROR', exit_code=50, detail=type(exc).__name__)
    # An audit write failure must not return a PASS. A committed decision report is
    # retained if indexing fails, so findings rebuild-index can recover it.
    if not path.exists():
        try:
            atomic_json(path, report)
        except OSError:
            report.update(result='TOOL_ERROR', exit_code=40, detail='gate report could not be persisted')
    report['report_reference'] = path.relative_to(root).as_posix()
    return report
