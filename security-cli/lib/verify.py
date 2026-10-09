"""Deterministic evidence collector. Only verified, policy-approved core closes JSON."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import uuid

from .doctor import ConfigError, load_yaml, validate_config
from .normalize import ContractError, RUN_ID, load_normalized, normalize, read_json, safe_path, schema_validator
from .scan import execute, executable_path, profile_inputs, run_scan, timestamp
from .storage_io import atomic_json
from . import policy, store

IGNORED = {'.git', '.security', '.tools', '.agent', '.serena', '.venv', '__pycache__',
           'node_modules', '.pytest_cache', '.gradle', 'build', 'dist', 'coverage'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def json_ref(root, path, value):
    atomic_json(path, value)
    return dict(raw_reference=path.relative_to(root).as_posix(), sha256=sha(path))


def canonical_hashes(root):
    return {p.name: sha(p) for p in sorted((root / '.security/findings').glob('*.json'))}


def source_hashes(root, target, extra):
    selected = set(extra)
    start = safe_path(root, target)
    if start.is_file():
        selected.add(start.relative_to(root).as_posix())
    elif start.is_dir():
        for directory, dirs, files in os.walk(start):
            dirs[:] = [d for d in dirs if d not in IGNORED]
            for name in files:
                if not name.endswith(('.pyc', '.pyo')):
                    selected.add((Path(directory) / name).relative_to(root).as_posix())
    else:
        raise ContractError('verification target missing')
    return {name: sha(path) if path.is_file() else None for name in sorted(selected)
            for path in (safe_path(root, name),)}


def command_evidence(root, folder, name, profile):
    out = folder / (name + '.stdout.log')
    err = folder / (name + '.stderr.log')
    receipt = dict(type=name, state='FAIL', source='security-verify-command', run_id=folder.name,
                   started_at=timestamp(), completed=False, timed_out=False, exit_code=None)
    try:
        executable = executable_path(root, profile['argv'][0])
        if not executable:
            raise FileNotFoundError('configured executable unavailable')
        argv = [executable] + profile['argv'][1:]
        receipt['argv'] = argv
        code, timeout = execute(argv, root, profile['timeout_seconds'], out, err)
        receipt.update(exit_code=code, timed_out=timeout, completed=True,
                       state='PASS' if code == 0 and not timeout else 'FAIL')
    except OSError as exc:
        receipt['error'] = type(exc).__name__
    receipt['timestamp'] = timestamp()
    for key, path in (('stdout', out), ('stderr', err)):
        if path.exists():
            receipt[key] = dict(raw_reference=path.relative_to(root).as_posix(), sha256=sha(path))
    path = folder / (name + '-receipt.json')
    record = {k: receipt[k] for k in ('type', 'state', 'source', 'run_id', 'timestamp')}
    record.update(json_ref(root, path, receipt))
    return record, bool(receipt.get('error'))


def scan_evidence(root, target, name, ids, folder):
    report = run_scan(root, target)
    ref = root / '.security/reports' / (report['run_id'] + '-scan-report.json')
    if not ref.exists():
        atomic_json(ref, report)
    record = dict(type=name, source='security-verify-scanners', state='FAIL',
                  run_id=report['run_id'], timestamp=report.get('finished_at', timestamp()),
                  raw_reference=ref.relative_to(root).as_posix(), sha256=sha(ref))
    remaining = []
    if report['exit_code'] == 0:
        normalize(root, report['run_id'])
        data = load_normalized(root, report['run_id'])
        fps = {f['fingerprint'] for f in data['findings']}
        remaining = [f['id'] for f in ids if f['fingerprint'] in fps]
        record.update(state='FAIL' if name == 'security_rescan' and remaining else 'PASS',
                      unresolved_ids=remaining)
    return record, report['exit_code'] == 40


def baseline_proof(root, findings, rescan_run_id):
    """Prove original tools/rules still cover the same target, without rereading old
    snippets against fixed code (the historical normalized snapshot is preserved)."""
    rescan = read_json(root / '.security/reports' / (rescan_run_id + '-scan-report.json'))
    current = {s['tool']: s for s in rescan['scanners'] if s['state'] in ('CLEAN', 'FINDINGS')}
    artifacts = {}
    validator = schema_validator(Path(__file__).with_name('sarif-2.1.0.schema.json'))
    for f in findings:
        for tool in {s['tool'] for s in f['sources']}:
            if tool not in current:
                raise ContractError('original scanner was not rerun successfully')
            matched = False
            for source in reversed([s for s in f['sources'] if s['tool'] == tool]):
                raw = safe_path(root, source['raw_reference'], '.security/raw/' + tool)
                run_id = raw.stem
                if not RUN_ID.fullmatch(run_id):
                    continue
                report_path = root / '.security/reports' / (run_id + '-scan-report.json')
                normalized_path = root / '.security/sarif' / (run_id + '-normalized.json')
                if not raw.is_file() or not report_path.is_file() or not normalized_path.is_file():
                    continue
                report = read_json(report_path)
                baseline = read_json(normalized_path)
                item = next((s for s in report.get('scanners', []) if s['tool'] == tool), {})
                if report.get('exit_code') != 0 or item.get('state') != 'FINDINGS' or item.get('timed_out') is not False:
                    continue
                if item.get('profile') != current[tool]['profile'] or item.get('profile_inputs') != current[tool].get('profile_inputs') or 'profile_inputs' not in item:
                    continue
                if not item.get('version') or item.get('version') != current[tool].get('version'):
                    continue
                if item['profile_inputs'] != profile_inputs(root, item['profile']):
                    continue
                if baseline.get('input_hashes', {}).get(raw.relative_to(root).as_posix()) != sha(raw):
                    continue
                original = next((i for i in baseline.get('findings', []) if i['fingerprint'] == f['fingerprint']), None)
                if original is None or source not in original['sources']:
                    continue
                validator.validate(read_json(raw))
                for p in (raw, report_path, normalized_path):
                    artifacts[p.relative_to(root).as_posix()] = sha(p)
                matched = True
                break
            if not matched:
                raise ContractError('matching original scanner/rule evidence missing or changed')
    return artifacts


def validate_receipt(root, record, profile):
    receipt = read_json(policy.reference(root, record))
    executable = executable_path(root, profile['argv'][0])
    if not executable or receipt.get('argv') != [executable] + profile['argv'][1:]:
        raise ContractError('receipt/configured command mismatch')
    if receipt.get('state') != 'PASS' or type(receipt.get('exit_code')) is not int or receipt['exit_code'] != 0 or receipt.get('timed_out') is not False or receipt.get('completed') is not True:
        raise ContractError('command did not complete successfully')
    for name in ('stdout', 'stderr'):
        policy.reference(root, receipt[name])


def closure_candidates(root, proof_reference, context):
    """Read-only prospective policy view. It never writes a CLOSED canonical row."""
    proof_path = safe_path(root, str(proof_reference), '.security/evidence')
    proof = read_json(proof_path)
    config = validate_config(load_yaml(root / 'security.config.yml'))
    if proof.get('producer') != 'security-verify-v1' or proof.get('close_requested') is not True or not proof.get('finding_ids'):
        raise ContractError('deterministic closure proof required')
    if proof.get('config_sha256') != sha(root / 'security.config.yml') or proof.get('policy_sha256') != sha(root / '.security/policies/security-policy.yml'):
        raise ContractError('config/policy changed after verification')
    if proof.get('scanner_inputs') != {tool: profile_inputs(root, p) for tool, p in config['scanners'].items()}:
        raise ContractError('scanner rule inputs changed after verification')
    if proof.get('canonical_hashes') != canonical_hashes(root):
        raise ContractError('canonical findings changed after verification')
    if proof.get('source_hashes') != source_hashes(root, proof['target'], proof['extra_paths']):
        raise ContractError('source changed after verification')
    context_path = policy.reference(root, proof['context'])
    if read_json(context_path) != context or context['patch']['finding_ids'] != proof['finding_ids']:
        raise ContractError('closure proof and gate context differ')
    now = datetime.now(timezone.utc)
    issues = policy.evidence_issues(root, context, config, now)
    if issues:
        raise ContractError('closure evidence missing or failed')
    times = [policy.utc_time(context['evidence'][n]['timestamp']) for n in policy.EVIDENCE]
    if times != sorted(times):
        raise ContractError('required evidence order was not respected')
    validate_receipt(root, context['evidence']['tests'], config['stack']['tests'])
    runtime = context['evidence']['runtime_verify']
    if runtime['state'] == 'PASS':
        if config['runtime_verify']['mode'] != 'command':
            raise ContractError('runtime command proof required for PASS')
        validate_receipt(root, runtime, config['runtime_verify'])
    findings = store.load_findings(root)
    by_id = {f['id']: f for f in findings}
    selected = []
    for i in proof['finding_ids']:
        if i not in by_id or by_id[i]['status'] not in policy.ACTIVE:
            raise ContractError('closure target must be an active canonical finding')
        f = by_id[i]
        if f['location']['path'] not in context['changed_files']:
            raise ContractError('relevant fix path not declared')
        selected.append(f)
    rescan_run = context['patch']['rescan_run_id']
    normalized = load_normalized(root, rescan_run)
    fingerprints = {f['fingerprint'] for f in normalized['findings']}
    if any(f['fingerprint'] in fingerprints for f in selected):
        raise ContractError('finding still present after rescan')
    expected_baseline = baseline_proof(root, selected, rescan_run)
    if proof.get('baseline_artifacts') != expected_baseline:
        raise ContractError('original scanner evidence changed')
    targets = {f['id'] for f in selected}
    candidates = deepcopy(findings)
    for f in candidates:
        if f['id'] in targets:
            f['status'] = 'CLOSED'
    return candidates, proof


def run_verify(root, target='.', context_file=None, event=None, finding_id=None, close=False, waiver=None):
    root = Path(root).resolve()
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex
    folder = root / '.security/evidence' / run_id
    report = dict(project='Coding Security Protocol', command='verify', run_id=run_id,
                  started_at=timestamp(), evidence={}, closed_ids=[], canonical_written=False)
    report_path = root / '.security/reports' / (run_id + '-verify-report.json')
    try:
        for p in (folder.parent, report_path.parent):
            if not p.is_dir() or p.is_symlink() or not p.resolve().is_relative_to(root):
                raise ContractError('missing or unsafe verification output directory')
        config = validate_config(load_yaml(root / 'security.config.yml'))
        if 'stack' not in config:
            raise ConfigError('stack.tests command is required for verification')
        policy.load_policy(root)
        findings = store.load_findings(root)
        if context_file:
            context = policy.validate_context(read_json(safe_path(root, str(context_file))))
            if context['evidence']:
                raise ContractError('verify must collect its own evidence')
            if event and context['event'] != event:
                raise ContractError('CLI/context event mismatch')
        else:
            if close:
                raise ContractError('closure requires explicit change metadata input')
            context = dict(version=1, event=event or 'merge', changed_files=[],
                dependencies=dict(lockfiles_changed=[], added=[], sbom_enabled=False, sbom_diff=None),
                patch=dict(source='none', trust='standard', finding_ids=[], rescan_run_id=None),
                coverage=dict(enabled=False, before=None, after=None), evidence={})
        ids = context['patch']['finding_ids'][:]
        if finding_id:
            if not store.SEC_ID.fullmatch(finding_id) or ids and ids != [finding_id]:
                raise ContractError('finding ID/context mismatch')
            ids = [finding_id]
        by_id = {f['id']: f for f in findings}
        start = safe_path(root, target)
        if not start.exists():
            raise ContractError('scan target missing')
        if not ids:
            ids = [f['id'] for f in findings if f['status'] in policy.ACTIVE and safe_path(root, f['location']['path']).is_relative_to(start)]
        selected = []
        for i in ids:
            if i not in by_id or not safe_path(root, by_id[i]['location']['path']).is_relative_to(start):
                raise ContractError('finding unknown or outside verification target')
            selected.append(by_id[i])
            for tool in {s['tool'] for s in by_id[i]['sources']}:
                if tool not in config['scanners'] or not config['scanners'][tool]['enabled']:
                    raise ContractError('original scanner is disabled or unknown')
        if close and not ids:
            raise ContractError('explicit active closure targets required')
        if close and any(f['location']['path'] not in context['changed_files'] for f in selected):
            raise ContractError('closure requires changed path metadata')
        context['patch']['finding_ids'] = ids
        if ids and context['patch']['source'] == 'none':
            context['patch']['source'] = 'human'
        extra = context['changed_files'] + [f['location']['path'] for f in selected]
        snapshot = dict(canonical_hashes=canonical_hashes(root), source_hashes=source_hashes(root, target, extra),
                        scanner_inputs={tool: profile_inputs(root, p) for tool, p in config['scanners'].items()},
                        config_sha256=sha(root / 'security.config.yml'), policy_sha256=sha(root / '.security/policies/security-policy.yml'))
        folder.mkdir()
        evidence = report['evidence']
        evidence['static_scan'], tool_error = scan_evidence(root, target, 'static_scan', selected, folder)
        evidence['tests'], failed_tool = command_evidence(root, folder, 'tests', config['stack']['tests'])
        tool_error |= failed_tool
        evidence['security_rescan'], failed_tool = scan_evidence(root, target, 'security_rescan', selected, folder)
        tool_error |= failed_tool
        context['patch']['rescan_run_id'] = evidence['security_rescan']['run_id']
        if waiver:
            path = safe_path(root, str(waiver), '.security')
            value = read_json(path)
            if value.get('actor_type') != 'human' or not policy.text(value.get('approved_by')) or not policy.text(value.get('reason')) or policy.utc_time(value.get('approved_at')) > datetime.now(timezone.utc):
                raise ContractError('runtime waiver must have existing human approval')
            evidence['runtime_verify'] = dict(type='runtime_verify', state='WAIVED', source='human-runtime-waiver',
                run_id=run_id, timestamp=timestamp(), raw_reference=path.relative_to(root).as_posix(), sha256=sha(path),
                **{k: value[k] for k in ('approved_by', 'approved_at', 'reason')})
        elif config['runtime_verify']['mode'] == 'command':
            evidence['runtime_verify'], failed_tool = command_evidence(root, folder, 'runtime_verify', config['runtime_verify'])
            tool_error |= failed_tool
        else:
            receipt = dict(type='runtime_verify', state='NOT_APPLICABLE', source='security.config.yml',
                           run_id=run_id, timestamp=timestamp(), reason='runtime_verify.mode is explicitly not_applicable')
            evidence['runtime_verify'] = dict(receipt, **json_ref(root, folder / 'runtime-not-applicable.json', receipt))
        # No success if a test/another process changed the evaluated source or config.
        if snapshot != dict(canonical_hashes=canonical_hashes(root), source_hashes=source_hashes(root, target, extra),
                            scanner_inputs={tool: profile_inputs(root, p) for tool, p in config['scanners'].items()},
                            config_sha256=sha(root / 'security.config.yml'), policy_sha256=sha(root / '.security/policies/security-policy.yml')):
            raise ContractError('source, findings or controls changed during verification')
        # Persist all successfully observed rescan findings, including new risks.
        # Scanner execution failure never becomes an empty successful store update.
        rescan_report = read_json(policy.reference(root, evidence['security_rescan']))
        if rescan_report.get('exit_code') == 0:
            store.update(root, evidence['security_rescan']['run_id'], expected_hashes=snapshot['canonical_hashes'])
            snapshot['canonical_hashes'] = canonical_hashes(root)
        context['evidence'] = evidence
        context_path = folder / 'gate-context.json'
        context_ref = json_ref(root, context_path, context)
        proof = dict(producer='security-verify-v1', run_id=run_id, close_requested=close,
                     finding_ids=ids, target=target, extra_paths=extra, context=context_ref, **snapshot)
        complete = not policy.evidence_issues(root, context, config, datetime.now(timezone.utc))
        if close and complete:
            proof['baseline_artifacts'] = baseline_proof(root, selected, context['patch']['rescan_run_id'])
        proof_path = folder / 'verification-proof.json'
        atomic_json(proof_path, proof)
        gate = policy.run_gate(root, context_ref['raw_reference'], context['event'],
                               _closure_proof=proof_path.relative_to(root).as_posix() if close and complete else None)
        report.update(gate=gate, proof_reference=proof_path.relative_to(root).as_posix(), gate_context_reference=context_ref['raw_reference'])
        code = 40 if tool_error else 60 if not complete else gate['exit_code']
        if close and code == 0:
            closed = store.close_finding(root, report['proof_reference'], gate['report_reference'])
            report.update(closed_ids=closed['ids'], canonical_written=True)
        report.update(exit_code=code, result={0:'PASS',10:'BLOCK',20:'REVIEW_REQUIRED',30:'CONFIG_ERROR',40:'TOOL_ERROR',50:'CONTRACT_ERROR',60:'VERIFY_ERROR'}[code])
    except ConfigError as exc:
        report.update(result='CONFIG_ERROR', exit_code=30, detail=str(exc))
    except store.IndexWriteError as exc:
        report.update(result='TOOL_ERROR', exit_code=40, canonical_written=True, detail=str(exc))
        report['closed_ids'] = [f['id'] for f in store.load_findings(root) if f['status'] == 'CLOSED' and
                               f['history'][-1].get('verification_reference') == report.get('proof_reference')]
    except (OSError, sqlite3.Error) as exc:
        report.update(result='TOOL_ERROR', exit_code=40, detail=type(exc).__name__)
    except Exception as exc:
        report.update(result='CONTRACT_ERROR', exit_code=50, detail=type(exc).__name__)
    report['finished_at'] = timestamp()
    report['report_reference'] = report_path.relative_to(root).as_posix()
    try:
        if not report_path.parent.is_symlink() and report_path.parent.resolve().is_relative_to(root):
            atomic_json(report_path, report)
        else:
            raise OSError('unsafe verification report directory')
    except OSError:
        report.update(result='TOOL_ERROR', exit_code=40, detail='verification report could not be persisted')
    return report
