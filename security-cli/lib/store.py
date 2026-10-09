"""Canonical JSON is authoritative; SQLite is a replaceable derived index."""
from datetime import datetime
import os
from pathlib import Path
import re
import tempfile

from .doctor import connect_database, validate_finding_schema
from .normalize import (ContractError, LEVELS, fingerprint, load_normalized, read_json,
                        safe_path, schema_validator)
from .storage_io import atomic_json, store_lock

SEC_ID = re.compile(r'^SEC-[0-9]{4,}$')


class IndexWriteError(OSError):
    """Canonical JSON was committed but the derived SQLite index failed."""


def load_findings(root):
    directory = root / '.security/findings'
    if not directory.is_dir() or directory.is_symlink():
        raise ContractError('canonical finding directory missing or unsafe')
    schema = root / 'schemas/finding.schema.json'
    validate_finding_schema(schema)
    validator = schema_validator(schema)
    result = []
    seen = set()
    for path in sorted((root / '.security/findings').glob('*.json')):
        if path.name == '.sequence.json':
            continue
        if path.is_symlink() or not SEC_ID.fullmatch(path.stem):
            raise ContractError('invalid canonical finding filename')
        data = read_json(path)
        validator.validate(data)
        if data['id'] != path.stem or data['id'] != f"SEC-{int(data['id'][4:]):04d}" or data['fingerprint_version'] != 1:
            raise ContractError('canonical ID or fingerprint version mismatch')
        if not isinstance(data.get('context'), dict) or not isinstance(data.get('sources'), list) or not data['sources']:
            raise ContractError('canonical finding context/sources missing')
        relative = safe_path(root, data['location']['path']).relative_to(root).as_posix()
        if relative != data['location']['path']:
            raise ContractError('canonical location must be a portable project-relative path')
        if fingerprint(data['category'], relative, data['context']) != data['fingerprint']:
            raise ContractError('canonical fingerprint disagrees with security identity')
        if data['fingerprint'] in seen:
            raise ContractError('duplicate canonical fingerprint')
        seen.add(data['fingerprint'])
        if not data['history'] or data['history'][-1]['status'] != data['status']:
            raise ContractError('canonical status/history mismatch')
        if datetime.fromisoformat(data['first_seen'].replace('Z', '+00:00')) > datetime.fromisoformat(data['last_seen'].replace('Z', '+00:00')):
            raise ContractError('canonical timestamps out of order')
        for source in data['sources']:
            if not isinstance(source, dict):
                raise ContractError('invalid canonical finding source structure')
            if not all(isinstance(source.get(key), str) and source[key] for key in ('tool', 'rule_id', 'raw_reference')):
                raise ContractError('invalid canonical finding source')
            safe_path(root, source['raw_reference'], '.security/raw')
        result.append(data)
    return result


def next_sequence(root, findings):
    maximum = max((int(item['id'][4:]) for item in findings), default=0)
    path = root / '.security/findings/.sequence.json'
    if path.exists():
        data = read_json(path)
        if set(data) != {'last_id'} or type(data['last_id']) is not int or data['last_id'] < maximum:
            raise ContractError('invalid canonical ID high-water mark')
        maximum = data['last_id']
    return maximum


def write_index(root, findings):
    """Build a transactionally complete new DB, then replace the derived index."""
    temp = None
    connection = None
    try:
        with tempfile.NamedTemporaryFile(dir=root / '.security', prefix='.index-', suffix='.db', delete=False) as stream:
            temp = Path(stream.name)
        connection = connect_database(temp)
        sql = (root / 'security-cli/security-store.schema.sql').read_text(encoding='utf-8-sig')
        connection.executescript('BEGIN IMMEDIATE;\n' + sql)
        for item in findings:
            connection.execute('INSERT INTO findings VALUES (?,?,?,?,?)',
                (item['id'], item['fingerprint'], 1, item['status'], '.security/findings/' + item['id'] + '.json'))
            for source in item['sources']:
                connection.execute('INSERT INTO finding_sources(finding_id,tool,raw_reference) VALUES (?,?,?)',
                                   (item['id'], source['tool'], source['raw_reference']))
            for event in item['history']:
                connection.execute('INSERT INTO finding_history(finding_id,timestamp,event) VALUES (?,?,?)',
                                   (item['id'], event['timestamp'], event.get('event', event['status'])))
        if connection.execute('PRAGMA foreign_keys').fetchone()[0] != 1 or connection.execute('PRAGMA foreign_key_check').fetchone():
            raise OSError('index foreign key verification failed')
        connection.commit()
        if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise OSError('index integrity verification failed')
        connection.close()
        connection = None
        os.replace(temp, root / '.security/security.db')
    finally:
        if connection is not None:
            connection.rollback()
            connection.close()
        if temp is not None and temp.exists():
            temp.unlink()


def update(root, run_id):
    root = Path(root).resolve()
    with store_lock(root):
        data = load_normalized(root, run_id)
        findings = load_findings(root)
        by_fp = {item['fingerprint']: item for item in findings}
        last_id = next_sequence(root, findings)
        affected = []
        for incoming in data['findings']:
            existing = by_fp.get(incoming['fingerprint'])
            if existing is not None and any(event.get('run_id') == run_id for event in existing['history']):
                affected.append(existing['id'])
                continue
            observed = data['observed_at']
            if not isinstance(observed, str) or not observed.endswith('Z'):
                raise ContractError('invalid scan observation timestamp')
            observed_time = datetime.fromisoformat(observed.replace('Z', '+00:00'))
            if existing is None:
                last_id += 1
                existing = dict(incoming, id=f'SEC-{last_id:04d}', status='OPEN',
                                first_seen=observed, last_seen=observed, regression=False, history=[])
                if existing['category'] == 'hardcoded-secret':
                    existing['remediation'] = {'rotation_required': True, 'rotation_confirmed': False,
                                               'confirmed_at': None, 'confirmed_by': None}
                findings.append(existing)
                by_fp[existing['fingerprint']] = existing
                event = 'opened'
            else:
                previous_time = datetime.fromisoformat(existing['last_seen'].replace('Z', '+00:00'))
                if observed_time < previous_time:
                    raise ContractError('out-of-order observation; use a fresh scan')
                event = 'observed'
                if existing['status'] == 'CLOSED':
                    closed_time = datetime.fromisoformat(existing['history'][-1]['timestamp'].replace('Z', '+00:00'))
                    if observed_time <= closed_time:
                        raise ContractError('historical scan cannot prove regression after closure')
                    existing.update(status='REOPENED', regression=True)
                    event = 'reopened'
                existing.update(last_seen=observed, location=incoming['location'])
                if LEVELS.index(incoming['severity']) > LEVELS.index(existing['severity']):
                    existing['severity'] = incoming['severity']
                for source in incoming['sources']:
                    if source not in existing['sources']:
                        existing['sources'].append(source)
            existing['history'].append({'timestamp': observed, 'status': existing['status'],
                                        'event': event, 'run_id': run_id})
            affected.append(existing['id'])
        # Reserve IDs before any finding write; interrupted writes burn IDs, never reuse them.
        atomic_json(root / '.security/findings/.sequence.json', {'last_id': last_id})
        for item in findings:
            atomic_json(root / '.security/findings' / (item['id'] + '.json'), item)
        # Validate the actual canonical files before deriving the DB, never mutate DB first.
        validated = load_findings(root)
        try:
            write_index(root, validated)
        except Exception as exc:
            raise IndexWriteError('canonical JSON saved; run findings rebuild-index') from exc
    return {'run_id': run_id, 'ids': affected, 'total_findings': len(validated),
            'canonical_written': True, 'index_rebuilt': True}


def rebuild(root):
    root = Path(root).resolve()
    with store_lock(root):
        findings = load_findings(root)
        last_id = next_sequence(root, findings)
        atomic_json(root / '.security/findings/.sequence.json', {'last_id': last_id})
        write_index(root, findings)
    return {'total_findings': len(findings), 'index_rebuilt': True}


def show(root, finding_id):
    if not SEC_ID.fullmatch(finding_id or ''):
        raise ContractError('invalid finding ID')
    for finding in load_findings(Path(root).resolve()):
        if finding['id'] == finding_id:
            return {'finding': finding}
    raise ContractError('finding does not exist in canonical JSON')


def close_finding(*args, **kwargs):
    # No production closure path until real M3/M4 deterministic checks exist.
    raise ContractError('closure unavailable until actual verification and policy checks exist')
