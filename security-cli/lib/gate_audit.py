"""Gate reports are durable audit/outbox records; SQLite is their derived index."""
from pathlib import Path

from .normalize import ContractError, RUN_ID, read_json


def load_audits(root):
    reports = []
    for path in sorted((root / '.security/reports').glob('*-gate-report.json')):
        report = read_json(path)
        run_id = path.name.removesuffix('-gate-report.json')
        if path.is_symlink() or not RUN_ID.fullmatch(run_id) or report.get('run_id') != run_id:
            raise ContractError('invalid gate audit identity')
        if report.get('command') != 'gate' or report.get('audit_version') != 1:
            raise ContractError('invalid gate audit contract')
        # Errors are retained in reports, not misrepresented as successful decisions.
        if report.get('result') not in ('PASS', 'BLOCK', 'REVIEW_REQUIRED'):
            if report.get('result') not in ('CONFIG_ERROR', 'TOOL_ERROR', 'CONTRACT_ERROR', 'VERIFY_ERROR'):
                raise ContractError('unknown gate audit result')
            continue
        codes = {'PASS': 0, 'BLOCK': 10, 'REVIEW_REQUIRED': 20}
        if report.get('exit_code') != codes[report['result']]:
            raise ContractError('gate audit result/code mismatch')
        from .policy import utc_time
        utc_time(report.get('timestamp'))
        if not isinstance(report.get('notifications'), list):
            raise ContractError('gate outbox missing')
        for item in report['notifications']:
            if not isinstance(item, dict) or item.get('stage') not in (30, 60, 90):
                raise ContractError('invalid gate outbox stage')
            if item.get('target') not in ('security_report', 'finding_owner', 'responsible_team', 'security_lead'):
                raise ContractError('invalid gate outbox target')
            if item.get('status') != 'QUEUED' or item.get('attempted_at') is not None or item.get('delivered_at') is not None or item.get('error') is not None:
                raise ContractError('M3 outbox must not claim attempted or delivered notification')
            if not isinstance(item.get('finding_id'), str):
                raise ContractError('invalid gate outbox finding')
        reports.append(report)
    return reports


def queued_keys(reports):
    return {(n['finding_id'], n['stage'], n['target']) for r in reports for n in r['notifications']}


def index_audits(connection, root):
    for report in load_audits(root):
        connection.execute('INSERT INTO gate_runs VALUES (?,?,?,?)',
            (report['run_id'], report['timestamp'], report['result'],
             '.security/reports/' + report['run_id'] + '-gate-report.json'))
        for n in report['notifications']:
            connection.execute('INSERT OR IGNORE INTO escalation_state VALUES (?,?,?,?,?,?,?)',
                (n['finding_id'], n['stage'], n['target'], n['status'],
                 n['attempted_at'], n['delivered_at'], n['error']))
