import copy
from contextlib import closing
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sqlite3
from unittest import mock

from tests.m3_support import GateProject
from lib import policy, store, doctor, normalize
from lib.storage_io import atomic_json


class PolicyTests(GateProject):
    def gate(self, context=None):
        if context is not None:
            self.write_context(context)
        return policy.run_gate(self.root, '.security/evidence/gate-context.json')

    def test_pass_requires_real_referenced_evidence_and_audit(self):
        self.context()
        report = self.gate()
        self.assertEqual(report['exit_code'], 0, report)
        with closing(doctor.connect_database(self.root / '.security/security.db')) as db:
            self.assertEqual(db.execute('SELECT result FROM gate_runs').fetchall(), [('PASS',)])
            self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone()[0], 1)

    def test_critical_release_and_merge_scope(self):
        self.finding('CRITICAL')
        context = self.context()
        self.assertEqual(self.gate(context)['exit_code'], 10)
        context['event'] = 'merge'
        self.assertEqual(self.gate(context)['exit_code'], 0)

    def test_pending_verification_critical_not_a_release_bypass(self):
        self.finding('CRITICAL', status='VERIFYING')
        self.context()
        self.assertEqual(self.gate()['exit_code'], 10)

    def test_policy_filters_and_actions_read_from_yaml(self):
        self.finding('CRITICAL')
        context = self.context('merge')
        path = self.root / '.security/policies/security-policy.yml'
        rules = doctor.load_yaml(path)
        rules['policies'][0]['events'] = ['merge']
        yaml, _ = doctor.dependencies()
        path.write_text(yaml.safe_dump(rules), encoding='utf-8')
        self.assertEqual(self.gate(context)['exit_code'], 10)

    def test_dependency_review_and_sbom_requirement(self):
        context = self.context('merge')
        context['changed_files'] = ['requirements.lock']
        context['dependencies'].update(lockfiles_changed=['requirements.lock'], added=['TEST_ONLY_PACKAGE'], sbom_enabled=True)
        report = self.gate(context)
        self.assertEqual(report['exit_code'], 20)
        self.assertEqual(len([p for p in report['policies'] if p['policy_id'] == 'POL-003']), 2)
        path = self.root / '.security/evidence/sbom.json'
        atomic_json(path, {'added': ['TEST_ONLY_PACKAGE']})
        context['dependencies']['sbom_diff'] = dict(raw_reference=path.relative_to(self.root).as_posix(), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        report = self.gate(context)
        self.assertEqual(report['exit_code'], 20)
        self.assertEqual(len([p for p in report['policies'] if p['policy_id'] == 'POL-003']), 1)

    def test_dependency_without_lock_change_does_not_trigger_003(self):
        context = self.context()
        context['dependencies']['added'] = ['TEST_ONLY_PACKAGE']
        self.assertEqual(self.gate(context)['exit_code'], 0)

    def ai_context(self, remains=True):
        self.finding()
        context = self.context('merge')
        run = self.evidence(number=3, results=remains)
        normalize.normalize(self.root, run)
        context['patch'].update(source='ai', finding_ids=['SEC-0001'], rescan_run_id=run)
        path = self.root / '.security/reports' / (run + '-scan-report.json')
        context['evidence']['security_rescan'].update(timestamp='2026-10-09T00:00:03Z', raw_reference=path.relative_to(self.root).as_posix(), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        return context

    def test_ai_patch_remains_and_clean_rescan_not_closure(self):
        context = self.ai_context()
        self.assertEqual(self.gate(context)['exit_code'], 10)
        run = self.evidence(number=4, results=False)
        from lib import normalize
        normalize.normalize(self.root, run)
        context['patch']['rescan_run_id'] = run
        path = self.root / '.security/reports' / (run + '-scan-report.json')
        context['evidence']['security_rescan'].update(timestamp='2026-10-09T00:00:04Z', raw_reference=path.relative_to(self.root).as_posix(), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(self.gate(context)['exit_code'], 0)
        self.assertEqual(store.show(self.root, 'SEC-0001')['finding']['status'], 'OPEN')

    def test_coverage_regression_and_restricted_trust(self):
        context = self.ai_context(False)
        context['coverage'].update(enabled=True, before=90, after=89)
        self.assertEqual(self.gate(context)['exit_code'], 10)
        context['coverage']['after'] = 90
        context['patch']['trust'] = 'restricted'
        self.assertEqual(self.gate(context)['exit_code'], 20)

    def test_coverage_missing_or_boolean_metrics_fails_closed(self):
        context = self.context()
        context['coverage'].update(enabled=True, before=True, after=None)
        self.assertEqual(self.gate(context)['exit_code'], 50)

    def test_open_secret_blocks_both_events_and_points_to_playbook(self):
        self.finding('LOW', 'hardcoded-secret')
        context = self.context()
        for event in ('merge', 'release'):
            context['event'] = event
            report = self.gate(context)
            self.assertEqual(report['exit_code'], 10)
            self.assertEqual(report['policies'][0]['policy_id'], 'POL-005')
            self.assertEqual(report['policies'][0]['playbook'], '.security/playbooks/secret-leak.md')

    def test_closed_secret_requires_rotation_and_confirmer(self):
        finding = self.finding('HIGH', 'hardcoded-secret', status='CLOSED')
        context = self.context()
        self.assertEqual(self.gate(context)['exit_code'], 10)
        finding['remediation'].update(rotation_confirmed=True, confirmed_at='2026-10-09T00:00:00Z', confirmed_by='TEST_ONLY_HUMAN')
        atomic_json(self.root / '.security/findings/SEC-0001.json', finding)
        self.assertEqual(self.gate(context)['exit_code'], 0)

    def test_security_critical_paths_root_nested_and_custom(self):
        context = self.context('merge')
        for path in ('auth/handler.py', 'src/auth/nested/handler.py', 'middleware/check.py', 'app/crypto/key.py'):
            context['changed_files'] = [path]
            self.assertEqual(self.gate(context)['exit_code'], 20, path)
        context['changed_files'] = ['src/authorization.py']
        self.assertEqual(self.gate(context)['exit_code'], 0)
        path=self.root/'.security/policies/security-policy.yml'
        rules=doctor.load_yaml(path)
        rules['policies'][5]['paths'].append('src/authorization.py')
        yaml,_=doctor.dependencies()
        path.write_text(yaml.safe_dump(rules),encoding='utf-8')
        self.assertEqual(self.gate(context)['exit_code'],20)

    def test_escalation_boundaries_outbox_and_no_repeat_after_rebuild(self):
        finding = self.finding(first='2026-06-01T00:00:00Z')
        context = self.context()
        first = datetime.fromisoformat(finding['first_seen'].replace('Z', '+00:00'))
        historical = dict(finding, last_seen=finding['first_seen'])
        from datetime import timedelta
        policies = policy.load_policy(self.root)
        previous = set()
        for age, stage, targets in ((29,None,[]),(30,30,['security_report']),(59,30,['security_report']),
                (60,60,['finding_owner','responsible_team']),(89,60,['finding_owner','responsible_team']),
                (90,90,['finding_owner','responsible_team','security_lead'])):
            matches, queued = policy.evaluate(self.root,policies,[historical],context,first+timedelta(days=age),previous)
            self.assertEqual(matches[0]['stage'] if matches else None,stage)
            if age in (59,89):
                self.assertFalse(queued)
            else:
                self.assertEqual([n['target'] for n in queued],targets)
        report = self.gate(context)
        self.assertEqual(report['exit_code'],0)
        self.assertEqual({n['target'] for n in report['notifications']},set(targets))
        self.assertTrue(all(n['status']=='QUEUED' and n['attempted_at'] is None and n['delivered_at'] is None for n in report['notifications']))
        store.rebuild(self.root)
        self.assertFalse(self.gate(context)['notifications'])
        with closing(doctor.connect_database(self.root/'.security/security.db')) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM escalation_state').fetchone()[0],3)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM gate_runs').fetchone()[0],2)

    def test_lower_severity_or_closed_not_escalated(self):
        self.finding('MEDIUM',first='2026-06-01T00:00:00Z')
        self.context()
        self.assertFalse(self.gate()['notifications'])

    def test_missing_context_or_evidence_never_passes(self):
        self.assertEqual(policy.run_gate(self.root)['exit_code'],60)
        context=self.context()
        for name in policy.EVIDENCE:
            broken=copy.deepcopy(context);del broken['evidence'][name]
            self.assertEqual(self.gate(broken)['exit_code'],60)

    def test_failed_timed_out_or_incomplete_receipt_never_passes(self):
        context=self.context()
        path=self.root/'.security/evidence/tests.json'
        for fields in ({'exit_code':1},{'timed_out':True},{'completed':False}):
            receipt=dict(context['evidence']['tests'],exit_code=0,timed_out=False,completed=True)
            receipt.update(fields);atomic_json(path,receipt)
            context['evidence']['tests']['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(self.gate(context)['exit_code'],60)

    def test_fake_scan_pass_receipt_rejected(self):
        context=self.context()
        path=self.root/'.security/evidence/fake-scan.json'
        atomic_json(path,dict(type='static_scan',state='PASS',exit_code=0,completed=True,timed_out=False))
        context['evidence']['static_scan'].update(raw_reference=path.relative_to(self.root).as_posix(),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(self.gate(context)['exit_code'],50)

    def test_hash_mismatch_and_path_escape_rejected(self):
        context=self.context()
        context['evidence']['tests']['sha256']='0'*64
        self.assertEqual(self.gate(context)['exit_code'],50)
        context['changed_files']=['../auth.py']
        self.assertEqual(self.gate(context)['exit_code'],50)

    def test_runtime_not_applicable_and_human_waiver(self):
        context=self.context()
        runtime=context['evidence']['runtime_verify']
        runtime.update(state='NOT_APPLICABLE',reason='TEST_ONLY_NO_RUNTIME')
        self.assertEqual(self.gate(context)['exit_code'],0)
        runtime.update(state='WAIVED',reason='TEST_ONLY_REASON',approved_by='TEST_ONLY_HUMAN',approved_at='2026-10-09T00:00:00Z')
        path=self.root/'.security/evidence/runtime_verify.json'
        for actor,expected in (('ai',60),('human',0)):
            atomic_json(path,dict(runtime,actor_type=actor))
            runtime['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(self.gate(context)['exit_code'],expected)

    def test_invalid_or_missing_policy_fail_closed(self):
        self.context()
        path=self.root/'.security/policies/security-policy.yml'
        original=path.read_text(encoding='utf-8')
        for content in ('policies: [',original.replace('days: 30','days: -1'),original.replace('action: WARNING','action: BLOCK'),original.replace('paths:', 'unknown_paths:')):
            path.write_text(content,encoding='utf-8')
            self.assertEqual(self.gate()['exit_code'],30)
        path.unlink();self.assertEqual(self.gate()['exit_code'],30)

    def test_index_failure_preserves_report_and_recovers(self):
        self.context()
        with mock.patch('lib.store.write_index',side_effect=sqlite3.OperationalError('TEST_ONLY_DB_FAILURE')):
            report=self.gate()
        self.assertEqual(report['exit_code'],40)
        self.assertTrue((self.root/report['report_reference']).is_file())
        store.rebuild(self.root)
        with closing(doctor.connect_database(self.root/'.security/security.db')) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM gate_runs').fetchone()[0],1)

    def test_invalid_prior_audit_protects_index(self):
        self.context();report=self.gate()
        path=self.root/report['report_reference']
        value=__import__('json').loads(path.read_text(encoding='utf-8'));value['exit_code']=10;atomic_json(path,value)
        self.assertEqual(self.gate()['exit_code'],50)

    def test_rescan_receipt_must_match_patch_rescan(self):
        context=self.ai_context(False)
        context['patch']['rescan_run_id']='20261009T000000Z-'+f'{2:032x}'
        self.assertEqual(self.gate(context)['exit_code'],50)

    def test_bare_pass_and_receipt_mismatch_are_not_evidence(self):
        context=self.context()
        record=context['evidence']['tests']
        path=self.root/'.security/evidence/tests.json'
        for value in ({'state':'PASS'},dict(record,exit_code=0,completed=True,timed_out=False,state='FAIL')):
            atomic_json(path,value)
            record['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(self.gate(context)['exit_code'],50)

    def test_evidence_failure_and_static_waiver_fail_closed(self):
        context=self.context()
        context['evidence']['tests']['state']='FAIL'
        self.assertEqual(self.gate(context)['exit_code'],60)
        context['evidence']['tests']['state']='WAIVED'
        self.assertEqual(self.gate(context)['exit_code'],60)

    def test_report_write_failure_cannot_pass(self):
        self.context()
        with mock.patch('lib.policy.atomic_json',side_effect=PermissionError('TEST_ONLY_WRITE_FAILURE')):
            self.assertEqual(self.gate()['exit_code'],40)

    def test_unapproved_accepted_risk_does_not_suppress_gate(self):
        self.finding('CRITICAL',status='ACCEPTED_RISK')
        self.context()
        self.assertEqual(self.gate()['exit_code'],50)
