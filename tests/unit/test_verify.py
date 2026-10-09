from contextlib import closing
import json
import sys
from unittest import mock

from tests.m4_support import VerifyProject, VULNERABLE
from lib import doctor, policy, store, verify
from lib.normalize import ContractError
from lib.storage_io import atomic_json


class VerifyTests(VerifyProject):
    def test_real_tests_rescan_runtime_policy_then_closed(self):
        self.fix();report=self.verify(close=True)
        self.assertEqual(report['exit_code'],0,report)
        self.assertEqual(report['closed_ids'],['SEC-0001'])
        self.assertTrue(all(r['state']=='PASS' for r in report['evidence'].values()))
        finding=store.show(self.root,'SEC-0001')['finding']
        self.assertEqual(finding['status'],'CLOSED')
        self.assertIn('gate_reference',finding['history'][-1])
        with closing(doctor.connect_database(self.root/'.security/security.db')) as db:
            self.assertEqual(db.execute('SELECT status FROM findings').fetchone()[0],'CLOSED')
            self.assertEqual(db.execute('SELECT result FROM gate_runs').fetchone()[0],'PASS')
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_remaining_finding_is_fail_and_cannot_close(self):
        report=self.verify(close=True)
        self.assertEqual(report['exit_code'],60,report)
        self.assertEqual(report['evidence']['security_rescan']['state'],'FAIL')
        self.assertEqual(report['evidence']['security_rescan']['unresolved_ids'],['SEC-0001'])
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')

    def test_nonclosing_verification_pass_does_not_close(self):
        self.fix();report=self.verify()
        self.assertEqual(report['exit_code'],0,report)
        self.assertFalse(report['closed_ids'])
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')

    def test_tests_failure_and_runtime_failure_reach_gate(self):
        self.fix()
        for name in ('tests','runtime_verify'):
            config=self.config()
            section=config['stack']['tests'] if name=='tests' else config['runtime_verify']
            original=section['argv']
            section['argv']=[sys.executable,'-c','raise SystemExit(1)']
            self.write_config(config)
            report=self.verify(close=True)
            self.assertEqual(report['exit_code'],60,report)
            self.assertEqual(report['evidence'][name]['state'],'FAIL')
            self.assertTrue(any(name in issue for issue in report['gate']['evidence_issues']))
            self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')
            section['argv']=original;self.write_config(config)

    def test_timeout_preserves_raw_receipt_and_no_closure(self):
        self.fix();config=self.config()
        config['stack']['tests'].update(argv=[sys.executable,'-c','import time;print("TEST_ONLY_PARTIAL",flush=True);time.sleep(20)'],timeout_seconds=1)
        self.write_config(config)
        report=self.verify(close=True)
        self.assertEqual(report['exit_code'],60,report)
        receipt=json.loads((self.root/report['evidence']['tests']['raw_reference']).read_text(encoding='utf-8'))
        self.assertTrue(receipt['timed_out'])
        self.assertIn('TEST_ONLY_PARTIAL',(self.root/receipt['stdout']['raw_reference']).read_text())

    def test_missing_test_or_scanner_is_not_finding_gone(self):
        self.fix();config=self.config()
        config['stack']['tests']['argv']=['TEST_ONLY_MISSING_EXECUTABLE']
        self.write_config(config)
        report=self.verify(close=True)
        self.assertEqual(report['exit_code'],40,report)
        self.assertEqual(report['evidence']['tests']['state'],'FAIL')
        config=self.config();config['scanners']['semgrep']['executable']='TEST_ONLY_MISSING_SCANNER';self.write_config(config)
        report=self.verify(close=True)
        self.assertEqual(report['exit_code'],40,report)
        self.assertEqual(report['evidence']['security_rescan']['state'],'FAIL')

    def test_not_applicable_is_not_pass(self):
        self.fix();config=self.config();config['runtime_verify']={'mode':'not_applicable'};self.write_config(config)
        report=self.verify(close=True)
        self.assertEqual(report['exit_code'],0,report)
        self.assertEqual(report['evidence']['runtime_verify']['state'],'NOT_APPLICABLE')

    def test_waiver_must_be_human_complete_and_audited(self):
        self.fix();path=self.root/'.security/evidence/human-waiver.json'
        waiver=dict(actor_type='ai',approved_by='TEST_ONLY_HUMAN',approved_at='2026-10-09T00:00:00Z',reason='TEST_ONLY_APPROVAL')
        atomic_json(path,waiver)
        self.assertEqual(self.verify(waiver=path.relative_to(self.root))['exit_code'],50)
        waiver['actor_type']='human';atomic_json(path,waiver)
        report=self.verify(close=True,waiver=path.relative_to(self.root))
        self.assertEqual(report['exit_code'],0,report)
        self.assertEqual(report['evidence']['runtime_verify']['state'],'WAIVED')

    def test_unknown_outside_target_and_disabled_original_tool_fail_closed(self):
        self.fix()
        self.assertEqual(self.verify(finding_id='SEC-9999')['exit_code'],50)
        config=self.config();config['scanners']['semgrep'].update(enabled=False,mandatory=False);self.write_config(config)
        self.assertEqual(self.verify(close=True)['exit_code'],50)

    def test_no_test_adapter_or_invalid_config_no_success(self):
        config=self.config();del config['stack'];self.write_config(config)
        self.assertEqual(self.verify()['exit_code'],30)
        (self.root/'security.config.yml').write_text('version: [',encoding='utf-8')
        self.assertEqual(self.verify()['exit_code'],30)

    def test_changed_rule_cannot_hide_vulnerability(self):
        self.fix()
        (self.root/'test-only-scanner.py').write_text((self.root/'test-only-scanner.py').read_text()+'\n# TEST_ONLY_RULE_CHANGED\n',encoding='utf-8')
        report=self.verify(close=True)
        self.assertEqual(report['exit_code'],50,report)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')

    def test_changed_ignore_config_or_tool_version_cannot_close(self):
        self.fix();(self.root/'.semgrepignore').write_text('sample.py\n',encoding='utf-8')
        self.assertEqual(self.verify(close=True)['exit_code'],50)
        (self.root/'.semgrepignore').unlink()
        finding=store.show(self.root,'SEC-0001')['finding']
        for source in finding['sources']:
            baseline=self.root/'.security/reports'/(source['raw_reference'].split('/')[-1].removesuffix('.sarif')+'-scan-report.json')
            report=json.loads(baseline.read_text())
            for item in report['scanners']:
                item['version']='TEST_ONLY_CHANGED_VERSION'
            atomic_json(baseline,report)
        self.assertEqual(self.verify(close=True)['exit_code'],50)

    def test_source_modified_by_test_cannot_close(self):
        self.fix();config=self.config()
        config['stack']['tests']['argv']=[sys.executable,'-c','from pathlib import Path;Path("sample.py").write_text("def parse(value):\\n    return int(value) + 1\\n")']
        self.write_config(config)
        self.assertEqual(self.verify(close=True)['exit_code'],50)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')

    def test_dependency_review_prevents_closure(self):
        self.fix();self.context['changed_files'].append('requirements.lock')
        self.context['dependencies'].update(lockfiles_changed=['requirements.lock'],added=['TEST_ONLY_PACKAGE']);self.write_context()
        report=self.verify(close=True)
        self.assertEqual(report['exit_code'],20,report)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')

    def test_injected_pass_or_missing_change_metadata_rejected(self):
        self.context['evidence']={'tests':{'state':'PASS'}};self.write_context()
        self.assertEqual(self.verify(close=True)['exit_code'],50)
        self.context['evidence']={};self.context['changed_files']=[];self.write_context()
        self.assertEqual(self.verify(close=True)['exit_code'],50)

    def test_direct_closure_without_proof_fails_closed(self):
        with self.assertRaises(ContractError):
            store.close_finding(self.root,'SEC-0001')

    def test_forged_gate_or_changed_source_cannot_close(self):
        self.fix();report=self.verify()
        with self.assertRaises(ContractError):
            store.close_finding(self.root,report['proof_reference'],report['gate']['report_reference'])

    def test_source_changed_after_policy_pass_cannot_close(self):
        self.fix();original=store.close_finding
        def changed_after_gate(*args):
            (self.root/'sample.py').write_text('def parse(value):\n    return int(value) + 1\n',encoding='utf-8')
            return original(*args)
        with mock.patch('lib.store.close_finding',side_effect=changed_after_gate):
            report=self.verify(close=True)
        self.assertEqual(report['gate']['exit_code'],0)
        self.assertEqual(report['exit_code'],50,report)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')

    def test_receipt_tampered_after_gate_cannot_close(self):
        self.fix();original=store.close_finding
        def tampered_after_gate(root,proof_ref,gate_ref):
            proof=json.loads((root/proof_ref).read_text())
            context=json.loads((root/proof['context']['raw_reference']).read_text())
            path=root/context['evidence']['tests']['raw_reference']
            path.write_text('{}',encoding='utf-8')
            return original(root,proof_ref,gate_ref)
        with mock.patch('lib.store.close_finding',side_effect=tampered_after_gate):
            report=self.verify(close=True)
        self.assertEqual(report['exit_code'],50,report)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')

    def test_waiver_missing_identity_reason_or_timestamp_rejected(self):
        self.fix();path=self.root/'.security/evidence/incomplete-waiver.json'
        for missing in ('approved_by','approved_at','reason'):
            value=dict(actor_type='human',approved_by='TEST_ONLY_HUMAN',approved_at='2026-10-09T00:00:00Z',reason='TEST_ONLY_REASON')
            del value[missing];atomic_json(path,value)
            self.assertEqual(self.verify(waiver=path.relative_to(self.root))['exit_code'],50)

    def test_new_critical_found_on_rescan_is_persisted_and_blocks_closure(self):
        config=self.config()
        for profile in config['scanners'].values():
            profile['severity_mapping']['HIGH']='CRITICAL'
        self.write_config(config)
        from lib.scan import run_scan
        from lib import normalize
        scan=run_scan(self.root,'sample.py');normalize.normalize(self.root,scan['run_id']);store.update(self.root,scan['run_id'])
        self.fix()
        with (self.root/'sample.py').open('a',encoding='utf-8') as stream:
            stream.write('def other(value):\n    return eval(value)\n')
        self.context['event']='release';self.write_context()
        report=self.verify(close=True)
        self.assertEqual(report['exit_code'],10,report)
        self.assertEqual(store.show(self.root,'SEC-0002')['finding']['status'],'OPEN')
        self.assertEqual(store.show(self.root,'SEC-0002')['finding']['severity'],'CRITICAL')
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')

    def test_verified_index_failure_keeps_canonical_and_recovers(self):
        self.fix()
        original=store.write_index
        def fail_when_closed(root,findings):
            if any(f['status']=='CLOSED' for f in findings):
                raise OSError('TEST_ONLY_CLOSED_INDEX_FAILURE')
            return original(root,findings)
        with mock.patch('lib.store.write_index',side_effect=fail_when_closed):
            report=self.verify(close=True)
        self.assertEqual(report['exit_code'],40,report)
        self.assertTrue(report['canonical_written'])
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'CLOSED')
        store.rebuild(self.root)

    def test_restore_same_fingerprint_reopens_same_id(self):
        self.fix();self.assertEqual(self.verify(close=True)['exit_code'],0)
        (self.root/'sample.py').write_text(VULNERABLE,encoding='utf-8')
        from lib.scan import run_scan
        from lib import normalize
        scan=run_scan(self.root,'sample.py');normalize.normalize(self.root,scan['run_id'])
        self.assertEqual(store.update(self.root,scan['run_id'])['ids'],['SEC-0001'])
        finding=store.show(self.root,'SEC-0001')['finding']
        self.assertEqual(finding['status'],'REOPENED')
        self.assertTrue(finding['regression'])


class SecretVerifyTests(VerifyProject):
    scanner_category='hardcoded-secret'

    def test_rotation_required_before_closure_and_reset_on_regression(self):
        self.fix();report=self.verify(close=True)
        self.assertEqual(report['exit_code'],10,report)
        finding=store.show(self.root,'SEC-0001')['finding']
        self.assertEqual(finding['status'],'OPEN')
        # Explicit fake human confirmation, never a real provider/credential.
        finding['remediation'].update(rotation_confirmed=True,confirmed_by='TEST_ONLY_HUMAN',confirmed_at='2026-10-09T00:00:00Z')
        atomic_json(self.root/'.security/findings/SEC-0001.json',finding)
        self.assertEqual(self.verify(close=True)['exit_code'],0)
        (self.root/'sample.py').write_text(VULNERABLE,encoding='utf-8')
        from lib.scan import run_scan
        from lib import normalize
        scan=run_scan(self.root,'sample.py');normalize.normalize(self.root,scan['run_id']);store.update(self.root,scan['run_id'])
        finding=store.show(self.root,'SEC-0001')['finding']
        self.assertEqual(finding['status'],'REOPENED')
        self.assertFalse(finding['remediation']['rotation_confirmed'])
        self.assertIsNone(finding['remediation']['confirmed_by'])
