from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import subprocess
import sys

from tests.m3_support import GateProject
from lib import doctor, store


class GateAcceptance(GateProject):
    def invoke(self, expected, *args):
        result = subprocess.run([sys.executable,str(self.root/'security-cli/security'),
                                 'gate',*args,'--json'],cwd=self.root,text=True,capture_output=True,timeout=30)
        self.assertEqual(result.returncode,expected,result.stdout+result.stderr)
        report=json.loads(result.stdout)
        self.assertEqual(report['exit_code'],expected)
        return report

    def test_cli_pass_block_review_missing_evidence_and_policy_error(self):
        context=self.context()
        self.invoke(0,'--input','.security/evidence/gate-context.json')
        context['changed_files']=['auth/guard.py'];self.write_context(context)
        self.invoke(20,'--input','.security/evidence/gate-context.json')
        finding=self.finding('CRITICAL')
        report=self.invoke(10,'--input','.security/evidence/gate-context.json')
        self.assertTrue(any(p['policy_id']=='POL-001' for p in report['policies']))
        before=(self.root/'.security/findings/SEC-0001.json').read_bytes()
        self.invoke(10,'--event','release')
        self.assertEqual(before,(self.root/'.security/findings/SEC-0001.json').read_bytes())
        self.invoke(60,'--event','merge')
        (self.root/'.security/policies/security-policy.yml').write_text('policies: [',encoding='utf-8')
        self.invoke(30,'--input','.security/evidence/gate-context.json')

    def test_dependency_review_and_secret_block_real_cli(self):
        context=self.context('merge')
        context['changed_files']=['requirements.lock']
        context['dependencies'].update(lockfiles_changed=['requirements.lock'],added=['TEST_ONLY_PACKAGE'])
        self.write_context(context)
        self.invoke(20,'--input','.security/evidence/gate-context.json')
        self.finding('LOW','hardcoded-secret')
        self.invoke(10,'--input','.security/evidence/gate-context.json')

    def test_escalation_outbox_concurrent_and_rebuild_audit(self):
        self.finding(first='2026-06-01T00:00:00Z')
        self.context()
        with ThreadPoolExecutor(max_workers=2) as executor:
            reports=list(executor.map(lambda _:self.invoke(0,'--input','.security/evidence/gate-context.json'),range(2)))
        self.assertEqual(sum(len(r['notifications']) for r in reports),3)
        self.assertTrue(any(n['target']=='security_lead' for r in reports for n in r['notifications']))
        store.rebuild(self.root)
        self.assertFalse(self.invoke(0,'--input','.security/evidence/gate-context.json')['notifications'])
        with closing(doctor.connect_database(self.root/'.security/security.db')) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM gate_runs').fetchone()[0],3)
            self.assertEqual(db.execute('SELECT DISTINCT status FROM escalation_state').fetchall(),[('QUEUED',)])
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_human_output_and_cli_contract_errors(self):
        self.context()
        command=[sys.executable,str(self.root/'security-cli/security'),'gate','--input','.security/evidence/gate-context.json']
        result=subprocess.run(command,cwd=self.root,text=True,capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('PASS (exit 0)',result.stdout)
        self.invoke(50,'--input','.security/evidence/gate-context.json','--event','merge')
        result=subprocess.run([sys.executable,str(self.root/'security-cli/security'),'gate','extra-argument','--json'],
                              cwd=self.root,text=True,capture_output=True,timeout=30)
        self.assertEqual(result.returncode,30)
        self.assertIn('CONFIG_ERROR',result.stderr)
