from contextlib import closing
import json
import shutil
import subprocess
import sys

from tests.support import DoctorProject, REPOSITORY, doctor
from lib import store
from lib.storage_io import atomic_json

VULNERABLE='def parse(value):\n    return eval(value)\n'
FIXED='def parse(value):\n    return int(value)\n'


class RealVerificationAcceptance(DoctorProject):
    def invoke(self, expected, *args):
        result=subprocess.run([sys.executable,str(self.root/'security-cli/security'),*args,'--json'],
            cwd=self.root,text=True,capture_output=True,timeout=180)
        self.assertEqual(result.returncode,expected,result.stdout+result.stderr)
        return json.loads(result.stdout)

    def test_full_actual_verified_closure_and_reopened_lifecycle_without_ai(self):
        shutil.copytree(REPOSITORY/'.security/rules',self.root/'.security/rules')
        config=doctor.load_yaml(REPOSITORY/'security.config.yml')
        config['scanners']['trivy']['executable']=str(REPOSITORY/'.tools/trivy/trivy.exe')
        config['stack']={'tests':{'argv':[sys.executable,'-m','unittest','discover','-s','app','-p','test_runtime.py','-v'],'timeout_seconds':30}}
        config['runtime_verify']={'mode':'command','argv':[sys.executable,'-c','from app.vulnerable import parse; assert parse("8")==8; print("ACTUAL_TEST_RUNTIME_OK")'],
            'timeout_seconds':30,'environment':'test'}
        self.write_config(config)
        app=self.root/'app';app.mkdir()
        source=app/'vulnerable.py';source.write_text(VULNERABLE,encoding='utf-8')
        (app/'test_runtime.py').write_text('import unittest\nfrom vulnerable import parse\nclass ParseTest(unittest.TestCase):\n    def test_parse(self):\n        self.assertEqual(parse("7"),7)\n',encoding='utf-8')
        def observe():
            scan=self.invoke(0,'scan','--target','app')
            self.invoke(0,'normalize','--run-id',scan['run_id'])
            return self.invoke(0,'findings','update','--run-id',scan['run_id'])
        self.assertEqual(observe()['ids'],['SEC-0001'])
        self.assertEqual(observe()['ids'],['SEC-0001'])
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')
        context=dict(version=1,event='release',changed_files=['app/vulnerable.py'],
            dependencies=dict(lockfiles_changed=[],added=[],sbom_enabled=False,sbom_diff=None),
            patch=dict(source='human',trust='standard',finding_ids=['SEC-0001'],rescan_run_id=None),
            coverage=dict(enabled=False,before=None,after=None),evidence={})
        atomic_json(self.root/'.security/evidence/change.json',context)
        source.write_text(FIXED,encoding='utf-8')
        original_runtime=config['runtime_verify']['argv']
        config['runtime_verify']['argv']=[sys.executable,'-c','raise SystemExit(1)'];self.write_config(config)
        failed=self.invoke(60,'verify','SEC-0001','--target','app','--input','.security/evidence/change.json','--close')
        self.assertEqual(failed['evidence']['runtime_verify']['state'],'FAIL')
        self.assertEqual(failed['gate']['result'],'VERIFY_ERROR')
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')
        config['runtime_verify']['argv']=original_runtime;self.write_config(config)
        verified=self.invoke(0,'verify','SEC-0001','--target','app','--input','.security/evidence/change.json','--close')
        self.assertEqual(verified['closed_ids'],['SEC-0001'])
        self.assertTrue(all(r['state']=='PASS' for r in verified['evidence'].values()))
        finding=store.show(self.root,'SEC-0001')['finding']
        self.assertEqual(finding['status'],'CLOSED')
        receipt=json.loads((self.root/verified['evidence']['tests']['raw_reference']).read_text())
        self.assertIn('Ran 1 test',(self.root/receipt['stderr']['raw_reference']).read_text())
        runtime=json.loads((self.root/verified['evidence']['runtime_verify']['raw_reference']).read_text())
        self.assertIn('ACTUAL_TEST_RUNTIME_OK',(self.root/runtime['stdout']['raw_reference']).read_text())
        self.invoke(0,'findings','rebuild-index')
        self.invoke(0,'doctor')
        source.write_text(VULNERABLE,encoding='utf-8')
        self.assertEqual(observe()['ids'],['SEC-0001'])
        reopened=store.show(self.root,'SEC-0001')['finding']
        self.assertEqual(reopened['status'],'REOPENED')
        self.assertTrue(reopened['regression'])
        self.assertEqual(len(store.load_findings(self.root)),1)
        self.assertIn('closed',[h['event'] for h in reopened['history']])
        self.assertEqual(reopened['history'][-1]['event'],'reopened')
        with closing(doctor.connect_database(self.root/'.security/security.db')) as db:
            self.assertEqual(db.execute('SELECT status FROM findings').fetchone()[0],'REOPENED')
            self.assertEqual(db.execute('SELECT result FROM gate_runs').fetchall(),[('PASS',)])
            self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone()[0],1)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])
        self.assertEqual(config['ai']['providers'],[])
