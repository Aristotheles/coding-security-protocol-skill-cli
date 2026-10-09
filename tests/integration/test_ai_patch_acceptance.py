import json
import subprocess
import sys

from tests.m4_support import VerifyProject, VULNERABLE


class AIPatchAcceptance(VerifyProject):
    def configure(self,trust='standard',fallback=False):
        response=dict(status='PATCH_PROPOSED',finding_id='SEC-0001',
            unified_diff='--- a/sample.py\n+++ b/sample.py\n@@ -1,2 +1,2 @@\n def parse(value):\n-    return eval(value)\n+    return int(value)\n',
            summary='TEST_ONLY fix',changed_files=['sample.py'],suggested_tests=['parse integer'],patch_source='native')
        code='import sys,json;request=json.load(sys.stdin);assert request["finding"]["id"]=="SEC-0001";print('+repr(json.dumps(response))+')'
        config=self.config()
        config['ai']['providers']=[dict(id='native',adapter='command',enabled=True,trust=trust,executable=sys.executable,argv=['-c',code],timeout_seconds=10)]
        if fallback:config['ai']['providers'].insert(0,dict(id='bad',adapter='command',enabled=True,trust='standard',executable=sys.executable,argv=['-c','print("TEST_ONLY malformed")'],timeout_seconds=10))
        self.write_config(config)

    def invoke(self,*args):
        result=subprocess.run([sys.executable,str(self.root/'security-cli/security'),*args,'--json'],cwd=self.root,capture_output=True,text=True,timeout=40)
        return result,json.loads(result.stdout)

    def test_real_cli_native_adapter_proposal_preserves_source_and_audit(self):
        self.configure()
        process,report=self.invoke('ai-patch','SEC-0001','--provider','native')
        self.assertEqual(process.returncode,20,report)
        self.assertEqual(report['terminal_state'],'PATCH_PROPOSED')
        self.assertFalse(report['patch_applied']);self.assertFalse(report['finding_closed'])
        self.assertEqual((self.root/'sample.py').read_text(),VULNERABLE)
        self.assertTrue((self.root/report['report_reference']).is_file())
        process,report=self.invoke('findings','show','SEC-0001')
        self.assertEqual(report['finding']['status'],'PATCH_PROPOSED')
        process,report=self.invoke('findings','rebuild-index');self.assertEqual(process.returncode,0,report)
        process,report=self.invoke('doctor');self.assertEqual(process.returncode,0,report)

    def test_real_cli_fallback_restricted_and_empty_registry(self):
        self.configure(trust='restricted',fallback=True)
        process,report=self.invoke('ai-patch','SEC-0001')
        self.assertEqual(process.returncode,20,report)
        self.assertEqual(len(report['attempts']),2)
        self.assertTrue(report['human_review_required'])
        self.assertEqual(report['trust'],'restricted')
        config=self.config();config['ai']['providers']=[];self.write_config(config)
        process,report=self.invoke('ai-patch','SEC-0001')
        self.assertEqual(process.returncode,20,report)
        self.assertEqual(report['terminal_state'],'human_review')
        process,report=self.invoke('doctor');self.assertEqual(process.returncode,0,report)
