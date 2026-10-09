"""Actual CLI and native TEST_ONLY bridges; not live independent AI proof."""
import json
import subprocess
import sys

from tests.m4_support import VerifyProject, VULNERABLE
import tests.unit.test_ai_review as fixtures


class AIReviewAcceptance(VerifyProject):
    configure = fixtures.AIReviewTests.configure
    provider = fixtures.AIReviewTests.provider

    def invoke(self, expected, *args):
        process=subprocess.run([sys.executable,str(self.root/'security-cli/security'),*args,'--json'],
                               cwd=self.root,capture_output=True,text=True,timeout=50)
        self.assertEqual(process.returncode,expected,process.stdout+process.stderr)
        return json.loads(process.stdout)

    def test_native_cli_review_contract_fallback_and_no_fake_verification(self):
        self.configure(('wrong_hash','APPROVE'))
        result=self.invoke(20,'ai-patch','SEC-0001','--provider','author')
        self.assertEqual(result['review']['reviewer_source'],'reviewer1')
        self.assertEqual(result['review']['attempts'][0]['fallback_reason'],'review_patch_binding_mismatch')
        self.assertEqual(result['review']['attempts'][1]['response_validation'],'VALIDATED')
        self.assertFalse(result['finding_closed']);self.assertFalse(result['patch_applied'])
        self.assertEqual((self.root/'sample.py').read_text(),VULNERABLE)
        persisted=json.loads((self.root/result['report_reference']).read_text())
        self.assertEqual(persisted['review'],result['review'])
        failed=self.invoke(60,'verify','SEC-0001','--target','sample.py','--input','.security/evidence/change.json','--close')
        self.assertEqual(failed['closed_ids'],[])

    def test_provider_removal_empty_chain_manual_closure_and_restricted_trust(self):
        self.configure(author_trust='restricted')
        result=self.invoke(20,'ai-patch','SEC-0001')
        self.assertEqual(result['trust'],'restricted');self.assertTrue(result['human_review_required'])
        self.assertEqual(result['review']['status'],'APPROVE')
        config=self.config();config['ai']['providers']=[];self.write_config(config)
        self.invoke(0,'doctor');self.invoke(0,'scan','--target','sample.py')
        result=self.invoke(20,'ai-patch','SEC-0001');self.assertEqual(result['terminal_state'],'human_review')
        self.fix()
        result=self.invoke(20,'verify','SEC-0001','--target','sample.py','--input','.security/evidence/change.json','--close')
        self.assertTrue(any(p['policy_id']=='TRUST' for p in result['gate']['policies']))

    def test_empty_provider_registry_allows_actual_manual_cli_closure(self):
        config=self.config();config['ai']['providers']=[];self.write_config(config)
        result=self.invoke(20,'ai-patch','SEC-0001')
        self.assertEqual(result['terminal_state'],'human_review')
        self.assertEqual(result['attempts'],[])
        self.fix()
        result=self.invoke(0,'verify','SEC-0001','--target','sample.py','--input','.security/evidence/change.json','--close')
        self.assertEqual(result['closed_ids'],['SEC-0001'])
        self.invoke(0,'findings','rebuild-index')
