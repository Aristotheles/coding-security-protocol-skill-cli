import json
import sys
import sqlite3
from unittest.mock import patch

from tests.m4_support import VerifyProject, VULNERABLE
from lib import ai_patch, store

DIFF = '--- a/sample.py\n+++ b/sample.py\n@@ -1,2 +1,2 @@\n def parse(value):\n-    return eval(value)\n+    return int(value)\n'


class AIPatchTests(VerifyProject):
    def setUp(self):
        super().setUp()
        self.response=dict(status='PATCH_PROPOSED',finding_id='SEC-0001',unified_diff=DIFF,
            summary='TEST_ONLY safe integer parsing',changed_files=['sample.py'],suggested_tests=['test integer parsing'],patch_source='test')

    def providers(self, modes, trust='standard'):
        config=self.config()
        config['ai']['providers']=[]
        for i,mode in enumerate(modes):
            identifier='test' if i==len(modes)-1 else 'bad'+str(i)
            response=dict(self.response,patch_source=identifier)
            if mode=='schema':response['status']='CLOSED'
            if mode=='missing_id':response.pop('finding_id')
            if mode=='wrong_id':response['finding_id']='SEC-9999'
            if mode=='source':response['patch_source']='other'
            if mode=='invalid_diff':response['unified_diff']='execute evil command'
            if mode=='empty':response['unified_diff']=''
            if mode=='dry_run':response['unified_diff']=DIFF.replace('return eval(value)','return absent(value)')
            if mode=='protected':response.update(unified_diff=DIFF.replace('sample.py','security.config.yml'),changed_files=['security.config.yml'])
            if mode=='outside':response.update(unified_diff=DIFF.replace('sample.py','other.py'),changed_files=['other.py']);(self.root/'other.py').write_text(VULNERABLE)
            if mode=='files':response['changed_files']=[]
            if mode=='human':response.update(status='NEEDS_HUMAN',unified_diff='',changed_files=[])
            if mode=='cannot':response.update(status='CANNOT_FIX',unified_diff='',changed_files=[])
            code='import json,sys; r=json.load(sys.stdin); print('+repr(json.dumps(response))+')'
            if mode=='quota':code='import sys; print("TEST_ONLY quota 429",file=sys.stderr);sys.exit(3)'
            if mode=='tool':code='import sys;sys.exit(4)'
            if mode=='timeout':code='import time;time.sleep(3)'
            if mode=='malformed':code='print("not json")'
            config['ai']['providers'].append(dict(id=identifier,adapter='command',enabled=True,trust=trust,
                                                 executable='TEST_ONLY_UNAVAILABLE' if mode=='unavailable' else sys.executable,argv=['-c',code],timeout_seconds=1 if mode=='timeout' else 10))
        self.write_config(config)

    def run_patch(self):return ai_patch.run_ai_patch(self.root,'SEC-0001')

    def test_actual_native_proposal_dry_run_and_no_application_or_closure(self):
        self.providers(['valid'])
        result=self.run_patch()
        self.assertEqual(result['terminal_state'],'PATCH_PROPOSED',result)
        self.assertEqual(result['exit_code'],20)
        self.assertFalse(result['patch_applied']);self.assertFalse(result['finding_closed'])
        self.assertEqual((self.root/'sample.py').read_text(),VULNERABLE)
        finding=store.show(self.root,'SEC-0001')['finding']
        self.assertEqual(finding['status'],'PATCH_PROPOSED')
        self.assertEqual(finding['patch_proposal']['trust'],'standard')
        self.assertTrue((self.root/result['patch_reference']).is_file())
        self.assertEqual(result['attempts'][0]['response_validation'],'VALIDATED')

    def test_fallback_for_every_m5_contract_and_execution_failure(self):
        baseline=(self.root/'.security/findings/SEC-0001.json').read_bytes()
        for mode in ['quota','tool','timeout','malformed','schema','missing_id','wrong_id','source','invalid_diff','empty','dry_run','protected','outside','files','human','cannot','unavailable']:
            with self.subTest(mode=mode):
                (self.root/'.security/findings/SEC-0001.json').write_bytes(baseline)
                self.providers([mode,'valid'])
                result=self.run_patch()
                self.assertEqual(result['terminal_state'],'PATCH_PROPOSED',result)
                self.assertEqual(len(result['attempts']),2)
                self.assertEqual(result['attempts'][0]['result'],'REJECTED')
                self.assertTrue(result['attempts'][0]['fallback_reason'])
                self.assertEqual(result['attempts'][1]['response_validation'],'VALIDATED')

    def test_empty_provider_registry_human_review_without_mutation(self):
        self.providers([])
        before=(self.root/'.security/findings/SEC-0001.json').read_bytes()
        result=self.run_patch()
        self.assertEqual(result['exit_code'],20,result)
        self.assertEqual(result['terminal_state'],'human_review')
        self.assertEqual(result['attempts'],[])
        self.assertEqual(before,(self.root/'.security/findings/SEC-0001.json').read_bytes())

    def test_all_fail_terminal_and_explicit_provider_no_hidden_fallback(self):
        self.providers(['schema','tool'])
        result=self.run_patch()
        self.assertEqual(result['terminal_state'],'human_review',result)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')
        result=ai_patch.run_ai_patch(self.root,'SEC-0001','bad0')
        self.assertEqual(len(result['attempts']),1)
        self.assertEqual(ai_patch.run_ai_patch(self.root,'SEC-0001','absent')['exit_code'],30)

    def test_restricted_provenance_cannot_be_downgraded_at_verified_closure(self):
        self.providers(['valid'],trust='restricted')
        result=self.run_patch();self.assertTrue(result['human_review_required'])
        self.fix()
        # Caller incorrectly labels AI patch human/standard: canonical trust wins.
        result=self.verify(close=True)
        self.assertEqual(result['exit_code'],20,result)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'PATCH_PROPOSED')
        self.assertTrue(any(p['policy_id']=='TRUST' for p in result['gate']['policies']))

    def test_standard_proposal_requires_real_m4_verification_before_closure(self):
        self.providers(['valid']);self.run_patch();self.fix()
        result=self.verify(close=True)
        self.assertEqual(result['exit_code'],0,result)
        self.assertEqual(result['closed_ids'],['SEC-0001'])

    def test_sensitive_context_refused_before_invocation(self):
        self.providers(['valid'])
        (self.root/'sample.py').write_text(VULNERABLE+'password = "TEST_ONLY_DO_NOT_USE"\n')
        with patch.object(ai_patch,'invoke') as invoke:
            result=self.run_patch()
        invoke.assert_not_called()
        self.assertEqual(result['exit_code'],20,result)
        self.assertIn('sensitive',result['detail'])

    def test_source_drift_and_index_failure_never_report_success(self):
        self.providers(['valid'])
        original=ai_patch.invoke
        def changed(*args):
            result=original(*args)
            (self.root/'sample.py').write_text(VULNERABLE+'# changed\n')
            return result
        with patch.object(ai_patch,'invoke',side_effect=changed):result=self.run_patch()
        self.assertEqual(result['terminal_state'],'human_review',result)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')
        (self.root/'sample.py').write_text(VULNERABLE)
        with patch.object(store,'write_index',side_effect=OSError('TEST_ONLY index failure')):result=self.run_patch()
        self.assertEqual(result['exit_code'],40,result)
        self.assertTrue(result['canonical_written'])
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'PATCH_PROPOSED')
        store.rebuild(self.root)
        with patch.object(store,'write_index',side_effect=sqlite3.OperationalError('TEST_ONLY DB failure')):result=self.run_patch()
        self.assertEqual(result['exit_code'],40,result)
        self.assertTrue(result['canonical_written'])

    def test_paths_binary_metadata_and_traversal_rejected(self):
        self.providers(['valid'])
        finding=store.show(self.root,'SEC-0001')['finding']
        request=ai_patch.minimal_request(self.root,finding)
        for target in ['../sample.py','/sample.py','C:/sample.py','sample.py:stream','Sample.py','schemas/x.json','.security/findings/SEC-0001.json','NUL.py']:
            response=dict(self.response,unified_diff=DIFF.replace('sample.py',target),changed_files=[target])
            with self.subTest(target=target),self.assertRaises(ai_patch.ContractError):ai_patch.parse_diff(self.root,response,request)
        for diff in ['GIT binary patch\n','old mode 100644\n'+DIFF,DIFF+'\n',DIFF.replace('-1,2','-1,99')]:
            with self.assertRaises(ai_patch.ContractError):ai_patch.parse_diff(self.root,dict(self.response,unified_diff=diff),request)

    def test_missing_schema_config_and_unknown_id_fail_closed(self):
        self.providers(['valid'])
        self.assertEqual(ai_patch.run_ai_patch(self.root,'SEC-9999')['exit_code'],50)
        (self.root/'schemas/ai-patch-response.schema.json').unlink()
        self.assertNotEqual(self.run_patch()['exit_code'],0)

    def test_codex_argv_is_read_only_isolated_and_no_model_override_by_default(self):
        provider=dict(id='codex',adapter='codex',enabled=True,trust='standard',executable=sys.executable)
        request=ai_patch.minimal_request(self.root,store.show(self.root,'SEC-0001')['finding'])
        folder=self.root/'.security/evidence/codex-check';folder.mkdir()
        def fake_execute(argv,cwd,timeout,out,err,**kwargs):
            self.assertNotEqual(cwd,self.root)
            self.assertIn('--ignore-user-config',argv)
            self.assertIn('read-only',argv)
            self.assertNotIn('--model',argv)
            self.assertIn('features.shell_tool=false',argv)
            self.assertNotIn('SECRET_TEST_ENV',kwargs['env'])
            self.assertEqual(kwargs['env'].get('SYSTEMROOT'),'C:/TEST_ONLY_WINDOWS')
            out.write_text('');err.write_text('')
            from pathlib import Path
            Path(argv[argv.index('--output-last-message')+1]).write_text(json.dumps(dict(self.response,patch_source='codex')))
            return 0,False
        with patch.object(ai_patch,'execute',side_effect=fake_execute),patch.dict('os.environ',{'SECRET_TEST_ENV':'TEST_ONLY_DO_NOT_USE','SYSTEMROOT':'C:/TEST_ONLY_WINDOWS'}):
            self.assertEqual(ai_patch.invoke(self.root,provider,request,folder)['patch_source'],'codex')
