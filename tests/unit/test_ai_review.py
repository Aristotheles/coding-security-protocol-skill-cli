import json
import sys
from copy import deepcopy
from unittest.mock import patch

from tests.m4_support import VerifyProject, VULNERABLE
from tests.unit.test_ai_patch import DIFF
from lib import ai_patch, doctor, store
from lib.scan import run_scan

BRIDGE = """import json,sys,time
request=json.load(sys.stdin)
mode=sys.argv[1]
identifier=sys.argv[2]
if mode=='quota':print('TEST_ONLY quota 429',file=sys.stderr);sys.exit(3)
if mode=='tool':sys.exit(4)
if mode=='timeout':time.sleep(3)
if mode=='malformed':print('TEST_ONLY invalid JSON');sys.exit(0)
if request.get('task')=='review':
    response=dict(status=mode if mode in ('APPROVE','REJECT','CONCERNS') else 'APPROVE',
        finding_id=request['finding_id'],patch_source=request['patch_source'],
        reviewer_source=identifier,patch_sha256=request['patch_sha256'],summary='TEST_ONLY advisory opinion')
    if mode=='schema':response['status']='CLOSED'
    if mode=='missing':response.pop('finding_id')
    if mode=='wrong_id':response['finding_id']='SEC-9999'
    if mode=='wrong_author':response['patch_source']='TEST_ONLY_OTHER'
    if mode=='wrong_reviewer':response['reviewer_source']='TEST_ONLY_OTHER'
    if mode=='wrong_hash':response['patch_sha256']='0'*64
else:
    response=dict(status='PATCH_PROPOSED',finding_id=request['finding']['id'],
        unified_diff=DIFF,summary='TEST_ONLY fix',changed_files=['sample.py'],
        suggested_tests=['test parsing'],patch_source=identifier)
    if mode=='schema':response['status']='CLOSED'
print(json.dumps(response))
""".replace('unified_diff=DIFF','unified_diff='+repr(DIFF))


class AIReviewTests(VerifyProject):
    def configure(self, modes=('APPROVE',), author_trust='standard', reviewer_trust='standard'):
        config=self.config()
        config['ai']['providers']=[self.provider('author','APPROVE',author_trust,['patch'])]
        for i,mode in enumerate(modes):
            config['ai']['providers'].append(self.provider('reviewer'+str(i),mode,reviewer_trust,['review']))
        self.write_config(config)

    def provider(self,identifier,mode,trust='standard',roles=None):
        bridge=self.root/'.agent/test-only-review-bridge.py'
        bridge.parent.mkdir(exist_ok=True)
        bridge.write_text(BRIDGE,encoding='utf-8')
        result=dict(id=identifier,adapter='command',enabled=True,trust=trust,
            executable=sys.executable,argv=[str(bridge),mode,identifier],timeout_seconds=1 if mode=='timeout' else 10)
        if roles is not None:result['roles']=roles
        return result

    def run_patch(self):return ai_patch.run_ai_patch(self.root,'SEC-0001')

    def test_independent_approval_binds_diff_and_never_applies_or_closes(self):
        self.configure();result=self.run_patch();review=result['review']
        self.assertEqual(result['terminal_state'],'PATCH_PROPOSED',result)
        self.assertEqual(result['exit_code'],20)
        self.assertEqual(review['status'],'APPROVE')
        self.assertEqual(review['reviewer_source'],'reviewer0')
        self.assertEqual(review['confidence'],'INDEPENDENT_ADVISORY')
        self.assertTrue(review['advisory']);self.assertFalse(result['human_review_required'])
        canonical=store.show(self.root,'SEC-0001')['finding']
        self.assertEqual(canonical['patch_proposal']['review'],review)
        self.assertEqual(canonical['patch_proposal']['patch_sha256'],review['patch_sha256'])
        self.assertEqual(canonical['status'],'PATCH_PROPOSED')
        self.assertEqual((self.root/'sample.py').read_text(),VULNERABLE)
        self.assertFalse(result['patch_applied']);self.assertFalse(result['finding_closed'])

    def test_contract_failure_fallback_once_per_reviewer_and_raw_audit(self):
        baseline=(self.root/'.security/findings/SEC-0001.json').read_bytes()
        for mode in ['quota','timeout','tool','malformed','schema','missing','wrong_id','wrong_author','wrong_reviewer','wrong_hash']:
            with self.subTest(mode=mode):
                (self.root/'.security/findings/SEC-0001.json').write_bytes(baseline)
                self.configure((mode,'APPROVE'));result=self.run_patch();review=result['review']
                self.assertEqual(review['status'],'APPROVE',result)
                self.assertEqual(len(review['attempts']),2)
                self.assertEqual(review['attempts'][0]['result'],'REJECTED_OUTPUT')
                self.assertTrue(review['attempts'][0]['fallback_reason'])
                self.assertEqual(review['attempts'][1]['response_validation'],'VALIDATED')
                self.assertTrue((self.root/review['response_reference']).is_file())

    def test_disagreement_is_not_retried_to_find_approval_and_survives_verification(self):
        self.configure(('CONCERNS','APPROVE'));result=self.run_patch()
        self.assertEqual(result['review']['status'],'CONCERNS')
        self.assertEqual(len(result['review']['attempts']),1)
        self.assertTrue(result['human_review_required'])
        self.fix();verified=self.verify(close=True)
        self.assertEqual(verified['exit_code'],20,verified)
        self.assertTrue(any(p['policy_id']=='AI_REVIEW' for p in verified['gate']['policies']))
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'PATCH_PROPOSED')

    def test_reject_and_restricted_approval_cannot_inherit_standard_trust(self):
        self.configure(('REJECT',));result=self.run_patch()
        self.assertEqual(result['review']['status'],'REJECT')
        self.assertEqual(result['review']['terminal_state'],'human_review')
        self.configure(author_trust='restricted');result=self.run_patch()
        self.assertEqual(result['trust'],'restricted');self.assertTrue(result['human_review_required'])
        self.assertEqual(result['review']['status'],'APPROVE')
        self.fix();result=self.verify(close=True)
        self.assertEqual(result['exit_code'],20,result)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'PATCH_PROPOSED')

    def test_restricted_reviewer_is_not_human_approval(self):
        self.configure(reviewer_trust='restricted');result=self.run_patch()
        self.assertEqual(result['trust'],'standard')
        self.assertEqual(result['review']['reviewer_trust'],'restricted')
        self.assertTrue(result['human_review_required'])

    def test_no_independent_reviewer_reduced_confidence_and_sensitive_requires_human(self):
        self.configure(())
        config=self.config();config['ai']['providers'][0].pop('roles');self.write_config(config)
        result=self.run_patch()
        self.assertEqual(result['review']['attempts'],[])
        self.assertEqual(result['review']['confidence'],'REDUCED')
        self.assertEqual(result['review']['terminal_state'],'human_review')
        self.assertFalse(result['human_review_required'])
        from lib import ai_review
        policies=deepcopy(__import__('lib.policy',fromlist=['load_policy']).load_policy(self.root))
        next(p for p in policies if p['id']=='POL-006')['paths']=['sample.py']
        with patch.object(ai_review.policy,'load_policy',return_value=policies):
            result=self.run_patch()
        self.assertTrue(result['human_review_required'])
        self.assertEqual(result['review']['terminal_state'],'human_review')

    def test_review_schema_missing_or_invalid_never_canonical_success(self):
        self.configure();before=(self.root/'.security/findings/SEC-0001.json').read_bytes()
        for content in ['', '{"type":"invalid"}']:
            (self.root/'schemas/ai-review-response.schema.json').write_text(content)
            result=self.run_patch();self.assertNotEqual(result['exit_code'],0)
            self.assertNotIn('canonical_written',result)
            self.assertEqual(before,(self.root/'.security/findings/SEC-0001.json').read_bytes())

    def test_review_source_or_control_drift_rejected_before_commit(self):
        self.configure();original=ai_patch.invoke
        def drift(*args,**kwargs):
            response=original(*args,**kwargs)
            if kwargs.get('task')=='review':
                (self.root/'sample.py').write_text(VULNERABLE+'# TEST_ONLY drift\n')
            return response
        with patch.object(ai_patch,'invoke',side_effect=drift):result=self.run_patch()
        self.assertEqual(result['terminal_state'],'human_review',result)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'OPEN')

    def test_roles_config_is_strict_and_removal_preserves_manual_core(self):
        self.configure();config=self.config()
        for roles in [[],['invalid'],['review','review'],'review']:
            bad=deepcopy(config);bad['ai']['providers'][0]['roles']=roles
            with self.assertRaises(doctor.ConfigError):doctor.validate_config(bad)
        config['ai']['providers']=[];self.write_config(config)
        self.assertEqual(run_scan(self.root,'sample.py')['exit_code'],0)
        result=self.run_patch();self.assertEqual(result['terminal_state'],'human_review')
        self.assertEqual(result['attempts'],[])
        self.fix();result=self.verify(close=True)
        self.assertEqual(result['exit_code'],0,result)
        self.assertEqual(result['closed_ids'],['SEC-0001'])

    def test_valid_approval_cannot_replace_failed_tests_or_rescan(self):
        self.configure();self.run_patch()
        result=self.verify(close=True)
        self.assertEqual(result['exit_code'],60,result)
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['status'],'PATCH_PROPOSED')

    def test_exhausted_reviewers_and_secret_diff_route_to_human_without_forwarding(self):
        self.configure(('schema','tool'));result=self.run_patch()
        self.assertIsNone(result['review']['status'])
        self.assertEqual(result['review']['terminal_state'],'human_review')
        self.assertEqual(len(result['review']['attempts']),2)
        self.configure();original=ai_patch.invoke
        def secret(*args,**kwargs):
            response=original(*args,**kwargs)
            if kwargs.get('task')!='review':
                response['unified_diff']=DIFF.replace('return int(value)','return "TEST_ONLY_DO_NOT_USE" # token = "TEST_ONLY_DO_NOT_USE"')
            return response
        with patch.object(ai_patch,'invoke',side_effect=secret):result=self.run_patch()
        self.assertEqual(result['review']['attempts'],[])
        self.assertTrue(result['human_review_required'])

    def test_codex_reviewer_uses_review_schema_and_binding_prompt(self):
        provider=dict(id='reviewer',adapter='codex',enabled=True,trust='standard',executable=sys.executable)
        folder=self.root/'.security/evidence/test-only-codex-review';folder.mkdir()
        request=dict(task='review',finding_id='SEC-0001',patch_source='author',patch_sha256='a'*64)
        response=dict(status='APPROVE',finding_id='SEC-0001',patch_source='author',reviewer_source='reviewer',patch_sha256='a'*64,summary='TEST_ONLY')
        def execute(argv,cwd,timeout,out,err,**kwargs):
            from pathlib import Path
            schema=json.loads(Path(argv[argv.index('--output-schema')+1]).read_text())
            self.assertEqual(schema['properties']['status']['enum'],['APPROVE','REJECT','CONCERNS'])
            prompt=kwargs['stdin'].read().decode();self.assertIn('advisory opinion',prompt)
            self.assertIn('patch_sha256',prompt);self.assertIn('read-only',argv)
            out.write_text('');err.write_text('')
            Path(argv[argv.index('--output-last-message')+1]).write_text(json.dumps(response))
            return 0,False
        with patch.object(ai_patch,'execute',side_effect=execute):
            self.assertEqual(ai_patch.invoke(self.root,provider,request,folder,task='review'),response)

    def test_two_codex_aliases_do_not_count_as_independent_providers(self):
        from lib import ai_review
        self.configure()
        config=self.config()
        for p in config['ai']['providers']:p['adapter']='codex'
        request=ai_patch.minimal_request(self.root,store.show(self.root,'SEC-0001')['finding'])
        proposal=dict(unified_diff=DIFF,changed_files=['sample.py'])
        folder=self.root/'.security/evidence/test-only-alias';folder.mkdir()
        diff=folder/'proposal.diff';diff.write_text(DIFF,encoding='utf-8')
        with patch.object(ai_patch,'invoke') as invoke:
            result=ai_review.review_proposal(self.root,config,config['ai']['providers'][0],request,proposal,diff,folder)
        invoke.assert_not_called();self.assertEqual(result['confidence'],'REDUCED')

    def test_configured_author_order_and_mixed_trust_fallback_preserved(self):
        self.configure()
        config=self.config()
        config['ai']['providers']=[self.provider('unavailable','schema','standard',['patch']),
                                  self.provider('local','APPROVE','restricted',['patch']),
                                  self.provider('reviewer','APPROVE','standard',['review'])]
        self.write_config(config);result=self.run_patch()
        self.assertEqual([a['provider'] for a in result['attempts']],['unavailable','local'])
        self.assertEqual(result['attempts'][0]['fallback_reason'],'schema_violation')
        self.assertEqual(result['trust'],'restricted')
        self.assertTrue(result['human_review_required'])
        self.assertEqual(result['review']['reviewer_source'],'reviewer')
        self.assertEqual(store.show(self.root,'SEC-0001')['finding']['patch_proposal']['trust'],'restricted')
