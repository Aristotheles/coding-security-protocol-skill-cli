"""Actual subprocess TEST_ONLY scanners, test and runtime adapters for unit checks."""
import sys

from tests.support import DoctorProject
from lib import normalize, store
from lib.scan import run_scan
from lib.storage_io import atomic_json

VULNERABLE = 'def parse(value):\n    return eval(value)\n'
FIXED = 'def parse(value):\n    return int(value)\n'

SCANNER = '''import json,sys,pathlib
if '--version' in sys.argv:
    print('TEST_ONLY_SCANNER 1');sys.exit(0)
path=pathlib.Path(sys.argv[-1])
if not path.is_file():
    path=path/'sample.py'
results=[]
if 'return eval(value)' in path.read_text():
    line=next(i+1 for i,text in enumerate(path.read_text().splitlines()) if 'return eval(value)' in text)
    results=[{'ruleId':'TEST_ONLY_EVAL','message':{'text':'TEST_ONLY_INJECTION'},
    'locations':[{'physicalLocation':{'artifactLocation':{'uri':str(path)},
    'region':{'startLine':line,'snippet':{'text':'return eval(value)'}}}}]}]
print(json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'TEST_ONLY_SCANNER',
    'rules':[{'id':'TEST_ONLY_EVAL','properties':{'category':'code-injection','tags':['HIGH']}}]}},'results':results}]}))
'''


class VerifyProject(DoctorProject):
    scanner_category='code-injection'

    def setUp(self):
        super().setUp()
        (self.root/'sample.py').write_text(VULNERABLE,encoding='utf-8')
        (self.root/'test-only-scanner.py').write_text(SCANNER.replace("'code-injection'",repr(self.scanner_category)),encoding='utf-8')
        config=self.config()
        for profile in config['scanners'].values():
            profile.update(enabled=True,mandatory=True,executable=sys.executable,
                           argv=['test-only-scanner.py','{target}'])
            profile['severity_mapping']['HIGH']='HIGH'
        config['stack']={'tests':{'argv':[sys.executable,'-c','from sample import parse; assert parse("7") == 7; print("TEST_ONLY_TESTS_EXECUTED")'],'timeout_seconds':10}}
        config['runtime_verify']={'mode':'command','argv':[sys.executable,'-c','from sample import parse; assert parse("8") == 8; print("TEST_ONLY_RUNTIME_EXECUTED")'],
                                 'timeout_seconds':10,'environment':'test'}
        self.write_config(config)
        scan=run_scan(self.root,'sample.py')
        self.assertEqual(scan['exit_code'],0,scan)
        normalize.normalize(self.root,scan['run_id'])
        store.update(self.root,scan['run_id'])
        self.context=dict(version=1,event='merge',changed_files=['sample.py'],
            dependencies=dict(lockfiles_changed=[],added=[],sbom_enabled=False,sbom_diff=None),
            patch=dict(source='human',trust='standard',finding_ids=['SEC-0001'],rescan_run_id=None),
            coverage=dict(enabled=False,before=None,after=None),evidence={})
        self.write_context()

    def write_context(self):
        atomic_json(self.root/'.security/evidence/change.json',self.context)

    def fix(self):
        (self.root/'sample.py').write_text(FIXED,encoding='utf-8')

    def verify(self,close=False,**kwargs):
        from lib.verify import run_verify
        return run_verify(self.root,'sample.py','.security/evidence/change.json',close=close,**kwargs)
