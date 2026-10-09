from pathlib import Path
import shutil
import sys
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / 'security-cli'))
from lib import doctor


class DoctorProject(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='csp-doctor-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in doctor.REQUIRED_DIRS:
            (self.root / name).mkdir(parents=True, exist_ok=True)
        for name in doctor.REQUIRED_FILES + (
                'security.config.yml', 'schemas/finding.schema.json',
                '.security/policies/security-policy.yml',
                'security-cli/lib/__init__.py', 'security-cli/lib/doctor.py',
                'security-cli/security.cmd'):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPOSITORY / name, target)
        shutil.copy2(REPOSITORY / 'security-cli/lib/scan.py', self.root / 'security-cli/lib/scan.py')
        for name in ('storage_io.py', 'normalize.py', 'store.py', 'gate_audit.py', 'policy.py', 'verify.py', 'ai_patch.py', 'ai_review.py', 'sarif-2.1.0.schema.json'):
            shutil.copy2(REPOSITORY / 'security-cli/lib' / name, self.root / 'security-cli/lib' / name)
        for name in ('ai-patch-request.schema.json', 'ai-patch-response.schema.json', 'ai-review-request.schema.json', 'ai-review-response.schema.json'):
            shutil.copy2(REPOSITORY / 'schemas' / name, self.root / 'schemas' / name)
        config = self.config()
        for name, profile in config['scanners'].items():
            profile.update(executable=name, enabled=False, mandatory=False)
        self.write_config(config)

    def config(self):
        return doctor.load_yaml(self.root / 'security.config.yml')

    def write_config(self, data):
        yaml, _ = doctor.dependencies()
        (self.root / 'security.config.yml').write_text(yaml.safe_dump(data), encoding='utf-8')

    def result(self):
        return doctor.run_doctor(self.root)
