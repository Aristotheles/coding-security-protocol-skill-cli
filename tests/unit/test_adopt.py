import tempfile
from pathlib import Path

from tests.support import DoctorProject, doctor
from lib import adopt


class AdoptionTests(DoctorProject):
    def target(self, parent):
        root = parent / 'application'
        root.mkdir()
        return root

    def test_preview_is_review_required_and_writes_nothing(self):
        with tempfile.TemporaryDirectory(prefix='csp-adopt-test-') as temp:
            root = self.target(Path(temp))
            report, _, _ = adopt.plan_adoption(root, self.root / 'security.config.yml',
                                               self.root / '.security/policies/security-policy.yml')
            self.assertEqual(report['result'], 'REVIEW_REQUIRED')
            self.assertEqual(report['exit_code'], 20)
            self.assertIn('security.config.yml', report['files_to_create'])
            self.assertFalse((root / '.security').exists())

    def test_apply_installs_contract_and_doctor_accepts_project(self):
        with tempfile.TemporaryDirectory(prefix='csp-adopt-test-') as temp:
            root = self.target(Path(temp))
            report = adopt.apply_adoption(root, self.root / 'security.config.yml',
                                          self.root / '.security/policies/security-policy.yml')
            self.assertEqual((report['result'], report['exit_code']), ('ADOPTED', 0), report)
            self.assertTrue((root / 'schemas/finding.schema.json').is_file())
            self.assertTrue((root / '.security/policies/security-policy.yml').is_file())
            doctor_report = doctor.run_doctor(root, external_project=True)
        self.assertEqual(doctor_report['result'], 'PASS', doctor_report)

    def test_conflict_preserves_existing_policy_and_writes_nothing_else(self):
        with tempfile.TemporaryDirectory(prefix='csp-adopt-test-') as temp:
            root = self.target(Path(temp))
            policy = root / '.security/policies/security-policy.yml'
            policy.parent.mkdir(parents=True)
            policy.write_text('human policy\n', encoding='utf-8')
            report = adopt.apply_adoption(root, self.root / 'security.config.yml',
                                          self.root / '.security/policies/security-policy.yml')
            self.assertEqual((report['result'], report['exit_code']), ('REVIEW_REQUIRED', 20))
            self.assertIn('.security/policies/security-policy.yml', report['conflicts'])
            self.assertEqual(policy.read_text(encoding='utf-8'), 'human policy\n')
            self.assertFalse((root / 'security.config.yml').exists())

    def test_invalid_config_is_rejected_before_writes(self):
        with tempfile.TemporaryDirectory(prefix='csp-adopt-test-') as temp:
            parent = Path(temp)
            root = self.target(parent)
            invalid = parent / 'invalid.yml'
            invalid.write_text('version: 1\nscanners: {}\n', encoding='utf-8')
            with self.assertRaises(doctor.ConfigError):
                adopt.apply_adoption(root, invalid,
                                     self.root / '.security/policies/security-policy.yml')
            self.assertEqual(list(root.iterdir()), [])

    def test_invalid_policy_is_rejected_before_writes(self):
        with tempfile.TemporaryDirectory(prefix='csp-adopt-test-') as temp:
            parent = Path(temp)
            root = self.target(parent)
            invalid = parent / 'invalid-policy.yml'
            invalid.write_text('version: 1\npolicies: []\n', encoding='utf-8')
            with self.assertRaises(doctor.ConfigError):
                adopt.apply_adoption(root, self.root / 'security.config.yml', invalid)
            self.assertEqual(list(root.iterdir()), [])
