import hashlib
import json
import sys
from unittest.mock import patch

from tests.support import DoctorProject
from lib import scan


class ScanTests(DoctorProject):
    def profile(self, body=None):
        stub = self.root / 'test-scanner.py'
        if body is None:
            body = "import json; print(json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'test-only'}},'results':[]}]}))"
        stub.write_text(body, encoding='utf-8')
        config = self.config()
        config['scanners']['semgrep'].update(executable=sys.executable, enabled=True,
            mandatory=True, argv=[str(stub), '{target}'], timeout_seconds=5)
        self.write_config(config)
        return config

    def test_disabled_scanners_cannot_pass(self):
        self.assertEqual(scan.run_scan(self.root)['exit_code'], 30)

    def test_malformed_config_no_execution(self):
        (self.root / 'security.config.yml').write_text('scanners: [', encoding='utf-8')
        with patch.object(scan, 'execute') as execute:
            self.assertEqual(scan.run_scan(self.root)['exit_code'], 30)
            execute.assert_not_called()

    def test_clean_success_and_skipped_profile(self):
        self.profile()
        report = scan.run_scan(self.root)
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual([p['state'] for p in report['scanners']], ['CLEAN', 'SKIPPED'])
        self.assertTrue((self.root / report['report_reference']).exists())

    def test_findings_exit_one_distinct_from_failure(self):
        self.profile("import json,sys; print(json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'test-only'}},'results':[{'message':{'text':'TEST_ONLY'}}]}]})); sys.exit(1)")
        report = scan.run_scan(self.root)
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(report['scanners'][0]['state'], 'FINDINGS')
        self.assertEqual(report['scanners'][0]['scanner_exit_code'], 1)

    def test_execution_failure_preserves_streams(self):
        self.profile("import sys; print('partial output'); print('TEST_ONLY_ERROR',file=sys.stderr); sys.exit(2)")
        report = scan.run_scan(self.root)
        self.assertEqual(report['exit_code'], 40)
        item = report['scanners'][0]
        self.assertIn('partial output', (self.root / item['raw_reference']).read_text())
        self.assertIn('TEST_ONLY_ERROR', (self.root / item['stderr_reference']).read_text())

    def test_zero_exit_invalid_evidence_fails_closed(self):
        for body in ("print('')", "print('{}')", "print('not json')",
                     "print('{\"version\":\"2.1.0\",\"runs\":[]}')"):
            self.profile(body)
            self.assertEqual(scan.run_scan(self.root)['exit_code'], 40)

    def test_sarif_execution_error_even_zero_exit(self):
        self.profile("import json; print(json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'test-only'}},'results':[],'invocations':[{'executionSuccessful':False}]}]}))")
        self.assertEqual(scan.run_scan(self.root)['exit_code'], 40)

    def test_timeout_preserves_partial_evidence(self):
        config = self.profile("import time; print('partial',flush=True); time.sleep(20)")
        config['scanners']['semgrep']['timeout_seconds'] = 1
        self.write_config(config)
        report = scan.run_scan(self.root)
        self.assertEqual(report['exit_code'], 40)
        self.assertTrue(report['scanners'][0]['timed_out'])
        self.assertIn('partial', (self.root / report['scanners'][0]['raw_reference']).read_text())

    def test_missing_scanner_enabled_or_mandatory(self):
        config = self.profile()
        for mandatory in (True, False):
            config['scanners']['semgrep'].update(executable='CSP_TEST_ONLY_MISSING', mandatory=mandatory)
            self.write_config(config)
            self.assertEqual(scan.run_scan(self.root)['exit_code'], 40)

    def test_disabled_mandatory_scanner_is_config_error(self):
        config = self.profile()
        config['scanners']['trivy'].update(mandatory=True, enabled=False)
        self.write_config(config)
        self.assertEqual(scan.run_scan(self.root)['exit_code'], 30)

    def test_invalid_profile_types_and_placeholder(self):
        for field, value in (('argv', 'echo unsafe'), ('timeout_seconds', 0),
                              ('output_format', 'text'), ('severity_mapping', {}),
                              ('argv', ['--missing-target'])):
            config = self.profile()
            config['scanners']['semgrep'][field] = value
            self.write_config(config)
            self.assertEqual(scan.run_scan(self.root)['exit_code'], 30)

    def test_unique_ids_and_no_overwrite(self):
        self.profile()
        first = scan.run_scan(self.root)
        raw = self.root / first['scanners'][0]['raw_reference']
        digest = hashlib.sha256(raw.read_bytes()).hexdigest()
        second = scan.run_scan(self.root)
        self.assertNotEqual(first['run_id'], second['run_id'])
        self.assertEqual(hashlib.sha256(raw.read_bytes()).hexdigest(), digest)

    def test_targets_must_stay_in_project(self):
        self.profile()
        self.assertEqual(scan.run_scan(self.root, '..')['exit_code'], 30)
        self.assertEqual(scan.run_scan(self.root, 'does-not-exist')['exit_code'], 30)

    def test_metacharacters_are_literal_arguments(self):
        config = self.profile("import sys,json; print(json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'test-only'}},'results':[]}]})); print(sys.argv,file=sys.stderr)")
        config['scanners']['semgrep']['argv'].insert(1, '; echo CSP_TEST_ONLY')
        self.write_config(config)
        report = scan.run_scan(self.root)
        self.assertEqual(report['exit_code'], 0)
        self.assertIn('; echo CSP_TEST_ONLY', (self.root / report['scanners'][0]['stderr_reference']).read_text())

    def test_shell_launcher_is_rejected(self):
        with patch.object(scan.shutil, 'which', return_value='test.cmd'):
            with self.assertRaises(ValueError):
                scan.executable_path(self.root, 'test')
