import hashlib
import json
import subprocess
import sys
import unittest

from tests.support import REPOSITORY


class RealScannerAcceptance(unittest.TestCase):
    def test_real_binaries_sarif_findings_metadata_and_preservation(self):
        command = [sys.executable, str(REPOSITORY / 'security-cli/security'), 'scan',
                   '--target', 'tests/fixtures/scanner-project', '--json']
        reports = []
        hashes = {}
        for _ in range(2):
            result = subprocess.run(command, cwd=REPOSITORY, text=True, capture_output=True,
                                    timeout=180, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            reports.append(report)
            for item in report['scanners']:
                self.assertEqual(item['state'], 'FINDINGS', item)
                self.assertGreater(item['findings_count'], 0)
                self.assertTrue(item['version'])
                self.assertIsInstance(item['argv'], list)
                self.assertTrue(item['started_at'].endswith('Z'))
                self.assertTrue(item['finished_at'].endswith('Z'))
                raw = REPOSITORY / item['raw_reference']
                data = json.loads(raw.read_text(encoding='utf-8-sig'))
                ids = {r.get('ruleId') for run in data['runs'] for r in run['results']}
                self.assertTrue(any('csp-python-eval' in value for value in ids) if item['tool']=='semgrep'
                                else 'csp-test-only-secret' in ids, ids)
                self.assertTrue((REPOSITORY / item['stderr_reference']).exists())
                hashes[raw] = hashlib.sha256(raw.read_bytes()).hexdigest()
        self.assertNotEqual(reports[0]['run_id'], reports[1]['run_id'])
        for path, digest in hashes.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
