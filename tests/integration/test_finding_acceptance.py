import json
from pathlib import Path
import shutil
import subprocess
import sys

from tests.support import DoctorProject, REPOSITORY, doctor
from lib import normalize, store
from lib.storage_io import atomic_json


class RealFindingAcceptance(DoctorProject):
    def invoke(self, *args):
        result = subprocess.run([sys.executable, str(self.root / 'security-cli/security'), *args, '--json'],
                                cwd=self.root, capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_real_scan_normalize_store_dedup_rebuild_and_seeded_regression(self):
        rules = self.root / '.security/rules'
        shutil.copytree(REPOSITORY / '.security/rules', rules)
        config = doctor.load_yaml(REPOSITORY / 'security.config.yml')
        config['scanners']['trivy']['executable'] = str(REPOSITORY / '.tools/trivy/trivy.exe')
        self.write_config(config)
        app = self.root / 'app'
        app.mkdir()
        source = app / 'dangerous.py'
        original = (REPOSITORY / 'tests/fixtures/scanner-project/dangerous.py').read_text(encoding='utf-8')
        source.write_text(original, encoding='utf-8')

        def observe():
            report = self.invoke('scan', '--target', 'app')
            self.invoke('normalize', '--run-id', report['run_id'])
            return self.invoke('findings', 'update', '--run-id', report['run_id'])

        first = observe()
        self.assertEqual(set(first['ids']), {'SEC-0001', 'SEC-0002'})
        self.assertTrue(all(item['status'] == 'OPEN' for item in store.load_findings(self.root)))
        second = observe()
        self.assertEqual(first['ids'], second['ids'])
        self.assertEqual(len(store.load_findings(self.root)), 2)
        finding = next(item for item in store.load_findings(self.root) if item['category'] == 'code-injection')
        finding_id = finding['id']
        # A historical CLOSED fixture, not a production closure or fake verification.
        finding['status'] = 'CLOSED'
        finding['history'].append({'timestamp': finding['last_seen'], 'status': 'CLOSED',
                                   'event': 'TEST_ONLY_SEEDED_HISTORICAL_CLOSED'})
        atomic_json(self.root / '.security/findings' / (finding_id + '.json'), finding)
        third = observe()
        self.assertEqual(first['ids'], third['ids'])
        reopened = self.invoke('findings', 'show', finding_id)['finding']
        self.assertEqual(reopened['status'], 'REOPENED')
        self.assertTrue(reopened['regression'])
        source.write_text(original.replace('eval(user_input)', 'user_input'), encoding='utf-8')
        observe()
        self.assertEqual(store.show(self.root, finding_id)['finding']['status'], 'REOPENED')
        (self.root / '.security/security.db').write_bytes(b'TEST_ONLY_CORRUPT_INDEX')
        rebuilt = self.invoke('findings', 'rebuild-index')
        self.assertEqual(rebuilt['total_findings'], 2)
        self.assertEqual(self.invoke('doctor')['exit_code'], 0)
