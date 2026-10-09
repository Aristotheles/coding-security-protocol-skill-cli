import json
import sys
import subprocess
from unittest.mock import patch

from tests.m2_support import FindingProject, normalize, store
from lib.storage_io import atomic_json, store_lock


class NormalizeTests(FindingProject):
    def test_fingerprint_survives_json_key_sorting(self):
        context = {'scope': 'example', 'code': 'eval(value)'}
        fp = normalize.fingerprint('code-injection', 'sample.py', context)
        restored = json.loads(json.dumps(context, sort_keys=True))
        self.assertEqual(fp, normalize.fingerprint('code-injection', 'sample.py', restored))
        self.assertNotEqual(fp, normalize.fingerprint('code-injection', 'sample.py', dict(context, scope='different')))

    def test_cross_tool_dedup_combines_sources_and_valid_merged_sarif(self):
        run_id = self.evidence(tools=('semgrep', 'trivy'))
        result = normalize.normalize(self.root, run_id)
        self.assertEqual(result['findings_count'], 1)
        data = normalize.load_normalized(self.root, run_id)
        self.assertEqual({source['tool'] for source in data['findings'][0]['sources']}, {'semgrep', 'trivy'})
        normalize.schema_validator(self.root / 'security-cli/lib/sarif-2.1.0.schema.json').validate(
            normalize.read_json(self.root / result['merged_reference']))

    def test_stable_fingerprint_when_lines_move(self):
        run_id = self.evidence()
        first, _ = normalize.collect(self.root, run_id)
        raw = self.root / '.security/raw/semgrep' / (run_id + '.sarif')
        data = normalize.read_json(raw)
        data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine'] = 4
        atomic_json(raw, data)
        (self.root / 'sample.py').write_text('\n\ndef example(value):\n    return eval(value)\n', encoding='utf-8')
        second, _ = normalize.collect(self.root, run_id)
        self.assertEqual(first['findings'][0]['fingerprint'], second['findings'][0]['fingerprint'])

    def test_missing_required_raw_fails(self):
        run_id = self.evidence()
        (self.root / '.security/raw/semgrep' / (run_id + '.sarif')).unlink()
        with self.assertRaises(OSError):
            normalize.normalize(self.root, run_id)
        self.assertEqual(list((self.root / '.security/sarif').glob('*')), [])

    def test_failed_report_and_missing_scanner_rejected(self):
        for change in ('failed', 'missing'):
            run_id = self.evidence()
            path = self.root / '.security/reports' / (run_id + '-scan-report.json')
            report = normalize.read_json(path)
            if change == 'failed':
                report['exit_code'] = 40
            else:
                report['scanners'] = report['scanners'][1:]
            atomic_json(path, report)
            with self.assertRaises(normalize.ContractError):
                normalize.normalize(self.root, run_id)

    def test_full_sarif_schema_rejects_invalid_result(self):
        run_id = self.evidence()
        path = self.root / '.security/raw/semgrep' / (run_id + '.sarif')
        data = normalize.read_json(path)
        data['runs'][0]['results'][0]['level'] = 'invented'
        atomic_json(path, data)
        with self.assertRaises(Exception):
            normalize.normalize(self.root, run_id)
        self.assertFalse((self.root / '.security/sarif' / (run_id + '-merged.sarif')).exists())

    def test_location_escape_and_source_drift_rejected(self):
        run_id = self.evidence()
        raw = self.root / '.security/raw/semgrep' / (run_id + '.sarif')
        baseline = normalize.read_json(raw)
        data = json.loads(json.dumps(baseline))
        data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'] = '../outside.py'
        atomic_json(raw, data)
        with self.assertRaises(normalize.ContractError):
            normalize.collect(self.root, run_id)
        atomic_json(raw, baseline)
        (self.root / 'sample.py').write_text('fixed = True\n', encoding='utf-8')
        with self.assertRaises(normalize.ContractError):
            normalize.collect(self.root, run_id)

    def test_normalized_tamper_is_not_trusted(self):
        run_id = self.evidence()
        result = normalize.normalize(self.root, run_id)
        path = self.root / result['normalized_reference']
        data = normalize.read_json(path)
        data['findings'] = []
        atomic_json(path, data)
        with self.assertRaises(normalize.ContractError):
            store.update(self.root, run_id)

    def test_normalization_is_idempotent(self):
        run_id = self.evidence()
        self.assertEqual(normalize.normalize(self.root, run_id), normalize.normalize(self.root, run_id))


class StoreTests(FindingProject):
    def test_open_duplicate_and_repeat_run_idempotency(self):
        run_id = self.populated()
        result = store.update(self.root, run_id)
        self.assertEqual(result['ids'], ['SEC-0001'])
        self.assertEqual(len(store.show(self.root, 'SEC-0001')['finding']['history']), 1)
        second = self.evidence(2)
        normalize.normalize(self.root, second)
        self.assertEqual(store.update(self.root, second)['ids'], ['SEC-0001'])
        self.assertEqual(len(store.show(self.root, 'SEC-0001')['finding']['history']), 2)
        self.assertEqual(len(store.load_findings(self.root)), 1)

    def test_absence_cannot_close_and_direct_closure_fails(self):
        self.populated()
        run_id = self.evidence(2, results=False)
        normalize.normalize(self.root, run_id)
        store.update(self.root, run_id)
        self.assertEqual(store.show(self.root, 'SEC-0001')['finding']['status'], 'OPEN')
        with self.assertRaises(normalize.ContractError):
            store.close_finding(self.root, 'SEC-0001')

    def test_test_only_seeded_closed_record_reopens_same_id(self):
        self.populated()
        path = self.root / '.security/findings/SEC-0001.json'
        finding = normalize.read_json(path)
        finding['status'] = 'CLOSED'
        finding['history'].append({'status': 'CLOSED', 'timestamp': finding['last_seen'],
                                   'event': 'TEST_ONLY_SEEDED_HISTORICAL_CLOSED'})
        atomic_json(path, finding)
        run_id = self.evidence(2)
        normalize.normalize(self.root, run_id)
        self.assertEqual(store.update(self.root, run_id)['ids'], ['SEC-0001'])
        finding = store.show(self.root, 'SEC-0001')['finding']
        self.assertEqual(finding['status'], 'REOPENED')
        self.assertTrue(finding['regression'])
        self.assertEqual(finding['history'][-1]['event'], 'reopened')

    def test_json_precedence_rebuild_and_corrupt_db_recovery(self):
        self.populated()
        db_path = self.root / '.security/security.db'
        db = store.connect_database(db_path)
        db.execute("UPDATE findings SET status='CLOSED'")
        db.commit()
        db.close()
        self.assertEqual(store.show(self.root, 'SEC-0001')['finding']['status'], 'OPEN')
        db_path.write_bytes(b'CORRUPT_DERIVED_INDEX')
        store.rebuild(self.root)
        db = store.connect_database(db_path)
        self.addCleanup(db.close)
        self.assertEqual(db.execute('SELECT status FROM findings').fetchone(), ('OPEN',))
        self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone(), (1,))
        self.assertEqual(db.execute('SELECT COUNT(*) FROM finding_history').fetchone(), (1,))

    def test_index_failure_leaves_recoverable_canonical_json(self):
        run_id = self.evidence()
        normalize.normalize(self.root, run_id)
        with patch.object(store, 'write_index', side_effect=OSError):
            with self.assertRaises(store.IndexWriteError):
                store.update(self.root, run_id)
        self.assertEqual(store.show(self.root, 'SEC-0001')['finding']['status'], 'OPEN')
        store.rebuild(self.root)

    def test_invalid_canonical_does_not_replace_db(self):
        self.populated()
        db_path = self.root / '.security/security.db'
        original = db_path.read_bytes()
        path = self.root / '.security/findings/SEC-0001.json'
        path.write_text('{}', encoding='utf-8')
        with self.assertRaises(Exception):
            store.rebuild(self.root)
        self.assertEqual(db_path.read_bytes(), original)

    def test_ids_not_reused_after_interrupted_canonical_write(self):
        run_id = self.evidence()
        normalize.normalize(self.root, run_id)
        original = store.atomic_json

        def fail_finding(path, value):
            if path.name.startswith('SEC-'):
                raise OSError('TEST_ONLY_WRITE_FAILURE')
            original(path, value)
        with patch.object(store, 'atomic_json', side_effect=fail_finding):
            with self.assertRaises(OSError):
                store.update(self.root, run_id)
        self.assertEqual(store.update(self.root, run_id)['ids'], ['SEC-0002'])

    def test_invalid_id_and_sequence_rejected(self):
        self.populated()
        with self.assertRaises(normalize.ContractError):
            store.show(self.root, '../SEC-0001')
        atomic_json(self.root / '.security/findings/.sequence.json', {'last_id': 0})
        with self.assertRaises(normalize.ContractError):
            store.rebuild(self.root)

    def test_concurrent_updates_share_one_id(self):
        run_id = self.evidence()
        normalize.normalize(self.root, run_id)
        cmd = [sys.executable, str(self.root / 'security-cli/security'), 'findings', 'update', '--run-id', run_id, '--json']
        processes = [subprocess.Popen(cmd, cwd=self.root, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True) for _ in range(2)]
        for process in processes:
            out, err = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, out + err)
            self.assertEqual(json.loads(out)['ids'], ['SEC-0001'])
        self.assertEqual(len(store.load_findings(self.root)), 1)

    def test_writer_lock_timeout(self):
        with store_lock(self.root):
            with self.assertRaises(TimeoutError):
                with store_lock(self.root, timeout=0.1):
                    self.fail('second writer acquired the lock')
