import copy
import json
import sqlite3
import sys
from unittest.mock import patch

from tests.support import DoctorProject, doctor


class ConfigTests(DoctorProject):
    def test_empty_ai_registry_is_valid(self):
        self.assertEqual(doctor.validate_config(self.config())['ai']['providers'], [])

    def test_yaml_fail_closed(self):
        path = self.root / 'security.config.yml'
        for text in ('', '{}', 'null', '[]', 'version: [',
                     'version: 1\nversion: 1', '!!python/object/apply:os.system [echo BAD]',
                     'version: 1\nai: &a {providers: *a}', '<<: {version: 1}'):
            with self.subTest(text=text):
                path.write_text(text, encoding='utf-8')
                self.assertEqual(self.result()['exit_code'], 30)

    def test_missing_config(self):
        (self.root / 'security.config.yml').unlink()
        self.assertEqual(self.result()['exit_code'], 30)

    def test_invalid_config_fields(self):
        baseline = self.config()
        for section, key, value in (
            ('ai', 'providers', None), ('ai', 'providers', {}),
            ('runtime_verify', 'mode', 'waived'),
            ('runtime_verify', 'mode', 'unknown'),
        ):
            data = copy.deepcopy(baseline)
            data[section][key] = value
            with self.subTest(section=section, value=value):
                with self.assertRaises(doctor.ConfigError):
                    doctor.validate_config(data)
        for key in ('enabled', 'mandatory', 'executable'):
            data = copy.deepcopy(baseline)
            data['scanners']['semgrep'][key] = 'false' if key != 'executable' else ''
            with self.assertRaises(doctor.ConfigError):
                doctor.validate_config(data)
        data = copy.deepcopy(baseline)
        data['scanners']['semgrep']['executable'] = 'invalid\x00executable'
        with self.assertRaises(doctor.ConfigError):
            doctor.validate_config(data)
        for data in (dict(baseline, unknown=True), dict(baseline, version=True)):
            with self.assertRaises(doctor.ConfigError):
                doctor.validate_config(data)
        data = copy.deepcopy(baseline)
        del data['scanners']['trivy']['mandatory']
        with self.assertRaises(doctor.ConfigError):
            doctor.validate_config(data)

    def test_provider_registry(self):
        data = self.config()
        provider = {'id': 'test-local', 'adapter': 'test-adapter', 'trust': 'restricted', 'enabled': False}
        data['ai']['providers'] = [provider]
        doctor.validate_config(data)
        for providers in ([provider, provider], [{'id': 'missing-fields'}],
                          [dict(provider, trust='trusted')], [dict(provider, enabled='yes')]):
            data['ai']['providers'] = providers
            with self.assertRaises(doctor.ConfigError):
                doctor.validate_config(data)

    def test_runtime_command_configuration(self):
        data = self.config()
        runtime = {'mode': 'command', 'argv': ['test-verifier', '--check'],
                   'timeout_seconds': 30, 'environment': 'staging'}
        data['runtime_verify'] = runtime
        doctor.validate_config(data)
        for key, value in (('argv', 'test-verifier'), ('argv', []), ('argv', ['']),
                           ('timeout_seconds', 0), ('timeout_seconds', True),
                           ('environment', 'production')):
            data['runtime_verify'] = dict(runtime, **{key: value})
            with self.assertRaises(doctor.ConfigError):
                doctor.validate_config(data)

    def test_policy_missing_or_invalid(self):
        path = self.root / '.security/policies/security-policy.yml'
        for text in ('version: [', '', '{}', 'policies: []',
                     'version: 1\nversion: 1\npolicies: []'):
            path.write_text(text, encoding='utf-8')
            self.assertEqual(self.result()['exit_code'], 30)
        path.unlink()
        self.assertEqual(self.result()['exit_code'], 30)

    def test_policy_duplicate_id_rejected(self):
        policy = doctor.load_yaml(self.root / '.security/policies/security-policy.yml')
        policy['policies'][1]['id'] = 'POL-001'
        with self.assertRaises(doctor.ConfigError):
            doctor.validate_policy(policy)

    def test_missing_parser_dependency_fails(self):
        with patch.object(doctor, 'dependencies', side_effect=ImportError):
            report = self.result()
        self.assertEqual(report['exit_code'], 40)
        self.assertEqual(next(c for c in report['checks'] if c['name'] == 'parser_dependencies')['code'], 40)


class SchemaTests(DoctorProject):
    def test_valid_schema(self):
        doctor.validate_finding_schema(self.root / 'schemas/finding.schema.json')

    def test_missing_schema(self):
        (self.root / 'schemas/finding.schema.json').unlink()
        self.assertEqual(self.result()['exit_code'], 30)

    def test_invalid_schema(self):
        path = self.root / 'schemas/finding.schema.json'
        baseline = json.loads(path.read_text(encoding='utf-8'))
        variants = ('{', '[]', '{}', '{"type":"object","type":"string"}',
                    '{"type":"object","minimum":NaN}',
                    json.dumps(dict(baseline, type=123)),
                    json.dumps(dict(baseline, required='id')),
                    json.dumps(dict(baseline, **{'$schema': 'https://unknown.invalid/schema'})))
        for text in variants:
            with self.subTest(text=text):
                path.write_text(text, encoding='utf-8')
                self.assertEqual(self.result()['exit_code'], 30)

    def test_unresolvable_or_remote_refs(self):
        path = self.root / 'schemas/finding.schema.json'
        baseline = json.loads(path.read_text(encoding='utf-8'))
        for ref in ('#/missing', 'https://example.invalid/schema', 'file:///private', '#/properties/unknown', '#/title'):
            baseline['properties']['id'] = {'$ref': ref}
            path.write_text(json.dumps(baseline), encoding='utf-8')
            self.assertEqual(self.result()['exit_code'], 30)


class EnvironmentTests(DoctorProject):
    def test_disabled_optional_scanner_missing_is_warning(self):
        with patch.object(doctor.shutil, 'which', return_value=None):
            report = self.result()
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual([c['state'] for c in report['checks'] if c['name'] in ('semgrep', 'trivy')], ['WARN', 'WARN'])

    def test_required_or_enabled_scanner_missing_is_tool_error(self):
        for enabled, mandatory in ((True, False), (False, True), (True, True)):
            config = self.config()
            config['scanners']['semgrep'].update(enabled=enabled, mandatory=mandatory)
            self.write_config(config)
            with patch.object(doctor.shutil, 'which', return_value=None):
                self.assertEqual(self.result()['exit_code'], 40)

    def test_available_scanner_is_never_executed(self):
        with patch.object(doctor.shutil, 'which', return_value=sys.executable):
            report = self.result()
        self.assertEqual(report['exit_code'], 0)
        self.assertTrue(all('not executed' in c['detail'] for c in report['checks']
                            if c['name'] in ('semgrep', 'trivy')))

    def test_unsupported_python(self):
        with patch.object(doctor.sys, 'version_info', (3, 10, 0)):
            self.assertEqual(self.result()['exit_code'], 30)

    def test_missing_directory(self):
        (self.root / 'tests/fixtures').rmdir()
        self.assertEqual(self.result()['exit_code'], 30)

    def test_write_probe_is_removed(self):
        doctor.check_write_access(self.root)
        self.assertEqual(list(self.root.rglob('.doctor-*')), [])

    def test_write_permission_error(self):
        with patch.object(doctor.tempfile, 'NamedTemporaryFile', side_effect=PermissionError):
            self.assertEqual(self.result()['exit_code'], 40)


class DatabaseTests(DoctorProject):
    def test_repeatable_init_preserves_data_and_foreign_keys(self):
        doctor.initialize_database(self.root)
        db = self.root / '.security/security.db'
        connection = doctor.connect_database(db)
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute('PRAGMA foreign_keys').fetchone(), (1,))
        connection.execute("INSERT INTO findings VALUES ('SEC-0001','test-fingerprint',1,'OPEN','SEC-0001.json')")
        connection.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO finding_history(finding_id,timestamp,event) VALUES ('SEC-9999','2026-10-09T00:00:00Z','test')")
        connection.rollback()
        doctor.initialize_database(self.root)
        self.assertEqual(connection.execute('SELECT id FROM findings').fetchall(), [('SEC-0001',)])

    def test_corrupt_database(self):
        (self.root / '.security/security.db').write_bytes(b'NOT A SQLITE DATABASE')
        self.assertEqual(self.result()['exit_code'], 40)

    def test_database_path_is_directory(self):
        (self.root / '.security/security.db').mkdir()
        self.assertEqual(self.result()['exit_code'], 40)

    def test_database_permission_error(self):
        with patch.object(doctor.sqlite3, 'connect', side_effect=sqlite3.OperationalError):
            self.assertEqual(self.result()['exit_code'], 40)

    def test_incompatible_existing_schema_rolls_back(self):
        connection = doctor.connect_database(self.root / '.security/security.db')
        connection.execute('CREATE TABLE findings (id TEXT)')
        connection.commit()
        connection.close()
        self.assertEqual(self.result()['exit_code'], 40)
        connection = doctor.connect_database(self.root / '.security/security.db')
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(), [('findings',)])

    def test_invalid_or_incomplete_sql(self):
        path = self.root / 'security-cli/security-store.schema.sql'
        for sql in ('CREATE TABLE broken (', '', 'CREATE TABLE unrelated (id TEXT);'):
            path.write_text(sql, encoding='utf-8')
            self.assertEqual(self.result()['exit_code'], 40)
        self.assertFalse((self.root / '.security/security.db').exists())

    def test_locked_database(self):
        doctor.initialize_database(self.root)
        connection = doctor.connect_database(self.root / '.security/security.db')
        self.addCleanup(connection.close)
        connection.execute('BEGIN IMMEDIATE')
        with self.assertRaises(sqlite3.OperationalError):
            doctor.initialize_database(self.root)
        connection.rollback()
