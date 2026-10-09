import json
import os
import subprocess
import sys

from tests.support import DoctorProject, doctor


class DoctorAcceptance(DoctorProject):
    def command(self, *args):
        return [sys.executable, str(self.root / 'security-cli/security'), *args]

    def invoke(self, *args):
        return subprocess.run(self.command(*args), cwd=self.root, capture_output=True,
                              text=True, timeout=30, check=False)

    def test_doctor_passes_valid_mandatory_requirements(self):
        result = self.invoke('doctor', '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['result'], 'PASS')
        self.assertEqual(report['exit_code'], result.returncode)
        self.assertTrue(report['timestamp'].endswith('Z'))
        self.assertFalse(any(c['state'] in ('FAIL', 'NOT_CHECKED') for c in report['checks']))

    def test_broken_policy_yaml_returns_30(self):
        (self.root / '.security/policies/security-policy.yml').write_text('policies: [', encoding='utf-8')
        result = self.invoke('doctor', '--json')
        self.assertEqual(result.returncode, 30)
        self.assertEqual(json.loads(result.stdout)['result'], 'CONFIG_ERROR')

    def test_missing_required_schema_returns_30(self):
        (self.root / 'schemas/finding.schema.json').unlink()
        self.assertEqual(self.invoke('doctor').returncode, 30)

    def test_initialization_is_idempotent(self):
        self.assertEqual(self.invoke('doctor').returncode, 0)
        db = doctor.connect_database(self.root / '.security/security.db')
        db.execute("INSERT INTO findings VALUES ('SEC-0001','test-only',1,'OPEN','SEC-0001.json')")
        db.commit()
        db.close()
        self.assertEqual(self.invoke('doctor').returncode, 0)
        db = doctor.connect_database(self.root / '.security/security.db')
        self.addCleanup(db.close)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM findings').fetchone(), (1,))

    def test_human_and_machine_readable_modes(self):
        human = self.invoke('doctor')
        machine = self.invoke('doctor', '--json')
        self.assertEqual(human.returncode, machine.returncode)
        self.assertIn('Coding Security Protocol', human.stdout)
        self.assertIn('[PASS] sqlite_initialization', human.stdout)
        self.assertEqual(json.loads(machine.stdout)['exit_code'], 0)

    def test_config_and_schema_error_scenarios(self):
        config_path = self.root / 'security.config.yml'
        original = config_path.read_text(encoding='utf-8')
        for value in ('ai: [', '', '{}', 'version: 1\nversion: 2'):
            config_path.write_text(value, encoding='utf-8')
            self.assertEqual(self.invoke('doctor', '--json').returncode, 30)
        config_path.write_text(original, encoding='utf-8')
        (self.root / 'schemas/finding.schema.json').write_text('{"type": 123}', encoding='utf-8')
        self.assertEqual(self.invoke('doctor', '--json').returncode, 30)

    def test_real_missing_mandatory_binary_returns_40(self):
        config = self.config()
        config['scanners']['semgrep'].update(executable='CSP_TEST_ONLY_NONEXISTENT_BINARY', mandatory=True)
        self.write_config(config)
        self.assertEqual(self.invoke('doctor', '--json').returncode, 40)

    def test_db_failure_returns_40(self):
        (self.root / '.security/security.db').write_bytes(b'corrupt')
        self.assertEqual(self.invoke('doctor', '--json').returncode, 40)

    def test_later_commands_fail_closed(self):
        for command in ('ai-patch',):
            result = self.invoke(command, '--json')
            self.assertEqual(result.returncode, 50)
            self.assertEqual(json.loads(result.stdout)['result'], 'CONTRACT_ERROR')

    def test_invalid_arguments_use_standard_exit_code(self):
        self.assertEqual(self.invoke('doctor', '--unknown').returncode, 30)

    def test_explicit_project_root(self):
        elsewhere = self.root / 'other-project'
        elsewhere.mkdir()
        self.assertEqual(self.invoke('doctor', '--root', str(elsewhere), '--json').returncode, 30)

    def test_concurrent_initialization(self):
        processes = [subprocess.Popen(self.command('doctor', '--json'), cwd=self.root,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for _ in range(2)]
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stdout + stderr)

    def test_windows_security_command(self):
        if os.name != 'nt':
            self.skipTest('Windows launcher test')
        env = dict(os.environ, PATH=str(self.root / 'security-cli') + os.pathsep + os.environ['PATH'])
        result = subprocess.run(['powershell', '-NoProfile', '-Command', 'security doctor --json; exit $LASTEXITCODE'],
                                cwd=self.root, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['result'], 'PASS')
