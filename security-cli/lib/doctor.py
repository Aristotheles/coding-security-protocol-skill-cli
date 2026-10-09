"""M0 environment checks. This command does not scan or evaluate policies."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import uuid

PASS, BLOCK, REVIEW_REQUIRED = 0, 10, 20
CONFIG_ERROR, TOOL_ERROR, CONTRACT_ERROR, VERIFY_ERROR = 30, 40, 50, 60
RUNTIME_DIRS = (
    '.security/findings', '.security/raw/semgrep', '.security/raw/trivy',
    '.security/sarif', '.security/evidence', '.security/reports',
)
REQUIRED_DIRS = RUNTIME_DIRS + (
    'schemas', '.security/policies', '.security/playbooks', 'docs',
    'security-cli/lib', 'tests/fixtures', 'tests/unit', 'tests/integration',
)
REQUIRED_FILES = ('MVP.md', 'AGENTS.md', 'SECURITY_AGENT.md', 'security-cli/security',
                  'security-cli/security-store.schema.sql')


class ConfigError(ValueError):
    """Invalid mandatory configuration."""


def dependencies():
    # An unavailable parser never downgrades to empty config.
    import yaml
    from jsonschema import Draft202012Validator
    return yaml, Draft202012Validator


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError('duplicate mapping key')
        result[key] = value
    return result


def reject_json_constant(value):
    raise ConfigError('non-standard JSON constant')


def load_yaml(path):
    yaml, _ = dependencies()

    class UniqueSafeLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node):
        if any(key.value == '<<' for key, _ in node.value):
            raise ConfigError('YAML merge keys are not supported')
        return unique_pairs([(loader.construct_object(key, deep=True),
                              loader.construct_object(value, deep=True))
                             for key, value in node.value])

    UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        data = yaml.load(path.read_text(encoding='utf-8-sig'), Loader=UniqueSafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError, TypeError, RecursionError) as exc:
        raise ConfigError('missing, unreadable or invalid YAML') from exc
    if not isinstance(data, dict) or not data:
        raise ConfigError('expected a non-empty YAML mapping')
    return data


def object_schema(properties, required=None):
    return {'type': 'object', 'properties': properties,
            'required': list(properties) if required is None else required,
            'additionalProperties': False}


TEXT = {'type': 'string', 'minLength': 1,
        'pattern': r'^[^\x00-\x1f\x7f]*[^\s\x00-\x1f\x7f][^\x00-\x1f\x7f]*$'}
BOOLEAN = {'type': 'boolean'}
ARGV = {'type': 'array', 'minItems': 1, 'items': TEXT}
TIMEOUT = {'type': 'integer', 'minimum': 1, 'maximum': 3600}
SCANNER = object_schema({
    'executable': TEXT, 'enabled': BOOLEAN, 'mandatory': BOOLEAN,
    'argv': ARGV, 'timeout_seconds': TIMEOUT, 'output_format': {'const': 'sarif'},
    'severity_mapping': {'type': 'object', 'minProperties': 1,
                         'additionalProperties': {'enum': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']}},
})
PROVIDER = object_schema({
    'id': TEXT, 'adapter': TEXT, 'model': TEXT, 'enabled': BOOLEAN,
    'trust': {'enum': ['standard', 'restricted']},
}, ['id', 'adapter', 'enabled', 'trust'])
RUNTIME = {'oneOf': [
    object_schema({'mode': {'const': 'not_applicable'}}),
    object_schema({'mode': {'const': 'command'}, 'argv': ARGV, 'timeout_seconds': TIMEOUT,
                   'environment': {'enum': ['test', 'staging']}}),
]}
CONFIG_SCHEMA = object_schema({
    'version': {'type': 'integer', 'const': 1},
    'scanners': object_schema({'semgrep': SCANNER, 'trivy': SCANNER}),
    'ai': object_schema({'providers': {'type': 'array', 'items': PROVIDER}}),
    'runtime_verify': RUNTIME,
})


def validate_config(data):
    _, validator = dependencies()
    # Do not include raw configuration values in diagnostics.
    if not validator(CONFIG_SCHEMA).is_valid(data):
        raise ConfigError('invalid security config structure or field types')
    ids = [provider['id'] for provider in data['ai']['providers']]
    if len(ids) != len(set(ids)):
        raise ConfigError('duplicate AI provider id')
    return data


def validate_policy(data):
    if set(data) != {'version', 'policies'} or type(data['version']) is not int or data['version'] != 1:
        raise ConfigError('invalid policy version or top-level structure')
    policies = data['policies']
    if not isinstance(policies, list) or len(policies) != 7:
        raise ConfigError('expected POL-001 through POL-007 definitions')
    ids = []
    for policy in policies:
        if not isinstance(policy, dict):
            raise ConfigError('invalid policy definition')
        if not all(isinstance(policy.get(key), str) and policy[key].strip()
                   for key in ('id', 'name', 'action')):
            raise ConfigError('missing policy identity, name or action')
        if policy['action'] not in ('BLOCK', 'REVIEW_REQUIRED', 'WARNING'):
            raise ConfigError('invalid policy action')
        ids.append(policy['id'])
    if set(ids) != {f'POL-{number:03d}' for number in range(1, 8)}:
        raise ConfigError('missing or duplicate policy id')


def validate_finding_schema(path):
    _, validator = dependencies()
    try:
        schema = json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_pairs,
                            parse_constant=reject_json_constant)
        if not isinstance(schema, dict):
            raise ConfigError('expected a JSON Schema object')
        if schema.get('$schema') != 'https://json-schema.org/draft/2020-12/schema':
            raise ConfigError('expected JSON Schema draft 2020-12')
        validator.check_schema(schema)
        if schema.get('type') != 'object' or not schema.get('required') or not schema.get('properties'):
            raise ConfigError('finding schema must constrain an object with required properties')
        if not set(schema['required']).issubset(schema['properties']):
            raise ConfigError('required finding properties must be defined')

        def references(node):
            if isinstance(node, dict):
                for keyword in ('$ref', '$dynamicRef'):
                    if keyword in node:
                        ref = node[keyword]
                        if not isinstance(ref, str) or not (ref == '#' or ref.startswith('#/')):
                            raise ConfigError('schema references must be local JSON pointers')
                        target = schema
                        for part in ref[2:].split('/') if ref != '#' else []:
                            part = part.replace('~1', '/').replace('~0', '~')
                            target = target[int(part)] if isinstance(target, list) else target[part]
                        validator.check_schema(target)
                for value in node.values():
                    references(value)
            elif isinstance(node, list):
                for value in node:
                    references(value)
        references(schema)
    except Exception as exc:
        # No network resolution, no parser/schema error treated as success.
        raise ConfigError('missing, unreadable or invalid finding JSON Schema') from exc


def connect_database(path):
    connection = sqlite3.connect(path, timeout=5)
    try:
        connection.execute('PRAGMA foreign_keys = ON')
        if connection.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
            raise sqlite3.DatabaseError('foreign keys not enabled')
        return connection
    except Exception:
        connection.close()
        raise


def database_objects(connection):
    return {(kind, name): ' '.join(sql.split()).lower()
            for kind, name, sql in connection.execute(
                "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'")}


def _initialize_database(root):
    sql = (root / 'security-cli/security-store.schema.sql').read_text(encoding='utf-8-sig')
    expected = connect_database(':memory:')
    actual = None
    try:
        expected.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        expected_objects = database_objects(expected)
        expected_tables = {'findings', 'finding_sources', 'finding_history', 'gate_runs', 'escalation_state'}
        if {name for kind, name in expected_objects if kind == 'table'} != expected_tables:
            raise sqlite3.DatabaseError('SQL contract missing required tables')
        actual = connect_database(root / '.security/security.db')
        # BEGIN IMMEDIATE serializes bootstrap writers; initialization is transactional.
        actual.executescript('BEGIN IMMEDIATE;\n' + sql)
        if actual.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
            raise sqlite3.DatabaseError('foreign keys disabled by SQL')
        if database_objects(actual) != expected_objects:
            raise sqlite3.DatabaseError('existing DB schema does not match SQL contract')
        if actual.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise sqlite3.DatabaseError('DB integrity check failed')
        if actual.execute('PRAGMA foreign_key_check').fetchone() is not None:
            raise sqlite3.DatabaseError('DB foreign key check failed')
        actual.commit()
    finally:
        if actual is not None:
            if actual.in_transaction:
                actual.rollback()
            actual.close()
        expected.close()


def initialize_database(root):
    from .storage_io import store_lock
    with store_lock(root):
        _initialize_database(root)


def check_write_access(root):
    for name in ('.security',) + RUNTIME_DIRS:
        # Create/write/read/delete a unique probe, rather than trusting permission bits.
        with tempfile.NamedTemporaryFile(dir=root / name, prefix='.doctor-', delete=True) as probe:
            probe.write(b'Coding Security Protocol doctor probe')
            probe.flush()
            probe.seek(0)
            if probe.read() != b'Coding Security Protocol doctor probe':
                raise OSError('runtime probe readback failed')


def run_doctor(root):
    root = Path(root).resolve()
    now = datetime.now(timezone.utc)
    checks = []

    def record(name, action, error_code=CONFIG_ERROR, detail='valid'):
        try:
            value = action()
            checks.append({'name': name, 'state': 'PASS', 'code': PASS, 'detail': detail})
            return value
        except Exception as exc:
            # Exception class is useful; arbitrary file content is not echoed.
            message = str(exc) if isinstance(exc, ConfigError) else type(exc).__name__
            checks.append({'name': name, 'state': 'FAIL', 'code': error_code, 'detail': message})
            return None

    def python_version():
        if not (3, 11) <= sys.version_info[:2] < (4, 0):
            raise ConfigError('Python 3.11 or newer within Python 3 is required')

    def structure():
        missing = [name for name in REQUIRED_DIRS if not (root / name).is_dir()]
        missing += [name for name in REQUIRED_FILES if not (root / name).is_file()]
        if missing:
            raise ConfigError('missing required paths: ' + ', '.join(missing))

    record('python', python_version, detail=sys.version.split()[0])
    record('structure', structure)
    available = record('parser_dependencies', dependencies, TOOL_ERROR)
    if available is not None:
        config = record('security_config', lambda: validate_config(load_yaml(root / 'security.config.yml')))
        record('policy', lambda: validate_policy(load_yaml(root / '.security/policies/security-policy.yml')),
               detail='parsed definitions; policy evaluation is outside M0')
        record('finding_schema', lambda: validate_finding_schema(root / 'schemas/finding.schema.json'))
    else:
        config = None
        for name in ('security_config', 'policy', 'finding_schema'):
            checks.append({'name': name, 'state': 'NOT_CHECKED', 'code': TOOL_ERROR,
                           'detail': 'required parser dependency unavailable'})
    for name in ('ai_provider_registry', 'runtime_verifier_config'):
        checks.append({'name': name, 'state': 'PASS' if config is not None else 'NOT_CHECKED',
                       'code': PASS if config is not None else CONFIG_ERROR if available is not None else TOOL_ERROR,
                       'detail': 'syntax validated; no adapter executed' if config is not None
                       else 'security config invalid or unavailable'})
    for name in ('semgrep', 'trivy'):
        if config is None:
            checks.append({'name': name, 'state': 'NOT_CHECKED',
                           'code': CONFIG_ERROR if available is not None else TOOL_ERROR,
                           'detail': 'security config invalid or unavailable'})
            continue
        profile = config['scanners'][name]
        candidate = profile['executable']
        if '/' in candidate or '\\' in candidate:
            candidate = str(root / candidate)
        executable = shutil.which(candidate)
        if executable:
            checks.append({'name': name, 'state': 'PASS', 'code': PASS,
                           'detail': 'executable available; not executed'})
        else:
            optional_disabled = not profile['enabled'] and not profile['mandatory']
            checks.append({'name': name, 'state': 'WARN' if optional_disabled else 'FAIL',
                           'code': PASS if optional_disabled else TOOL_ERROR,
                           'detail': 'executable missing; explicitly disabled and optional'
                           if optional_disabled else 'required executable missing'})
    record('runtime_write_access', lambda: check_write_access(root), TOOL_ERROR)
    record('sqlite_initialization', lambda: initialize_database(root), TOOL_ERROR,
           'initialized; foreign_keys=ON; schema and integrity checked')
    codes = {check['code'] for check in checks if check['code']}
    code = CONFIG_ERROR if CONFIG_ERROR in codes else TOOL_ERROR if codes else PASS
    return {'project': 'Coding Security Protocol', 'command': 'doctor',
            'run_id': now.strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8],
            'timestamp': now.isoformat(timespec='seconds').replace('+00:00', 'Z'),
            'result': {PASS: 'PASS', CONFIG_ERROR: 'CONFIG_ERROR', TOOL_ERROR: 'TOOL_ERROR'}[code],
            'exit_code': code, 'checks': checks}


def main(argv=None):
    class SecurityParser(argparse.ArgumentParser):
        def error(self, message):
            self.print_usage(sys.stderr)
            self.exit(CONFIG_ERROR, 'CONFIG_ERROR: invalid CLI arguments\n')

    parser = SecurityParser(description='Coding Security Protocol - Deterministic Core')
    parser.add_argument('command', help='doctor, scan, normalize or findings')
    parser.add_argument('action', nargs='?')
    parser.add_argument('identifier', nargs='?')
    parser.add_argument('--root', type=Path, default=Path.cwd(), help='project root; defaults to current directory')
    parser.add_argument('--json', action='store_true', help='emit machine-readable JSON')
    parser.add_argument('--target', default='.', help='scan target within project root')
    parser.add_argument('--run-id', help='scan run ID for normalize or findings update')
    args = parser.parse_args(argv)
    if args.command in ('doctor', 'scan', 'normalize') and (args.action or args.identifier):
        parser.error('unexpected positional arguments')
    if args.command == 'findings' and args.action in ('update', 'rebuild-index') and args.identifier:
        parser.error('unexpected finding identifier')
    if args.command in ('normalize', 'findings'):
        try:
            from . import normalize, store
            from jsonschema.exceptions import ValidationError
        except ImportError:
            report = {'project': 'Coding Security Protocol', 'command': args.command,
                      'exit_code': TOOL_ERROR, 'result': 'TOOL_ERROR', 'detail': 'required parser dependency unavailable'}
            print(json.dumps(report) if args.json else 'TOOL_ERROR: required parser dependency unavailable')
            return TOOL_ERROR
        report = {'project': 'Coding Security Protocol', 'command': args.command, 'exit_code': 0}
        try:
            if args.command == 'normalize':
                result = normalize.normalize(args.root, args.run_id)
            elif args.action == 'update':
                result = store.update(args.root, args.run_id)
            elif args.action == 'show':
                result = store.show(args.root, args.identifier)
            elif args.action == 'rebuild-index':
                result = store.rebuild(args.root)
            else:
                raise normalize.ContractError('finding operation not implemented')
            report.update(result='COMPLETED', **result)
        except ConfigError as exc:
            report.update(result='CONFIG_ERROR', exit_code=CONFIG_ERROR, detail=str(exc))
        except store.IndexWriteError as exc:
            report.update(result='TOOL_ERROR', exit_code=TOOL_ERROR, canonical_written=True, detail=str(exc))
        except (normalize.ContractError, ValidationError, ValueError, KeyError, TypeError) as exc:
            report.update(result='CONTRACT_ERROR', exit_code=CONTRACT_ERROR, detail=type(exc).__name__)
        except OSError as exc:
            report.update(result='TOOL_ERROR', exit_code=TOOL_ERROR, detail=type(exc).__name__)
        except Exception as exc:
            report.update(result='CONTRACT_ERROR', exit_code=CONTRACT_ERROR, detail=type(exc).__name__)
    elif args.command == 'scan':
        from .scan import run_scan
        report = run_scan(args.root, args.target)
    elif args.command != 'doctor':
        report = {'project': 'Coding Security Protocol', 'command': args.command,
                  'result': 'CONTRACT_ERROR', 'exit_code': CONTRACT_ERROR,
                  'detail': 'command not implemented in M2'}
    else:
        report = run_doctor(args.root)
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        print('Coding Security Protocol - ' + report['command'])
        for check in report.get('checks', []):
            print(f"[{check['state']}] {check['name']}: {check['detail']}")
        for scan in report.get('scanners', []):
            print(f"[{scan['state']}] {scan['tool']}: findings={scan.get('findings_count', 'unknown')}")
        if 'detail' in report:
            print(report['detail'])
        if 'ids' in report:
            print('Findings: ' + ', '.join(report['ids']))
        if 'finding' in report:
            print(json.dumps(report['finding'], ensure_ascii=True, indent=2))
        print(f"{report['result']} (exit {report['exit_code']})")
    return report['exit_code']
