"""Validated SARIF → portable findings and a merged evidence artifact."""
import ast
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlparse

from jsonschema import FormatChecker, validators
from referencing import Registry

from .doctor import ConfigError, load_yaml, validate_config, unique_pairs, reject_json_constant
from .scan import sarif_count
from .storage_io import atomic_json, store_lock

RUN_ID = re.compile(r'^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8,32}$')
LEVELS = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']


class ContractError(ValueError):
    """Malformed or inconsistent deterministic evidence."""


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'), object_pairs_hook=unique_pairs,
                      parse_constant=reject_json_constant)


def no_remote_reference(uri):
    raise ContractError('remote schema retrieval is forbidden')


def schema_validator(path):
    schema = read_json(path)
    cls = validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, format_checker=FormatChecker(), registry=Registry(retrieve=no_remote_reference))


def safe_path(root, value, prefix=None):
    if not isinstance(value, str) or not value or '\x00' in value:
        raise ContractError('invalid evidence path')
    path = (root / value.replace('\\', '/')).resolve()
    if not path.is_relative_to(root) or (prefix and not path.is_relative_to(root / prefix)):
        raise ContractError('path escapes required project directory')
    return path


def artifact_path(root, run, artifact):
    uri = artifact.get('uri')
    if not uri:
        raise ContractError('result location URI missing')
    base = run.get('originalUriBaseIds', {}).get(artifact.get('uriBaseId'), {}).get('uri', '')

    def decode(value):
        if value.startswith('file:'):
            parsed = urlparse(value)
            if parsed.netloc:
                raise ContractError('remote file URI not supported')
            value = unquote(parsed.path)
            if re.match(r'^/[A-Za-z]:/', value):
                value = value[1:]
        elif re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:', value) and not re.match(r'^[A-Za-z]:[\\/]', value):
            raise ContractError('non-file artifact URI not supported')
        return unquote(value).replace('\\', '/')

    decoded = decode(uri)
    path = Path(decoded)
    if not path.is_absolute() and base:
        decoded = str(Path(decode(base)) / decoded)
    return safe_path(root, decoded).relative_to(root).as_posix()


def category(rule, rule_id):
    props = rule.get('properties', {})
    explicit = props.get('category')
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower()
    tags = props.get('tags', [])
    if 'secret' in tags or rule.get('name') == 'Secret':
        return 'hardcoded-secret'
    cwes = sorted(set(re.findall(r'CWE-\d+', ' '.join(str(tag) for tag in tags), re.I)))
    if cwes:
        return cwes[0].upper()
    if rule_id.endswith('csp-python-eval'):
        return 'code-injection'
    return 'rule:' + rule_id


def fingerprint(category_name, path, context):
    # Tool, rule name, line, severity, message and run timestamps are not identity.
    payload = [1, category_name, path.replace('\\', '/'), context]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()


def context_identity(root, path, region, rule, result, category_name):
    snippet = region.get('snippet', {}).get('text', '').strip()
    if not snippet and category_name == 'hardcoded-secret':
        # Trivy already masks secrets; never recover a live secret from source text.
        snippet = rule.get('fullDescription', {}).get('text', '').strip()
    if not snippet:
        raise ContractError('scanner result lacks stable code/context identity')
    scope = ''
    if path.endswith('.py') and category_name != 'hardcoded-secret':
        source_path = root / path
        if not source_path.is_file():
            raise ContractError('source context missing for Python scope identity')
        source = source_path.read_text(encoding='utf-8-sig')
        lines = source.splitlines()
        line = region['startLine']
        if line > len(lines) or snippet.splitlines()[0].strip() not in lines[line - 1].strip():
            raise ContractError('source changed since scan; rescan before normalization')
        tree = ast.parse(source)
        names = []

        def scopes(node):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.lineno <= line <= node.end_lineno:
                    return
                names.append(node.name)
            for child in ast.iter_child_nodes(node):
                scopes(child)
        scopes(tree)
        scope = '.'.join(names)
    logical = result.get('locations', [{}])[0].get('logicalLocations', [])
    if logical:
        scope = logical[0].get('fullyQualifiedName', scope)
    # Preserve token/string identity. Strip outer indentation only, not string whitespace.
    return {'scope': scope, 'code': '\n'.join(line.strip() for line in snippet.splitlines())}


def collect(root, run_id):
    if not RUN_ID.fullmatch(run_id or ''):
        raise ConfigError('invalid run_id')
    config = validate_config(load_yaml(root / 'security.config.yml'))
    report = read_json(root / '.security/reports' / (run_id + '-scan-report.json'))
    if report.get('run_id') != run_id or report.get('exit_code') != 0 or report.get('result') != 'SCAN_COMPLETED':
        raise ContractError('scan report missing successful execution')
    items = report.get('scanners', [])
    if not isinstance(items, list) or not items:
        raise ContractError('scan report lacks scanner evidence')
    if len({item.get('tool') for item in items}) != len(items):
        raise ContractError('duplicate scanner evidence')
    for tool, profile in config['scanners'].items():
        if profile['enabled'] or profile['mandatory']:
            matches = [item for item in items if item.get('tool') == tool]
            if len(matches) != 1 or matches[0].get('state') not in ('CLEAN', 'FINDINGS'):
                raise ContractError('required scanner evidence missing or failed')
    validator = schema_validator(Path(__file__).with_name('sarif-2.1.0.schema.json'))
    grouped = {}
    merged = {'version': '2.1.0', 'runs': []}
    input_hashes = {}
    for item in items:
        tool = item['tool']
        if tool not in config['scanners']:
            raise ContractError('unrecognized scanner evidence')
        if item.get('state') == 'SKIPPED' and not config['scanners'][tool]['enabled'] and not config['scanners'][tool]['mandatory']:
            continue
        if item.get('state') not in ('CLEAN', 'FINDINGS') or item.get('timed_out') is not False:
            raise ContractError('scanner did not execute successfully')
        raw = safe_path(root, item['raw_reference'], '.security/raw/' + tool)
        if raw.name != run_id + '.sarif':
            raise ContractError('raw evidence belongs to another run')
        data = read_json(raw)
        validator.validate(data)
        count = sarif_count(raw)
        if count != item.get('findings_count') or item.get('scanner_exit_code') not in (0, 1):
            raise ContractError('raw evidence and scan metadata disagree')
        if item['scanner_exit_code'] == 1 and count == 0:
            raise ContractError('nonzero exit without findings')
        if (count > 0) != (item['state'] == 'FINDINGS'):
            raise ContractError('scanner result state mismatch')
        raw_ref = raw.relative_to(root).as_posix()
        input_hashes[raw_ref] = hashlib.sha256(raw.read_bytes()).hexdigest()
        merged['runs'].extend(data['runs'])
        for run in data['runs']:
            rules = {rule['id']: rule for rule in run['tool']['driver'].get('rules', [])}
            for index, result in enumerate(run.get('results', [])):
                rule_id = result.get('ruleId')
                rule = rules.get(rule_id)
                if rule is None:
                    raise ContractError('result references an undefined rule')
                if len(result.get('locations', [])) != 1:
                    raise ContractError('exactly one primary result location required')
                physical = result['locations'][0]['physicalLocation']
                path = artifact_path(root, run, physical['artifactLocation'])
                region = physical['region']
                if 'startLine' not in region:
                    raise ContractError('source region missing')
                cat = category(rule, rule_id)
                context = context_identity(root, path, region, rule, result, cat)
                tags = rule.get('properties', {}).get('tags', [])
                source_severity = next((tag for tag in tags if tag in LEVELS), None)
                if source_severity is None:
                    source_severity = {'error': 'ERROR', 'warning': 'WARNING', 'note': 'INFO', 'none': 'INFO'}[
                        result.get('level', rule.get('defaultConfiguration', {}).get('level', 'warning'))]
                mapping = item['profile']['severity_mapping']
                severity = mapping.get(source_severity)
                if severity not in LEVELS:
                    raise ConfigError('scanner severity mapping incomplete')
                fp = fingerprint(cat, path, context)
                finding = grouped.setdefault(fp, {'fingerprint': fp, 'fingerprint_version': 1,
                    'category': cat, 'severity': severity, 'location': {'path': path, 'line': region['startLine']},
                    'context': context, 'message': result['message']['text'], 'sources': []})
                if LEVELS.index(severity) > LEVELS.index(finding['severity']):
                    finding['severity'] = severity
                finding['sources'].append({'tool': tool, 'rule_id': rule_id, 'raw_reference': raw_ref,
                                           'result_index': index})
    if not merged['runs']:
        raise ContractError('no executed scanner evidence to merge')
    validator.validate(merged)
    normalized = {'run_id': run_id, 'fingerprint_version': 1, 'observed_at': report['finished_at'],
                  'input_hashes': input_hashes, 'findings': [grouped[key] for key in sorted(grouped)]}
    return normalized, merged


def normalize(root, run_id):
    root = Path(root).resolve()
    with store_lock(root):
        data, merged = collect(root, run_id)
        sarif_path = root / '.security/sarif' / (run_id + '-merged.sarif')
        json_path = root / '.security/sarif' / (run_id + '-normalized.json')
        for path, value in ((sarif_path, merged), (json_path, data)):
            if path.exists():
                if read_json(path) != value:
                    raise ContractError('normalized artifact already exists with different content')
            else:
                atomic_json(path, value)
    return {'run_id': run_id, 'findings_count': len(data['findings']),
            'normalized_reference': json_path.relative_to(root).as_posix(),
            'merged_reference': sarif_path.relative_to(root).as_posix()}


def load_normalized(root, run_id):
    expected, merged = collect(root, run_id)
    stored = read_json(root / '.security/sarif' / (run_id + '-normalized.json'))
    stored_merged = read_json(root / '.security/sarif' / (run_id + '-merged.sarif'))
    if stored != expected or stored_merged != merged:
        raise ContractError('normalized evidence changed or disagrees with raw evidence')
    return stored
