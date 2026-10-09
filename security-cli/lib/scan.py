"""M1 scanner execution and raw evidence. No normalization or policy gate."""
from datetime import datetime, timezone
import json
import hashlib
import os
from pathlib import Path
import signal
import shutil
import subprocess
import uuid

from .doctor import (CONFIG_ERROR, TOOL_ERROR, ConfigError, load_yaml, validate_config,
                     reject_json_constant, unique_pairs)


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def profile_inputs(root, profile):
    """Local scanner rule/config files must not change to make a fix disappear."""
    result = {'@git-root': hashlib.sha256(b'git' if (root / '.git').exists() else b'no-git').hexdigest()}
    # Target selection is part of scanner evidence too. A newly added ignore
    # file must not make an unchanged vulnerability count as a verified fix.
    ignored = {'.git', '.security', '.tools', '.agent', '.serena', '.venv', '__pycache__', 'node_modules'}
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ignored]
        for name in ('.gitignore', '.semgrepignore'):
            if name in files:
                path = (Path(directory) / name).resolve()
                if not path.is_relative_to(root):
                    raise ConfigError('scanner ignore configuration escapes project')
                result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for arg in profile['argv']:
        if arg == '{target}' or arg.startswith('-'):
            continue
        path = (root / arg).resolve()
        if path.is_relative_to(root) and path.is_file():
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def executable_path(root, name):
    if '/' in name or '\\' in name:
        name = str(root / name)
    path = shutil.which(name)
    if path and Path(path).suffix.lower() in ('.cmd', '.bat'):
        raise ConfigError('scanner must be a native executable, not a shell script')
    return path


def execute(command, root, timeout, stdout_path, stderr_path, stdin=subprocess.DEVNULL, env=None):
    """Stream raw bytes directly to exclusive files; kill descendants on timeout."""
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        process = subprocess.Popen(command, cwd=root, stdout=stdout, stderr=stderr,
                                   stdin=stdin, env=env, shell=False,
                                   start_new_session=os.name != 'nt')
        try:
            return process.wait(timeout=timeout), False
        except subprocess.TimeoutExpired:
            if os.name == 'nt':
                killer = str(Path(os.environ['SystemRoot']) / 'System32/taskkill.exe')
                try:
                    subprocess.run([killer, '/PID', str(process.pid), '/T', '/F'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=10, check=False, shell=False)
                finally:
                    if process.poll() is None:
                        process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            return process.returncode, True


def sarif_count(path):
    data = json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_pairs,
                      parse_constant=reject_json_constant)
    if not isinstance(data, dict) or data.get('version') != '2.1.0':
        raise ValueError('invalid SARIF version')
    runs = data.get('runs')
    if not isinstance(runs, list) or not runs:
        raise ValueError('missing SARIF runs')
    count = 0
    for run in runs:
        if not isinstance(run, dict) or not run.get('tool', {}).get('driver', {}).get('name'):
            raise ValueError('missing SARIF tool')
        results = run.get('results')
        if not isinstance(results, list) or any(not isinstance(result, dict) or
                not isinstance(result.get('message'), dict) for result in results):
            raise ValueError('invalid SARIF results')
        for invocation in run.get('invocations', []):
            if invocation.get('executionSuccessful') is False:
                raise ValueError('scanner reports unsuccessful execution')
            if any(item.get('level') == 'error' for item in invocation.get('toolExecutionNotifications', [])):
                raise ValueError('scanner reports execution error')
        count += len(results)
    return count


def run_scan(root, target='.'):
    root = Path(root).resolve()
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex
    report = {'project': 'Coding Security Protocol', 'command': 'scan', 'run_id': run_id,
              'started_at': timestamp(), 'scanners': [], 'exit_code': 0,
              'result': 'SCAN_COMPLETED'}
    try:
        config = validate_config(load_yaml(root / 'security.config.yml'))
        scan_target = (root / target).resolve()
        if not scan_target.is_relative_to(root) or not scan_target.exists():
            raise ConfigError('scan target must exist within project root')
        profiles = config['scanners']
        report['target'] = scan_target.relative_to(root).as_posix()
        if not any(profile['enabled'] for profile in profiles.values()):
            raise ConfigError('no enabled scanners; no scan performed')
        for profile in profiles.values():
            if profile['mandatory'] and not profile['enabled']:
                raise ConfigError('mandatory scanner cannot be disabled')
            if profile['argv'].count('{target}') != 1:
                raise ConfigError('scanner argv requires exactly one target placeholder')
    except ConfigError as exc:
        report.update(result='CONFIG_ERROR', exit_code=CONFIG_ERROR, detail=str(exc), finished_at=timestamp())
        return report
    except Exception as exc:
        report.update(result='TOOL_ERROR', exit_code=TOOL_ERROR, detail=type(exc).__name__, finished_at=timestamp())
        return report

    for tool, profile in profiles.items():
        item = {'tool': tool, 'started_at': timestamp(), 'profile': profile,
                'state': 'SKIPPED' if not profile['enabled'] else 'TOOL_ERROR'}
        report['scanners'].append(item)
        if not profile['enabled']:
            item['finished_at'] = timestamp()
            continue
        try:
            item['profile_inputs'] = profile_inputs(root, profile)
            executable = executable_path(root, profile['executable'])
            if not executable:
                raise FileNotFoundError('scanner executable unavailable')
            raw_dir = root / '.security/raw' / tool
            raw_dir.mkdir(parents=True, exist_ok=True)
            raw = raw_dir / (run_id + '.sarif')
            stderr = raw_dir / (run_id + '.stderr.log')
            version_out = raw_dir / (run_id + '.version.stdout')
            version_err = raw_dir / (run_id + '.version.stderr')
            item.update(raw_reference=str(raw.relative_to(root)), stderr_reference=str(stderr.relative_to(root)))
            try:
                version_code, version_timeout = execute([executable, '--version'], root,
                    min(profile['timeout_seconds'], 10), version_out, version_err)
                item.update(version=version_out.read_text(encoding='utf-8', errors='replace').strip()[:2000]
                            if version_code == 0 and not version_timeout else None,
                            version_exit_code=version_code, version_timeout=version_timeout,
                            version_reference=str(version_out.relative_to(root)))
            except OSError:
                item['version'] = None
            command = [executable] + [str(scan_target) if arg == '{target}' else arg for arg in profile['argv']]
            item['argv'] = command
            code, timed_out = execute(command, root, profile['timeout_seconds'], raw, stderr)
            item.update(scanner_exit_code=code, timed_out=timed_out)
            if item['profile_inputs'] != profile_inputs(root, profile):
                raise ValueError('scanner rule/config files changed during execution')
            if timed_out:
                raise TimeoutError('scanner timeout')
            findings = sarif_count(raw)
            if code != 0 and not (code == 1 and findings > 0):
                raise ValueError('scanner execution exit code')
            item.update(state='FINDINGS' if findings else 'CLEAN', findings_count=findings)
        except Exception as exc:
            item.update(state='TOOL_ERROR', error=type(exc).__name__)
            report.update(exit_code=TOOL_ERROR, result='TOOL_ERROR')
        finally:
            item['finished_at'] = timestamp()
    report['finished_at'] = timestamp()
    report_path = root / '.security/reports' / (run_id + '-scan-report.json')
    report['report_reference'] = str(report_path.relative_to(root))
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2, ensure_ascii=True)
            stream.write('\n')
    except OSError as exc:
        report.update(exit_code=TOOL_ERROR, result='TOOL_ERROR', detail=type(exc).__name__)
    return report
