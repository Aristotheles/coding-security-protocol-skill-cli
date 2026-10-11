"""Non-destructive installation of the protocol contract into an application."""
from pathlib import Path
import os
import tempfile

from . import doctor


ASSET_FILES = (
    '.security/playbooks/secret-leak.md',
    '.security/rules/python-security.yml',
    '.security/rules/trivy-secret.yml',
    'schemas/finding.schema.json',
    'schemas/ai-patch-request.schema.json',
    'schemas/ai-patch-response.schema.json',
    'schemas/ai-review-request.schema.json',
    'schemas/ai-review-response.schema.json',
)
RUNTIME_DIRS = (
    '.security/findings', '.security/raw/semgrep', '.security/raw/trivy',
    '.security/sarif', '.security/evidence', '.security/reports',
)


def _files(config_path, policy_path):
    sources = {name: doctor.TOOL_ROOT / name for name in ASSET_FILES}
    sources['security.config.yml'] = Path(config_path).resolve()
    sources['.security/policies/security-policy.yml'] = Path(policy_path).resolve()
    return sources


def _required_dirs(files):
    directories = set()
    for name in RUNTIME_DIRS:
        current = Path(name)
        while str(current) != '.':
            directories.add(current.as_posix())
            current = current.parent
    for name in files:
        current = Path(name).parent
        while str(current) != '.':
            directories.add(current.as_posix())
            current = current.parent
    return directories


def plan_adoption(root, config_path, policy_path):
    requested_root = Path(root).expanduser()
    requested_source = Path(config_path).expanduser()
    requested_policy = Path(policy_path).expanduser()
    if requested_root.is_symlink():
        raise doctor.ConfigError('target project root must not be a symlink')
    if requested_source.is_symlink():
        raise doctor.ConfigError('adoption config must not be a symlink')
    if requested_policy.is_symlink():
        raise doctor.ConfigError('adoption policy must not be a symlink')
    root = requested_root.resolve()
    source = requested_source.resolve()
    policy_source = requested_policy.resolve()
    if not root.is_dir():
        raise doctor.ConfigError('target project root must be an existing non-symlink directory')
    if not source.is_file() or not policy_source.is_file():
        raise doctor.ConfigError('adoption config and policy must be existing non-symlink files')

    files = _files(source, policy_source)
    missing_assets = [name for name, path in files.items() if not path.is_file()]
    if missing_assets:
        raise doctor.ConfigError('protocol distribution is missing required adoption assets')
    try:
        contents = {name: path.read_bytes() for name, path in files.items()}
    except OSError as exc:
        raise doctor.ConfigError('adoption inputs or protocol assets are unreadable') from exc
    doctor.validate_config(doctor.load_yaml_content(contents['security.config.yml']))
    doctor.validate_policy(doctor.load_yaml_content(contents['.security/policies/security-policy.yml']))
    doctor.validate_finding_schema(doctor.TOOL_ROOT / 'schemas/finding.schema.json')

    required_dirs = _required_dirs(files)
    conflicts = [name for name in files if (root / name).exists() or (root / name).is_symlink()]
    conflicts.extend(name + ' (expected directory)' for name in required_dirs
                     if (root / name).is_symlink() or ((root / name).exists() and not (root / name).is_dir()))
    planned_dirs = sorted(name for name in required_dirs if not (root / name).exists())
    return {
        'project': doctor.project_name(root), 'command': 'adopt', 'result': 'REVIEW_REQUIRED',
        'exit_code': doctor.REVIEW_REQUIRED, 'mode': 'preview',
        'files_to_create': sorted(files), 'directories_to_create': planned_dirs,
        'conflicts': sorted(conflicts), 'config_valid': True,
    }, contents, root


def apply_adoption(root, config_path, policy_path):
    report, contents, root = plan_adoption(root, config_path, policy_path)
    if report['conflicts']:
        report.update(result='REVIEW_REQUIRED', exit_code=doctor.REVIEW_REQUIRED,
                      mode='blocked', detail='existing paths were preserved; resolve conflicts explicitly')
        return report

    created_files = []
    created_dirs = []
    required_dirs = _required_dirs(contents)
    try:
        with tempfile.TemporaryDirectory(prefix='.csp-adopt-', dir=root) as staging:
            staging = Path(staging)
            for name, data in contents.items():
                staged_file = staging / name
                staged_file.parent.mkdir(parents=True, exist_ok=True)
                staged_file.write_bytes(data)

            # Recheck immediately before writing. O_EXCL prevents replacing a file
            # created by another process after the preflight check.
            for name in sorted(required_dirs, key=lambda value: (len(Path(value).parts), value)):
                directory = root / name
                if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                    raise FileExistsError('adoption directory conflict')
                if not directory.exists():
                    directory.mkdir()
                    created_dirs.append(directory)

            for name in contents:
                destination = root / name
                staged_file = staging / name
                data = staged_file.read_bytes()
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                created_files.append(destination)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
    except Exception as exc:
        for path in reversed(created_files):
            path.unlink(missing_ok=True)
        for path in sorted(set(created_dirs), key=lambda p: len(p.parts), reverse=True):
            try:
                path.rmdir()
            except OSError:
                pass
        report.update(result='TOOL_ERROR', exit_code=doctor.TOOL_ERROR,
                      mode='failed', detail=type(exc).__name__)
        return report

    report.update(result='ADOPTED', exit_code=doctor.PASS, mode='applied', conflicts=[])
    return report
