"""Explicit TEST_ONLY evidence producers for policy consumer acceptance tests."""
import hashlib
import json

from tests.m2_support import FindingProject
from lib import normalize
from lib.storage_io import atomic_json


class GateProject(FindingProject):
    def context(self, event='release'):
        run_id = self.evidence(results=False)
        normalize.normalize(self.root, run_id)
        context = dict(version=1, event=event, changed_files=[],
            dependencies=dict(lockfiles_changed=[], added=[], sbom_enabled=False, sbom_diff=None),
            patch=dict(source='none', trust='standard', finding_ids=[], rescan_run_id=None),
            coverage=dict(enabled=False, before=None, after=None), evidence={})
        for name in ('static_scan', 'tests', 'security_rescan', 'runtime_verify'):
            record = dict(type=name, state='PASS', source='TEST_ONLY_DETERMINISTIC_PRODUCER',
                          timestamp='2026-10-09T00:00:01Z')
            if name in ('static_scan', 'security_rescan'):
                path = self.root / '.security/reports' / (run_id + '-scan-report.json')
            else:
                path = self.root / '.security/evidence' / (name + '.json')
                atomic_json(path, dict(record, exit_code=0, timed_out=False, completed=True))
            record.update(raw_reference=path.relative_to(self.root).as_posix(),
                          sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            context['evidence'][name] = record
        atomic_json(self.root / '.security/evidence/gate-context.json', context)
        return context

    def write_context(self, context):
        atomic_json(self.root / '.security/evidence/gate-context.json', context)

    def finding(self, severity='HIGH', category='code-injection', status='OPEN', first='2026-10-09T00:00:00Z'):
        run_id = self.evidence(number=2, category=category)
        normalize.normalize(self.root, run_id)
        from lib import store
        store.update(self.root, run_id)
        value = store.show(self.root, 'SEC-0001')['finding']
        value.update(severity=severity, status=status, first_seen=first)
        value['history'].append(dict(timestamp=value['last_seen'], status=status, event='TEST_ONLY_SEEDED_STATE'))
        atomic_json(self.root / '.security/findings/SEC-0001.json', value)
        return value
