import copy
from datetime import datetime, timezone, timedelta
from pathlib import Path

from tests.support import DoctorProject, doctor
from lib import normalize, store
from lib.storage_io import atomic_json


class FindingProject(DoctorProject):
    def evidence(self, number=1, tools=('semgrep',), results=True, line=2, category='code-injection'):
        config = self.config()
        path = self.root / 'sample.py'
        path.write_text('def example(value):\n    return eval(value)\n', encoding='utf-8')
        run_id = '20261009T000000Z-' + f'{number:032x}'
        items = []
        for tool in ('semgrep', 'trivy'):
            profile = config['scanners'][tool]
            profile.update(enabled=tool in tools, mandatory=tool in tools)
            profile['severity_mapping']['HIGH'] = 'HIGH'
            if tool not in tools:
                items.append({'tool': tool, 'state': 'SKIPPED'})
                continue
            rule_id = tool + '-test-rule'
            rule = {'id': rule_id, 'properties': {'category': category, 'tags': ['HIGH']}}
            result = {'ruleId': rule_id, 'message': {'text': 'TEST_ONLY_FINDING'},
                      'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'sample.py'},
                                    'region': {'startLine': line, 'snippet': {'text': 'return eval(value)'}}}}]}
            data = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': tool, 'rules': [rule]}},
                                               'results': [result] if results else []}]}
            raw = self.root / '.security/raw' / tool / (run_id + '.sarif')
            atomic_json(raw, data)
            items.append({'tool': tool, 'state': 'FINDINGS' if results else 'CLEAN',
                          'profile': copy.deepcopy(profile), 'raw_reference': raw.relative_to(self.root).as_posix(),
                          'findings_count': int(results), 'scanner_exit_code': 0, 'timed_out': False})
        self.write_config(config)
        report = {'run_id': run_id, 'result': 'SCAN_COMPLETED', 'exit_code': 0,
                  'finished_at': (datetime(2026, 10, 9, tzinfo=timezone.utc) + timedelta(seconds=number)).isoformat().replace('+00:00', 'Z'),
                  'scanners': items}
        atomic_json(self.root / '.security/reports' / (run_id + '-scan-report.json'), report)
        return run_id

    def populated(self):
        run_id = self.evidence()
        normalize.normalize(self.root, run_id)
        store.update(self.root, run_id)
        return run_id
