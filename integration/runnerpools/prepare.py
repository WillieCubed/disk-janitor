#!/usr/bin/env python3
"""Prepare reviewed runtime source; never edit installed/protected broker files."""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def patched(source):
    edits = [
        ('import process_control as control\n', 'import process_control as control\nrunnerpools_bridge = control\n'),
        ('        reclaim=None,\n', '        reclaim=None,\n        resource_bridge=None,\n'),
        ('        self.reclaim = reclaim\n', '        self.reclaim = reclaim\n        self.resource_bridge = resource_bridge or runnerpools_bridge.BrokerBridge()\n        self._shared_bridge = None\n'),
        ('                yield\n        except control.StateError:', '''                with self.resource_bridge.transaction(self.global_root) as bridge:
                    self._shared_bridge = bridge
                    try:
                        if bridge:
                            bridge.publish(self._scan(), self.global_root.stat().st_dev)
                        yield
                    finally:
                        try:
                            if bridge:
                                bridge.publish(self._scan(), self.global_root.stat().st_dev)
                        finally:
                            self._shared_bridge = None
        except runnerpools_bridge.BridgeUnavailable:
            raise CapacityWaiting("Shared local/CI admission is unavailable; existing work is preserved.") from None
        except control.StateError:'''),
        ('    def _write(self, platform, record):\n        control.atomic_write(', '''    def _write(self, platform, record):
        if self._shared_bridge and record["state"] in ACTIVE:
            # Export the claim durably before the authoritative journal can
            # admit VM work. An interrupted commit remains conservative.
            records = [r for r in self._scan() if
                       (r["profile_id"], r["platform"]) != (record["profile_id"], platform)]
            self._shared_bridge.publish(records + [record], self.global_root.stat().st_dev)
        control.atomic_write('''),
        ('            active = self._scan()\n            if self.profile.get("fleet") and len(active) >= 2:', '''            active = self._scan()
            local = self._shared_bridge.local_claims() if self._shared_bridge else []
            device = self.global_root.stat().st_dev
            local_disk = sum(max((v["budget"] for v in item["volumes"] if v["device"] == device), default=0) for item in local)
            local_reserve = max([0] + [v["reserve"] for item in local for v in item["volumes"] if v["device"] == device])
            if self.profile.get("fleet") and len(active) >= 2:'''),
        ('            reserve = max(\n                [resources["reserve_bytes"]]', '''            if sum(r["resources"]["memory_bytes"] for r in active) + resources["memory_bytes"] + sum(item["memory"] for item in local) > memory:
                raise CapacityWaiting("Shared local/CI memory commitments are occupied; waiting for completion.")
            reserve = max(
                [resources["reserve_bytes"], local_reserve]'''),
        ('            budget = resources["disk_bytes"] + sum(\n', '            budget = resources["disk_bytes"] + local_disk + sum(\n'),
        ('    def run_once(self, platform):\n', '    def run_once(self, platform):\n        if self.resource_bridge.binding() is not None:\n            with self._resources():\n                pass  # Refresh joined admission for idle/unavailable/drained pools.\n'),
    ]
    for before, after in edits:
        if source.count(before) != 1:
            raise ValueError('reviewed broker source changed; exact adaptation requires review: '+repr(before[:80]))
        source = source.replace(before, after, 1)
    return source


def prepare(source, output):
    source, output = Path(source), Path(output)
    output.mkdir(parents=True, exist_ok=False)
    original = (source / 'pool_runtime.py').read_text()
    result = patched(original)
    # Only copies: supported native installer still owns integrity checks,
    # quiescence, recovery and privileged runtime publication.
    for path in source.iterdir():
        if path.is_file() and path.suffix == '.py':
            shutil.copy2(path, output / path.name)
    (output / 'pool_runtime.py').write_text(result)
    bridge = (REPO / 'bin/runnerpools_bridge.py').read_text()
    digest = hashlib.sha256(bridge.encode()).hexdigest()
    spec = importlib.util.spec_from_file_location('reviewed_local_installer', REPO / 'bin/install_runtime.py')
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)  # Unprivileged reviewed source preparation only.
    launcher_digest = hashlib.sha256(installer.launcher_bytes()).hexdigest()
    control = output / 'process_control.py'
    control.write_text(control.read_text()+'\n\n# Shared local/CI admission; included in the existing exact runtime receipt.\n'+bridge+
                       '\nADMISSION_BRIDGE_SHA256 = '+repr(digest)+'\n'+
                       'ADMISSION_LAUNCHER_SHA256 = '+repr(launcher_digest)+'\n')
    host = output / 'pool_host.py'
    if host.exists():
        text = host.read_text()
        needle = '        proof = macos_owner_session(profile, owner_home)\n'
        if text.count(needle) != 1:
            raise ValueError('native installation boundary changed')
        text = text.replace(needle, '        _join_local_admission(profile, owner_home)\n'+needle)
        hook = (HERE / 'native_hook.py').read_text()
        host.write_text(text+'\n\n'+hook)
    patch = ''.join(difflib.unified_diff(original.splitlines(True), result.splitlines(True),
                   fromfile='a/pool_runtime.py', tofile='b/pool_runtime.py'))
    (output / 'pool_runtime.py.patch').write_text(patch)
    receipt = dict(source=str(source), source_sha256=hashlib.sha256(original.encode()).hexdigest(),
                   candidate_sha256=hashlib.sha256(result.encode()).hexdigest(), deployed=False)
    (output / 'bridge-review.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt


def package_candidate(package, reviewed, output):
    """Keep the public operator's complete package layout and exact host payload."""
    package, reviewed, output = Path(package).resolve(strict=True), Path(reviewed), Path(output)
    shutil.copytree(package, output, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
    scripts = output / 'skills/self-hosted-runner/scripts'
    if not (scripts / 'runner_operator.py').is_file() or not (output / 'core/terminal.py').is_file():
        raise ValueError('complete reviewed operator package required')
    # Retain the exact installed runtime baseline plus the three reviewed edits.
    # Supplemental user-only operator modules remain from the selected package.
    for path in reviewed.glob('*.py'):
        shutil.copy2(path, scripts / path.name)
    return scripts / 'runner_operator.py'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--package', type=Path, help='complete reviewed operator package for an optional runnable package copy')
    args = parser.parse_args()
    receipt = prepare(args.source, args.output)
    if args.package:
        receipt['operator'] = str(package_candidate(args.package, args.output, args.output / 'package'))
    print(json.dumps(receipt, indent=2))
