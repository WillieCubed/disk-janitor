import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


class JanitorRunTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory()
        self.home = Path(self.sandbox.name)
        self.fakebin = self.home / 'bin'
        self.fakebin.mkdir()
        (self.home / 'Projects').mkdir()
        (self.home / '.cache/cargo-target').mkdir(parents=True)
        self.env = dict(os.environ, HOME=str(self.home),
                        DISK_JANITOR_HOME=str(self.home / '.dj'),
                        DISK_JANITOR_NO_SCHED='1',
                        PATH=str(self.fakebin) + ':' + os.environ['PATH'])
        for name in ('cargo', 'cargo-sweep'):
            self.command(name, 'exit 0')
        (self.home / '.dj').mkdir()
        (self.home / '.dj/config.env').write_text(
            'cargo() { "$HOME/bin/cargo" "$@"; }\n'
            'cargo-sweep() { "$HOME/bin/cargo-sweep" "$@"; }\n'
            'pnpm() { "$HOME/bin/pnpm" "$@"; }\n')

    def tearDown(self):
        self.sandbox.cleanup()

    def command(self, name, body):
        path = self.fakebin / name
        path.write_text('#!/bin/sh\n' + body + '\n')
        path.chmod(0o755)

    def run_janitor(self, *args):
        return subprocess.run(['bash', str(REPO / 'bin/disk-janitor'), *args],
                              cwd='/', env=self.env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=15)

    def test_pnpm_prune_runs_in_writable_home(self):
        self.command('pnpm', 'test "$PWD" = "$HOME" || exit 23\nprintf done > "$HOME/pruned"')
        result = self.run_janitor('run')
        self.assertTrue((self.home / 'pruned').exists(), result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_cleanup_failure_is_visible_and_nonzero(self):
        self.command('pnpm', 'echo fixture-prune-failed >&2; exit 23')
        result = self.run_janitor('run')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('pnpm store prune failed', result.stdout)
        self.assertIn('cleanup incomplete', result.stdout)

    def test_dry_run_does_not_prune(self):
        self.command('pnpm', 'touch "$HOME/pruned"')
        result = self.run_janitor('run', '--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.home / 'pruned').exists())


if __name__ == '__main__':
    unittest.main()
