import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
OLD = time.time() - 7 * 86400


def run(cwd, *args):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                   env=dict(os.environ, GIT_AUTHOR_DATE=f'@{int(OLD)}', GIT_COMMITTER_DATE=f'@{int(OLD)}',
                            GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1'))


class WorktreeRetirementTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('recovery', REPO / 'bin/recovery.py')
        self.recovery = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.recovery)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.app = self.home / '.dj'
        self.app.mkdir()
        os.environ['DISK_JANITOR_PROJECT_DIRS'] = str(self.home / 'Projects')
        self.addCleanup(os.environ.pop, 'DISK_JANITOR_PROJECT_DIRS', None)
        # A remote with main, and a clone under Projects whose origin/main tracks it.
        self.remote = self.home / 'remote.git'
        run(self.home, 'git', 'init', '-q', '--bare', '-b', 'main', str(self.remote))
        self.repo = self.home / 'Projects/app'
        run(self.home, 'git', 'clone', '-q', str(self.remote), str(self.repo))
        self.commit('README', 'hello')
        run(self.repo, 'git', 'push', '-q', 'origin', 'HEAD:main')
        run(self.repo, 'git', 'remote', 'set-head', 'origin', 'main')

    def commit(self, name, text, cwd=None):
        cwd = cwd or self.repo
        (cwd / name).write_text(text)
        run(cwd, 'git', '-c', 'user.name=t', '-c', 'user.email=t@t', 'add', name)
        run(cwd, 'git', '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', name)

    def worktree(self, name, branch, start='origin/main'):
        path = self.home / 'agents' / name
        run(self.repo, 'git', 'worktree', 'add', '-q', '-b', branch, str(path), start)
        self.age(path)
        return path

    def age(self, path):
        git_dir = Path((path / '.git').read_text().split(': ', 1)[1].strip())
        for p in (git_dir / 'HEAD', git_dir / 'index', git_dir / 'logs/HEAD'):
            if p.exists():
                os.utime(p, (OLD, OLD))

    def recover(self, apply=True, paths=()):
        return self.recovery.recover(self.home, self.app, apply=apply, observer=lambda: ([], list(paths)))

    def scheduled(self, maintain):
        # The scheduled pass with plenty of free space: no device is below its floor.
        return self.recovery.recover(self.home, self.app, apply=True, pressure_only=True, maintain=maintain,
                                     floors={str(self.home): 0}, observer=lambda: ([], []))

    def test_scheduled_maintenance_retires_finished_worktrees_without_disk_pressure(self):
        tree = self.worktree('merged', 'feature/merged')
        report = self.scheduled(maintain=True)
        self.assertEqual(report['status'], 'no-disk-pressure')
        self.assertEqual(self.statuses(report)[str(tree)], 'removed')
        self.assertFalse(tree.exists())

    def test_pressure_pass_without_maintenance_leaves_worktrees_when_space_is_free(self):
        tree = self.worktree('merged', 'feature/merged')
        report = self.scheduled(maintain=False)
        self.assertEqual(report['status'], 'no-disk-pressure')
        self.assertTrue(tree.exists())

    def statuses(self, report):
        return {e['path']: e['status'] for e in report['entries'] if e['kind'] == 'worktree-retire'}

    def test_merged_clean_idle_worktree_is_retired_and_branch_kept(self):
        tree = self.worktree('merged', 'feature/merged')
        report = self.recover()
        self.assertEqual(self.statuses(report)[str(tree)], 'removed')
        self.assertFalse(tree.exists())
        run(self.repo, 'git', 'rev-parse', '--verify', 'refs/heads/feature/merged')

    def test_preview_retires_nothing(self):
        tree = self.worktree('preview', 'feature/preview')
        report = self.recover(apply=False)
        self.assertEqual(self.statuses(report)[str(tree)], 'eligible')
        self.assertTrue(tree.exists())

    def test_branch_deleted_upstream_is_retired(self):
        tree = self.worktree('gone', 'feature/gone')
        self.commit('work', 'done', cwd=tree)
        run(tree, 'git', 'push', '-q', '-u', 'origin', 'feature/gone')
        run(self.repo, 'git', 'push', '-q', 'origin', '--delete', 'feature/gone')
        run(self.repo, 'git', 'fetch', '-q', '--prune')
        self.age(tree)
        self.assertEqual(self.statuses(self.recover())[str(tree)], 'removed')
        run(self.repo, 'git', 'rev-parse', '--verify', 'refs/heads/feature/gone')

    def test_squash_merged_branch_is_retired(self):
        tree = self.worktree('squashed', 'feature/squashed')
        self.commit('a', 'one', cwd=tree)
        self.commit('b', 'two', cwd=tree)
        self.age(tree)
        # Land both commits on main as one squash commit.
        run(self.repo, 'git', 'merge', '-q', '--squash', 'feature/squashed')
        run(self.repo, 'git', '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'squash')
        run(self.repo, 'git', 'push', '-q', 'origin', 'HEAD:main')
        run(self.repo, 'git', 'fetch', '-q')
        self.assertEqual(self.statuses(self.recover())[str(tree)], 'removed')
        run(self.repo, 'git', 'rev-parse', '--verify', 'refs/heads/feature/squashed')

    def test_unmerged_dirty_recent_locked_and_occupied_worktrees_are_kept(self):
        unmerged = self.worktree('unmerged', 'feature/unmerged')
        self.commit('work', 'local only', cwd=unmerged)
        self.age(unmerged)
        dirty = self.worktree('dirty', 'feature/dirty')
        (dirty / 'notes.txt').write_text('untracked work')
        recent = self.home / 'agents/recent'
        run(self.repo, 'git', 'worktree', 'add', '-q', '-b', 'feature/recent', str(recent), 'origin/main')
        locked = self.worktree('locked', 'feature/locked')
        run(self.repo, 'git', 'worktree', 'lock', str(locked))
        occupied = self.worktree('occupied', 'feature/occupied')

        report = self.recover(paths=[str(occupied / 'README')])

        for tree in (unmerged, dirty, recent, locked, occupied):
            self.assertTrue(tree.exists(), str(tree))
        self.assertEqual(self.statuses(report)[str(occupied)], 'active')
        self.assertEqual(report['worktrees_kept'], 4)

    def test_space_report_groups_worktrees_by_state_and_folder(self):
        ready = self.worktree('ready', 'feature/ready')
        dirty = self.worktree('dirty', 'feature/dirty')
        (dirty / 'notes.txt').write_text('work')
        result = self.recovery.space(self.home, observer=lambda: ([], []))
        states = result['worktrees']['states']
        self.assertEqual(states['ready to retire']['count'], 1)
        self.assertEqual(states['uncommitted work preserved']['count'], 1)
        self.assertEqual([r['path'] for r in result['worktrees']['ready']], [str(ready)])
        self.assertEqual(result['worktrees']['folders'][str(self.home / 'agents')]['count'], 2)
        self.assertTrue(ready.exists(), 'the report changes nothing')
        text = self.recovery._render_space(result, self.home)
        self.assertIn('ready to retire', text)

    def test_main_checkout_is_never_retired(self):
        self.recover()
        self.assertTrue((self.repo / 'README').exists())


if __name__ == '__main__':
    unittest.main()
