import importlib.util
import os
from pathlib import Path
import plistlib
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
MB = 1024 ** 2


class ServiceLogCapTests(unittest.TestCase):
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
        os.environ['DISK_JANITOR_LOG_CAP_MB'] = '16'
        self.addCleanup(os.environ.pop, 'DISK_JANITOR_PROJECT_DIRS', None)
        self.addCleanup(os.environ.pop, 'DISK_JANITOR_LOG_CAP_MB', None)
        (self.home / 'Library/LaunchAgents').mkdir(parents=True)
        self.logs = self.home / 'service/logs'
        self.logs.mkdir(parents=True)

    def agent(self, label, **paths):
        with (self.home / 'Library/LaunchAgents' / (label + '.plist')).open('wb') as stream:
            plistlib.dump(dict(Label=label, ProgramArguments=['/bin/true'], **paths), stream)

    def log(self, name, megabytes):
        path = self.logs / name
        line = b'{"msg":"Request completed"}\n'
        with path.open('wb') as stream:
            stream.write(line * (int(megabytes * MB) // len(line)))
        return path

    def recover(self, apply=True):
        return self.recovery.recover(self.home, self.app, apply=apply, observer=lambda: ([], []))

    def test_oversized_log_keeps_tail_and_is_emptied_in_place(self):
        log = self.log('relay.log', 40)
        self.agent('relay', StandardOutPath=str(log))
        writer = log.open('ab')  # a running service holding the file open for appending
        inode = log.stat().st_ino

        report = self.recover()

        self.assertEqual(log.stat().st_size, 0)
        self.assertEqual(log.stat().st_ino, inode, 'the log must be emptied in place, not replaced')
        tail = log.with_name('relay.log.1').read_bytes()
        self.assertLessEqual(len(tail), self.recovery.LOG_TAIL_BYTES)
        self.assertTrue(tail.startswith(b'{"msg"'), 'the kept tail starts at a line boundary')
        writer.write(b'next line\n'); writer.close()
        self.assertEqual(log.read_bytes(), b'next line\n')
        self.assertIn('service-log:removed', report['counts'])

    def test_small_logs_unlisted_files_and_previews_are_left_alone(self):
        small = self.log('small.log', 1)
        self.agent('small', StandardErrorPath=str(small))
        stray = self.log('stray.log', 40)  # no launchd agent writes it
        big = self.log('big.log', 40)
        self.agent('big', StandardOutPath=str(big))

        self.recover(apply=False)
        self.assertGreater(big.stat().st_size, 16 * MB)
        self.recover()
        self.assertGreater(small.stat().st_size, 0)
        self.assertGreater(stray.stat().st_size, 16 * MB)
        self.assertFalse(small.with_name('small.log.1').exists())

    def test_symlinked_log_is_not_followed(self):
        target = self.log('target.log', 40)
        link = self.logs / 'link.log'
        link.symlink_to(target)
        self.agent('linked', StandardOutPath=str(link))
        self.recover()
        self.assertGreater(target.stat().st_size, 16 * MB)


if __name__ == '__main__':
    unittest.main()
