"""Slot sizing and external storage-root selection, with injected volumes and disk info."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
GIB = 2**30


def load():
    spec = importlib.util.spec_from_file_location('capacity_storage', REPO / 'bin/capacity.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SlotLimitTests(unittest.TestCase):
    def setUp(self):
        self.capacity = load()
        patcher = patch.dict(os.environ, {}, clear=False)
        patcher.start(); self.addCleanup(patcher.stop)
        os.environ.pop('DISK_JANITOR_MAX_RUNNING', None)

    def limit(self, cores, memory_gib, free_gib):
        pages = memory_gib * GIB // 4096
        with patch.object(self.capacity.os, 'cpu_count', return_value=cores), \
             patch.object(self.capacity.os, 'sysconf', side_effect=lambda n: pages if n == 'SC_PHYS_PAGES' else 4096), \
             patch.object(self.capacity, 'storage_free', return_value=free_gib * GIB):
            return self.capacity.slot_limit()

    def test_cores_bind_when_memory_and_disk_are_plentiful(self):
        self.assertEqual(self.limit(16, 128, 458), 8)

    def test_disk_binds_when_free_space_is_short(self):
        self.assertEqual(self.limit(16, 128, 40), 2)

    def test_memory_binds_on_a_small_machine(self):
        self.assertEqual(self.limit(16, 32, 458), 2)

    def test_never_below_one(self):
        self.assertEqual(self.limit(1, 8, 0), 1)

    def test_configured_value_wins(self):
        os.environ['DISK_JANITOR_MAX_RUNNING'] = '11'
        self.assertEqual(self.limit(16, 128, 0), 11)

    def test_storage_free_counts_each_filesystem_once_and_skips_absent_roots(self):
        usage = type('Usage', (), {'free': 7 * GIB})()
        with tempfile.TemporaryDirectory() as td, \
             patch.object(self.capacity.shutil, 'disk_usage', return_value=usage):
            self.assertEqual(self.capacity.storage_free([Path(td), Path(td), Path(td) / 'absent']), 7 * GIB)


class StorageRootTests(unittest.TestCase):
    def setUp(self):
        self.capacity = load()
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.volumes = Path(self.tmp.name)
        for name in ('Internal', 'ExFat', 'Ext', 'ReadOnly'):
            (self.volumes / name).mkdir()
        self.info = {'Internal': dict(Internal=True, WritableVolume=True, FilesystemType='apfs'),
                     'ExFat': dict(Internal=False, WritableVolume=True, FilesystemType='exfat'),
                     'Ext': dict(Internal=False, WritableVolume=True, FilesystemType='apfs'),
                     'ReadOnly': dict(Internal=False, WritableVolume=False, FilesystemType='apfs')}

    def choose(self):
        with patch.object(self.capacity.os.path, 'ismount', return_value=True):
            return self.capacity.external_storage_root(self.volumes, lambda m: self.info[m.name])

    def test_picks_the_only_writable_external_apfs_volume(self):
        self.assertEqual(self.choose(), self.volumes / 'Ext')

    def test_none_when_no_volume_qualifies(self):
        self.info['Ext']['Internal'] = True
        self.assertIsNone(self.choose())

    def test_unreadable_disk_info_disqualifies_a_volume(self):
        self.info['Ext'] = {}
        self.assertIsNone(self.choose())


if __name__ == '__main__': unittest.main()
