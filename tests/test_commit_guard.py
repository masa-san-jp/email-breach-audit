import os
from pathlib import Path
import subprocess
import tempfile
import unittest

GUARD = Path(__file__).resolve().parents[1] / 'scripts/check_staged.py'


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '-q')
        (self.root / '.gitignore').write_text('*.csv\ninput/\n*.sqlite\n.env\n')
        self.git('add', '.gitignore')

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.root, check=True,
                              capture_output=True)

    def run_guard(self):
        return subprocess.run(['python3', str(GUARD)], cwd=self.root,
                              capture_output=True)

    def stage(self, content, name='note.txt'):
        (self.root / name).write_bytes(content)
        self.git('add', '-f', '--', name)

    def test_allowed(self):
        self.stage(b'taro@example.com\nhanako@EXAMPLE.JP')
        self.assertEqual(self.run_guard().returncode, 0)

    def test_rejections_and_private_output(self):
        samples = [b'taro@' + b'sub.example.com', b'taro@' + b'SUB.EXAMPLE.COM',
                   b'HIBP_API_KEY=MOCK_SECRET', b'-----BEGIN ' + b'PRIVATE KEY-----',
                   b'SQLite format 3\0', b'\xff', b'a\0b']
        name = 'private space\nname.txt'
        for sample in samples:
            with self.subTest(sample=sample):
                self.stage(sample, name)
                result = self.run_guard()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(sample, result.stderr)
                self.assertNotIn(name.encode(), result.stderr)

    def test_forced_ignored_file(self):
        self.stage(b'innocent', 'result.csv')
        self.assertNotEqual(self.run_guard().returncode, 0)

    def test_index_not_worktree(self):
        self.stage(b'taro@' + b'sub.example.com')
        (self.root / 'note.txt').write_text('taro@example.com')
        self.assertNotEqual(self.run_guard().returncode, 0)

    def test_rename(self):
        self.stage(b'taro@' + b'sub.example.com')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.com',
                 'commit', '-qm', 'fixture')
        self.git('mv', 'note.txt', 'renamed.txt')
        self.assertNotEqual(self.run_guard().returncode, 0)

    def test_symlink(self):
        os.symlink('missing', self.root / 'link')
        self.git('add', 'link')
        self.assertNotEqual(self.run_guard().returncode, 0)

    def test_failure_closed(self):
        self.git('reset', '--', '.gitignore')
        self.assertNotEqual(self.run_guard().returncode, 0)
