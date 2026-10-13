#!/usr/bin/env python3
"""Offline staged-content guard, SPEC §12.1."""
import re
import subprocess
import sys

EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
ALLOWED = {'example.com', 'example.org', 'example.jp'}
KEY = re.compile(r'(?m)^\s*(?:export\s+)?HIBP_API_KEY\s*=\s*(.*)$')


def git(*args, data=None):
    return subprocess.run(['git', *args], input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout


def check():
    gitignore = git('show', ':.gitignore')
    entries = git('ls-files', '--stage', '-z').split(b'\0')
    staged = git('diff', '--cached', '--name-only', '--diff-filter=ACMRT', '-z')
    paths = set(staged.split(b'\0')) - {b''}
    reasons = []
    for entry in entries:
        if not entry:
            continue
        meta, path = entry.split(b'\t', 1)
        if path not in paths:
            continue
        mode, oid, stage = meta.split()
        number = len(reasons) + 1
        reason = None
        parts = path.split(b'/')
        # Evaluate the tracked ignore rules independently of local overrides.
        import fnmatch
        rules = [line.strip() for line in gitignore.decode('utf-8').splitlines()
                 if line.strip() and not line.startswith('#')]
        ignored = False
        for rule in rules:
            negative = rule.startswith('!')
            pattern = rule.lstrip('!').rstrip('/')
            candidates = [p.decode('utf-8', 'surrogateescape') for p in parts]
            matched = (any(fnmatch.fnmatchcase(p, pattern) for p in candidates)
                       if '/' not in pattern else
                       fnmatch.fnmatchcase(path.decode('utf-8', 'surrogateescape'), pattern))
            if matched:
                ignored = not negative
        if ignored:
            reason = '除外対象のファイル'
        elif mode not in (b'100644', b'100755') or stage != b'0':
            reason = '通常ファイル以外'
        else:
            content = git('cat-file', 'blob', oid.decode('ascii'))
            try:
                text = content.decode('utf-8')
            except UnicodeDecodeError:
                reason = 'UTF-8 以外'
            else:
                if b'\0' in content or content.startswith(b'SQLite format 3'):
                    reason = 'バイナリまたはキャッシュ'
                elif any(m.group(1).lower() not in ALLOWED for m in EMAIL.finditer(text)):
                    reason = '許可外のメールアドレス'
                elif re.search(r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----', text):
                    reason = '秘密鍵'
                else:
                    for match in KEY.finditer(text):
                        value = match.group(1).strip().strip('\"\'')
                        if value and not value.startswith(('$', '`')):
                            reason = 'API キーの直接代入'
                            break
        reasons.append(reason)
        if reason:
            print(f'拒否: ファイル {number}: {reason}', file=sys.stderr)
    return int(any(reasons))


def main():
    try:
        return check()
    except Exception:
        print('拒否: コミット前検査を完了できませんでした', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
