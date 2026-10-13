"""Install without overwriting existing hook configuration."""
from pathlib import Path
import subprocess
import sys

configured = subprocess.run(['git', 'config', '--get', 'core.hooksPath'],
                            capture_output=True, text=True)
if configured.returncode not in (0, 1):
    sys.exit('Git 設定を確認できませんでした')
if configured.returncode == 0:
    if configured.stdout.strip() == '.githooks':
        sys.exit(0)
    sys.exit('既存の hooksPath があります。既存 pre-commit から python3 scripts/check_staged.py を呼び、失敗時はコミットを止めてください。')
hook_path = subprocess.check_output(['git', 'rev-parse', '--git-path', 'hooks/pre-commit'], text=True).strip()
if Path(hook_path).exists() or Path(hook_path).is_symlink():
    sys.exit('既存の pre-commit があります。そこから python3 scripts/check_staged.py を呼び、失敗時はコミットを止めてください。')
Path('.githooks/pre-commit').chmod(0o755)
subprocess.run(['git', 'config', '--local', 'core.hooksPath', '.githooks'], check=True)
print('コミット前検査を有効にしました')
