# AGENTS.md — 実装する人・エージェント向けの作業ルール

このリポジトリで作業する人（Claude Code、Codex などのエージェントを含む）が守るルール。

## 1. SSOT

- 仕様の正は次の 2 つ。範囲は重ならない。README、コード、テストはこれらから導く。
  - 調査ツール（検出からレポート出力まで）: [SPEC.md](SPEC.md)
  - 事後対応（検出後の判定・封じ込め・復旧）: [docs/post-investigation-response-design.md](docs/post-investigation-response-design.md)
- SPEC §8.3 のリスク区分と §10 の出力の列は、事後対応の仕様 §5 の入力になっている。片方を変えるときは、もう片方も確かめる。
- SPEC.md の「状態」が承認済みになるまで、実装（`email_breach_audit.py`、`tests/`）に手をつけない。
- 仕様にない振る舞いを足したくなったら、コードより先に SPEC.md の変更を提案する。
- 仕様を変えるときは、版を上げて、その文書の変更履歴に追記する。
- コードと SPEC.md が食い違っていたら、SPEC.md に合わせる。SPEC.md のほうが間違っていると思ったら、勝手に直さず指摘する。

## 2. 実装の制約

- Python 3.10 以上、標準ライブラリのみ（SPEC §2 C-3）。
- 本体は `email_breach_audit.py` の 1 ファイル（SPEC §15）。
- テストは `tests/` に置き、`python3 -m unittest` で動かす。
- テストから外部の API を呼ばない。プロバイダはモックにする（SPEC §14）。

## 3. 公開リポジトリとしての禁止事項

このリポジトリは公開されている（SPEC §12 S-7・S-8）。

- 実在のメールアドレスをコミットしない。例やテストには `example.com` / `example.org` / `example.jp` だけを使う。
- キャッシュ（`*.sqlite`）、出力物（`*.csv`、`report.html`）、API キー、`.env` をコミットしない。
- 流出したパスワード（平文、ハッシュ、マスク済み）を扱うコードを書かない（SPEC §12 S-1）。

## 4. コミット前の確認

- `git status` で、`.gitignore` の対象が紛れていないか見る。
- `git diff --cached | grep -E '@' ` で、予約済みドメイン以外のアドレスが入っていないか見る。
