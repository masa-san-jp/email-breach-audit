# email-breach-audit

組織が付与したメールアドレスの流出を調べて、その結果に応じた事後対応までを整理するリポジトリ。

| 部分 | 内容 | 仕様（SSOT） |
|---|---|---|
| 調査ツール | メールアドレスの一覧を複数の流出 DB でまとめて照合し、全件をリスク区分つきのレポートにする | [SPEC.md](SPEC.md) |
| 事後対応 | 調査結果を受けて、判定・封じ込め・復旧・再発防止を人が行う手順（Google Workspace / Microsoft 365） | [docs/post-investigation-response-design.md](docs/post-investigation-response-design.md) |

それぞれの仕様が、その範囲の唯一の正（SSOT）。版と状態は各仕様の冒頭にある。この README は入口で、値や規則は書かずに仕様の節へリンクする。

## 調査ツール

| 知りたいこと | 仕様の節 |
|---|---|
| 目的と範囲 | [SPEC §1](SPEC.md#1-目的) |
| 使う前に守ること（権限・承認） | [SPEC §2](SPEC.md#2-前提と制約) |
| 照会先の DB と各 API | [SPEC §5](SPEC.md#5-プロバイダ仕様) |
| リスク区分の決め方 | [SPEC §8](SPEC.md#8-判定の規則) |
| 出力されるファイルと出力先 | [SPEC §10](SPEC.md#10-出力仕様) |
| コマンドのオプションと環境変数 | [SPEC §11](SPEC.md#11-cli-仕様) |
| 個人情報の扱い | [SPEC §12](SPEC.md#12-セキュリティとプライバシー) |

使い方（Python 3 の標準ライブラリだけで動く。オプションと環境変数は [SPEC §11](SPEC.md#11-cli-仕様)）:

```sh
HIBP_API_KEY="$(cat ~/.config/email-breach-audit/hibp_api_key)" python3 email_breach_audit.py <アドレスの一覧のファイル>
```

結果は `~/breach-check-output/` の `report.md`（読む用）、`summary.csv`・`findings.csv`（集計用）、`history.csv`（全実行の履歴）に出る（[SPEC §10](SPEC.md#10-出力仕様)）。

検出の後の判定と対応は、[事後対応の仕様](docs/post-investigation-response-design.md)に従う。

## 作業する人へ

[AGENTS.md](AGENTS.md) を読んでから始める。仕様の変え方もそこに書いてある。

## ライセンス

[MIT](LICENSE)

## 謝辞

照会先の一つとして [LeakCheck](https://leakcheck.io) の Public API を使う。
