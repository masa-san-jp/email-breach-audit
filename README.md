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

### 初めて使う方へ

このツールには、次の3種類のファイルがあります。

| 種類 | 内容 | 保存する場所 |
|---|---|---|
| プログラム | このリポジトリから取得したコードや説明書 | `email-breach-audit` フォルダ |
| 入力データ | 調べるメールアドレスの一覧、API キー | 下の手順で作る専用フォルダ |
| 調査結果 | レポート、CSV、キャッシュ、実行履歴 | プログラムが出力するフォルダ |

**メールアドレスの一覧と API キーは、プログラムのフォルダに入れないでください。** このリポジトリは公開されています。調査結果にも個人情報が含まれるので、プログラムのフォルダへコピーしないでください。

以下は macOS・Linux のターミナルで使う手順です。`~` は自分のホームフォルダを表します。Windows では、組織の担当者に保存場所・アクセス権とコマンドを確認してください。

実行前に、組織の情報システム部門またはセキュリティ責任者の承認を得てください。実行すると、一覧のメールアドレスを外部の流出情報サービスへ送って調べます。対象と送信先は [SPEC §2](SPEC.md#2-前提と制約)・[§5](SPEC.md#5-プロバイダ仕様) を参照してください。

#### 1. プログラムを取得する

Python 3.10 以上と Git が必要です。Python の追加パッケージは不要です。

```sh
git clone https://github.com/masa-san-jp/email-breach-audit.git
cd email-breach-audit
```

以降のプログラムを実行するコマンドは、この `email-breach-audit` フォルダで実行します。

#### 2. 誤って公開するのを防ぐ検査を有効にする

```sh
python3 scripts/install_hooks.py
```

「コミット前検査を有効にしました」と表示されたら完了です。これは、Git に変更を記録する操作（コミット）の直前に、追加予定のファイルを自動検査する仕組みです。メールリストなどを誤って追加した場合、コミットを止めます。

**ダウンロード・クローンしただけでは有効になりません。利用する人それぞれが、取得したフォルダでこのコマンドを実行してください。** すでに有効な場合は何も表示せず終了します。既存の Git フックがあるという案内が出た場合は、組織の開発担当者に併用の設定を依頼してください。

Git を使わずに調査する人も、入力データは次の専用フォルダへ保存してください。この検査は、調査の実行時やファイル保存時に働くものではありません。

#### 3. メールリストを保存するフォルダを作る

```sh
mkdir -p ~/.local/share/email-breach-audit/private
chmod 700 ~/.local/share/email-breach-audit/private
touch ~/.local/share/email-breach-audit/private/addresses.txt
chmod 600 ~/.local/share/email-breach-audit/private/addresses.txt
```

このコマンドで、プログラムの外に専用フォルダと空のリストを作り、自分だけが読み書きできる権限にします。この場所が Google Drive・OneDrive・Dropbox などの同期対象や、別の Git リポジトリの中でないことを確認してください。不明な場合は組織の担当者に確認してください。保存場所の規則は [SPEC §12.1](SPEC.md#121-誤公開防止) にあります。

作成した `addresses.txt` をテキストエディタで開き、調べるアドレスを1行に1件ずつ書いて保存します。エディタでは UTF-8 のテキストとして保存してください。

```text
taro@example.com
hanako@example.com
```

上のアドレスは説明用です。自分の組織から調査を許可されたアドレスに置き換えてください。入力形式の詳細は [SPEC §4](SPEC.md#4-入力仕様) を参照してください。

#### 4. 調査を実行する

API キーがない場合は、次のコマンドで実行できます。HIBP はスキップされ、LeakCheck で調べます。

```sh
python3 email_breach_audit.py ~/.local/share/email-breach-audit/private/addresses.txt
```

HIBP も使う場合は、契約した API キーを同じ専用フォルダへ保存します。

```sh
touch ~/.local/share/email-breach-audit/private/hibp_api_key
chmod 600 ~/.local/share/email-breach-audit/private/hibp_api_key
```

`hibp_api_key` をテキストエディタで開き、キーを1行で書いて保存してください。その後、次を実行します。

```sh
HIBP_API_KEY="$(cat ~/.local/share/email-breach-audit/private/hibp_api_key)" python3 email_breach_audit.py ~/.local/share/email-breach-audit/private/addresses.txt
```

既存の別の場所にキーを保存している場合は、`cat` の後のパスをその保存場所に置き換えます。キーの契約先は [HIBP](https://haveibeenpwned.com/API/Key)、オプションの一覧は [SPEC §11](SPEC.md#11-cli-仕様) を参照してください。

#### 5. 結果を読む

既定ではホームフォルダの `breach-check-output` に結果が出ます。この場所もクラウド同期や別の Git リポジトリの対象外であることを、実行前に確認してください。

- `report.md`：調査結果と対応内容を読むためのレポート
- `summary.csv`・`findings.csv`：集計用のデータ
- `history.csv`：実行ごとの結果を積み重ねた履歴

出力の詳細は [SPEC §10](SPEC.md#10-出力仕様)、検出後の対応は [事後対応の仕様](docs/post-investigation-response-design.md) を参照してください。

### コミットを止められた場合

例えば、メールリストをプログラムのフォルダへ誤ってコピーし、Git に追加すると、コミット時に次のような表示が出ます。

```text
拒否: ファイル 1: 許可外のメールアドレス
```

この時点ではコミットは作られていません。検査は個人情報を表示しないため、メールアドレスやファイル名は出しません。

誤って追加したファイルがわかる場合は、次の順に対処します。

1. `git status` で追加予定のファイルを確認する。画面の内容を公開の場所へ貼り付けない。
2. `git restore --staged -- "対象ファイルのパス"` で、コミット予定から外す。ファイル自体は削除されない。
3. メールリストやキーなら、上の専用フォルダへ移す。調査結果なら、プログラムのフォルダの外へ移す。
4. `git status` で対象が外れたことを確認し、必要な変更だけをコミットする。

最初のコミットがまだないリポジトリでは、手順2の代わりに `git rm --cached -- "対象ファイルのパス"` を使います。対象がわからない場合は、検査を無効にせず開発担当者に確認してください。

検査は別名のファイルや、Git の除外設定を無視して強制追加したファイルも対象にします。ただし、検査を無効化すると働かず、すべての秘密情報や個人情報を識別できるものでもありません。**入力データをプログラムの外に置くことが基本で、自動検査は誤操作への追加対策です。** 検査対象と限界は [SPEC §12.1](SPEC.md#121-誤公開防止) を参照してください。

## 作業する人へ

[AGENTS.md](AGENTS.md) を読んでから始める。仕様の変え方もそこに書いてある。

## ライセンス

[MIT](LICENSE)

## 謝辞

照会先の一つとして [LeakCheck](https://leakcheck.io) の Public API を使う。
