# Development

## crate の責務

依存は `pasori` から reader crate（`rcs956`、`rcs310`、`port100`）へ、それぞれから `felica-packet` への一方向で、下位の crate は上位を知らない。reader crate 同士は依存しない。いずれも `no_std` と `alloc` で動作し、`unsafe_code` を禁止する。

`felica-packet` は reader によらない FeliCa カードの packet の事実を所有する。IDm、Polling の要求と応答、packet の長さ byte の検証と、Polling で選択したカードとの packet 交換の contract（`Selection`）がここに属する。各 reader crate は自分の選択 handle でこの contract を実装し、RF 転送・待機・失敗時の状態遷移は reader crate が決める。

`rcs956` は RC-S956 チップの制御を所有する。フレーム、取引状態、firmware の RF 設定と timer、target の検出と活性化（InListPassiveTarget と TgInitTarget）、その応答の検証、firmware が実行するカード操作（NFC-A の ISO-DEP、MIFARE Classic の認証と block access、NFC-DEP）がここに属する。host が実行するプロトコルには、選択した target ごとの交換手段を渡す。FeliCa の packet 交換と packet stream、NFC-B の block 転送、Type 1 と Type A の command 交換、passive Type A target の受信と応答がそれにあたる。crate が定義する `Transport` へ同期転送、pipe 回復、単調時計、待機を委譲し、期限・待機時間とエラー時の状態遷移は crate で決める。OS のデバイス列挙、USB backend、ドライバとの通信は `Transport` の実装側が所有する。

`rcs310` は RC-S310 と RC-S320 の制御を所有する。RC-S320 と同じ USB ID の RC-S600 もここで扱う。このリーダーは FeliCa だけを扱う。フレーム、取引状態、USB descriptor と register の観測による機種の判定、機種ごとの初期 register 値の書込み、RF field の切断、`5C` による FeliCa packet の運搬がここに属する。初期 register 値は Sony のドライバーパッケージが同じ観測に対して書く値で、値が分からない組合せは推測せずに拒否する。`Transport` の実装側は vendor control OUT 転送と interrupt IN 転送を受け持つ。

`port100` は RC-S380 などに載る Port-100 チップの制御を所有する。フレーム、取引状態、host ACK による command の中断、command 種別の選択、firmware の版で変わる FeliCa の RF 設定とプロトコル設定、InCommRF による FeliCa packet の運搬がここに属する。設定値は Sony のドライバーパッケージが同じ版の firmware へ送る値で、古い firmware へ送らない項目も同じ判定で省く。`Transport` の実装側は bulk OUT 転送と bulk IN 転送を受け持つ。

`pasori` は host が実行するカードのプロトコルを所有する。FeliCa の command と認証、FALP、NFC-B の ISO-DEP、NFC Forum Type 1〜4 の NDEF、Type 2 tag の emulation がここに属する。FeliCa の command、認証、Type 3 の NDEF は任意の `Selection` の上で動く。FALP は `rcs956` の packet stream を使い、それ以外の方式は `rcs956` の選択 handle を受け取る。`pasori` は `felica-packet`、`rcs956`、`rcs310`、`port100` を再公開する。

`reader-script` は各 crate の wire-level test が共有する RC-S956、RC-S310、Port-100 の scripted transport で、公開しない dev dependency である。

## ビルドと検証

リポジトリのルートで実行する。`no_std` 検証にはベアメタル向け Rust target が必要。

```powershell
cargo build --workspace
cargo fmt --all --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps --all-features --config "build.rustdocflags=['-Dwarnings']"
cargo check -p felica-packet -p rcs956 -p rcs310 -p port100 -p pasori --lib --all-features --target x86_64-unknown-none
```

## 状態と失敗の契約

各操作の詳細な条件は定義側の rustdoc が正本であり、ここでは workspace 全体に共通する契約だけを示す。

失敗した初期化を成功状態として公開しない。カード handle は reader の排他的 borrow を保持し、選択・raw 交換・認証の権限はその borrow と RF 状態より長く残らない。raw 交換や認証へ移ると typed handle は消費され、その前提は回復しない。次の選択要求で消えないカード状態を残す操作は、送る前に `rcs956` の選択 handle へ field cycle の必要を宣言する。次の選択はその宣言を受けて RF field を切ってから要求を送る。

どの操作も自動で再送しない。例外は FALP の再送で、protocol 自体が順序番号で重複を排除する欠落 block の再要求と、応答のない送信切替 block の再送だけを行う。送信前の拒否や準備失敗と、送信後の失敗を区別し、送信後の失敗ではカードへの効果が不明になり得るため、確認済みの progress を error に残す。transport 失敗後には RF readiness が失効する。reader への `initialize` は明示的な再同期であり、失敗したカード操作の再実行や結果照合ではない。

`rcs956` の回復では pipe の状態整理と host ACK による未完了 command の中断を行い、その後は reset だけを許可する。USB pipe reset だけを firmware command の中断として扱わない。`port100` の回復では pipe の状態整理と host ACK による未完了 command の中断を行い、受信済み bytes を捨ててから command を許可する。`rcs310` には command を中断する手段がなく、回復は pipe と受信済み bytes の整理だけを行う。いずれでも、中断前のカード操作の結果不明は caller に残る。

`rcs310` のリーダーは ACK の後に応答を返さないことがある。その取引は失敗として返すが stream は使える状態に残し、遅れて届く応答に備えて、次の取引は受信済み bytes を捨ててから送り、ACK より前の frame を拒否する。

`rf_off` や `finish` の失敗は caller が観測する。Drop は OS resource の解放だけを担当する。

NDEF の書込みはメッセージを非公開にしてから本文を更新し、最後に公開する。失敗はその段階と確認済み bytes 数を返すため、caller は再選択してタグの状態を確認してから回復操作を判断する。

## 検証境界

固定 packet vector はデバイスに送るフレームと応答の解釈を検証する。実機 capture は USB と RF の観測範囲を別途記録する。

NFC-A／B の固定 vector はカード実機の成功証拠ではない。`rcs310` の固定 vector は Sony のドライバーの静的解析と第三者実装の挙動から組み立てたもので、RC-S310／RC-S320 の実機では確認していない。`port100` の固定 vector は Sony のドライバーの静的解析から組み立てたもので、Port-100 の実機では確認していない。全 firmware、全カード command／APDU の意味と副作用の成立は、固定 vector の検証対象に含めない。

## 外部実装へ委譲する責務

`pasori` の `felica-lite-s` feature は 2-key TDES を `des`、MAC の比較を `subtle`、鍵用バッファの消去を `zeroize` に委譲し、Lite-S のプロトコル、MAC の入力構成、session 状態は crate が所有する。`felica-standard-aes` feature は AES と CMAC を RustCrypto へ委譲し、暗号フレームと取引番号は crate が所有する。フレーム形式の参照は [FeliCa Card User's Manual (Unofficial Edition)](https://soltia48.github.io/felica-users-manual-unofficial/en/) の Mutual Authentication and Secure Messaging Algorithms。どちらもカード鍵と認証ごとの CSPRNG challenge は呼出側が供給する。

`serde_json` は `rcs956` の固定 fixture の読取にだけ使う dev dependency で、通常の library へ入れない。JSON parser とその formatter／string 処理の依存、および Cargo target に基づく build script は test build の trust surface として扱う。
