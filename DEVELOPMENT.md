# Development

## crate の責務

依存は `pasori` から reader crate（`rcs956`、`rcs310`、`port100`、`port110`、`port400`）へ、それぞれから `felica-packet` と `iso14443` への一方向で、下位の crate は上位を知らない。reader crate 同士は依存しない。いずれも `no_std` と `alloc` で動作し、`unsafe_code` を禁止する。

`felica-packet` は reader によらない FeliCa カードの packet の事実を所有する。IDm、Polling の要求と応答、packet の長さ byte の検証と、Polling で選択したカードとの packet 交換の contract（`Selection`）がここに属する。各 reader crate は自分の選択 handle でこの contract を実装し、送受信可能な packet 上限、RF 転送・待機・失敗時の状態遷移を決める。

`iso14443` は reader によらない NFC-A と NFC-B の活性化の事実と、選択したカードとの交換の contract を所有する。SENS_RES・SEL_RES・UID・ATS、ATQB と ATTRIB 応答の検証、そこから決まる ISO-DEP の block parameter がここに属する。reader crate の選択 handle は、NFC-A の command frame を運ぶ `nfca::Selection` と、host が block protocol を実行するための `iso_dep::Selection` を実装する。NFC-A の passive target は `nfca::PassiveTarget` で initiator からの command と一度だけ応答する権限を渡す。

`rcs956` は RC-S956 チップの制御を所有する。フレーム、取引状態、firmware の RF 設定と timer、target の検出と活性化（InListPassiveTarget と TgInitTarget）、その応答の検証、firmware が実行するカード操作（NFC-A の ISO-DEP、MIFARE Classic の認証と block access、NFC-DEP）がここに属する。host が実行するプロトコルには、選択した target ごとの交換手段を渡す。FeliCa の packet 交換と packet stream、NFC-B の block 転送、Type 1 と Type A の command 交換、passive Type A target の受信と応答がそれにあたる。`4A` が返す target record は `iso14443` の活性化データへ変換する。crate が定義する `Transport` へ同期転送、pipe 回復、単調時計、待機を委譲し、期限・待機時間とエラー時の状態遷移は crate で決める。OS のデバイス列挙、USB backend、ドライバとの通信は `Transport` の実装側が所有する。

`rcs310` は RC-S310 と RC-S320 の制御を所有する。RC-S320 と同じ USB ID の RC-S600 もここで扱う。このリーダーは FeliCa だけを扱う。フレーム、取引状態、USB descriptor と register の観測による機種の判定、機種ごとの初期 register 値の書込み、RF field の切断、`5C` による FeliCa packet の運搬がここに属する。初期 register 値は Sony のドライバーパッケージが同じ観測に対して書く値で、値が分からない組合せは推測せずに拒否する。`Transport` の実装側は vendor control OUT 転送と interrupt IN 転送を受け持つ。

`port100` は RC-S380 などに載る Port-100 チップの制御を所有する。フレーム、取引状態、host ACK による command の中断、command 種別の選択、firmware の版で変わる技術ごとの RF 設定とプロトコル設定、InCommRF による frame の運搬がここに属する。initiator の設定値は Sony のドライバーパッケージが既定の registry で同じ版の firmware へ送る値で、古い firmware へ送らない項目も同じ判定で省く。initiator としては NFC-A の SENS_REQ、cascade ごとの衝突防止と選択、RATS、NFC-B の REQB と ATTRIB を crate が送り、NFC-A と NFC-B の選択は毎回 RF field を切ってから始める。複数のカードが同時に応答したときの衝突は失敗として返す。ISO-DEP を広告する NFC-A カードと NFC-B カードは block 転送を、それ以外の NFC-A カードは command 交換を受け取る。passive target としては firmware が NFC-A の選択と FeliCa の初回 Polling に応答し、後続の frame を TgCommRF で host に渡す。NFC-A の ISO-DEP target では応答を送るコマンドで次の受信を開始し、取得した frame を次の呼出しに渡す。`Transport` の実装側は bulk OUT 転送と bulk IN 転送を受け持つ。

`port110` は RC-S390 などの Port-110 リーダーを Bluetooth LE の GATT 経由で制御する。このリーダーは FeliCa だけを扱う。フレーム、20 bytes ごとの GATT 書込み、Indication で届く ACK と応答の受信、再同期、command 種別 3 の選択、BLE 接続パラメーターの要求、FeliCa の RF 設定とプロトコル設定、InCommRF による packet の運搬がここに属する。設定値は Sony のドライバーパッケージが送る値で、ドライバーが GetProperty と GetPDDataVersion の値で選ぶ機器には、RF 設定のたびに同じ RF 設定表の調整を行う。FeliCa の Polling は 212 kbps で行い、Request Code `02` でカードが対応を通知した場合は選択後の交換を 424 kbps で行う。`Transport` の実装側は接続、サービスの探索、Indication と Notification の購読、Write Request による書込みと Indication の受信を受け持つ。

`port400` は USB Port-400 リーダーの CCID Escape、Transparent Session と RF field の制御を所有する。対象は RC-S300/S・P と RC-S660/U。呼出側の `Transport` が USB descriptor から bulk endpoint を選び、デバイスを排他的に使う。FeliCa の Polling は 212 kbps で行い、Request Code `02` でカードが対応を通知した場合は、速度変更を確認してから選択後の交換を 424 kbps で行う。NFC-A はリーダーの Layer 3 選択に続いて RATS を送り、NFC-B は Layer 2 framing で REQB と ATTRIB を送る。活性化後の ISO-DEP block protocol は `pasori` が実行する。

`pasori` は host が実行するカードのプロトコルを所有する。FeliCa の command と認証、FALP、ISO-DEP の block protocol、NFC Forum Type 1〜4 の NDEF、読み取り専用の Type 2、Type 3、Type 4A tag の emulation がここに属する。FeliCa の command、認証、Type 3 の NDEF は任意の `felica_packet::Selection`、ISO-DEP は任意の `iso_dep::Selection`、Type 2 の NDEF は任意の `nfca::Selection` の上で動き、Type 4 の NDEF は ISO-DEP の APDU 交換を受け取る。RC-S956 の NFC-A カードの ISO-DEP は firmware が実行する。FALP と Type 1 の NDEF は `rcs956` の handle を使う。Type 2 tag は `nfca::PassiveTargetReader` から NFC-A target を取得し、Type 3 tag は `port100` の FeliCa target に NDEF の読み取り応答を返す。Type 4A tag は `port100` の NFC-A target で ISO-DEP のカード側 block protocol を実行し、活性化ごとに独立した NDEF ファイルの選択状態を持つ。`pasori` は `felica-packet`、`iso14443`、`rcs956`、`rcs310`、`port100`、`port110`、`port400` を再公開する。

`reader-script` は各 crate の wire-level test が共有する RC-S956、RC-S310、Port-100、Port-110、Port-400 の scripted transport で、公開しない dev dependency である。

## ビルドと検証

リポジトリのルートで実行する。`no_std` 検証にはベアメタル向け Rust target が必要。

```powershell
cargo build --workspace
cargo fmt --all --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps --all-features --config "build.rustdocflags=['-Dwarnings']"
cargo check -p felica-packet -p iso14443 -p rcs956 -p rcs310 -p port100 -p port110 -p port400 -p pasori --lib --all-features --target x86_64-unknown-none
```

## 状態と失敗の契約

各操作の詳細な条件は定義側の rustdoc が正本であり、ここでは workspace 全体に共通する契約だけを示す。

失敗した初期化を成功状態として公開しない。カード handle は reader の排他的 borrow を保持し、選択・raw 交換・認証の権限はその borrow と RF 状態より長く残らない。raw 交換や認証へ移ると typed handle は消費される。FeliCa Standard の有効な認証 session は Reset Mode の成功を検証して Mode0 の typed handle へ移れる。次の選択要求で消えないカード状態を残す操作は、送る前に選択 handle へ field cycle の必要を宣言する。次の選択はその宣言を受けて RF field を切ってから要求を送る。

カード操作全体は自動で再実行しない。FALP は順序番号で重複を排除できる欠落 block の再要求と、応答のない送信切替 block の再送を行う。ISO-DEP は block protocol の再送要求に応答し、同じ APDU を再処理しない。送信前の拒否や準備失敗と、送信後の失敗を区別し、送信後の失敗ではカードへの効果が不明になり得るため、確認済みの progress を error に残す。transport 失敗後には RF readiness が失効する。reader への `initialize` は明示的な再同期であり、失敗したカード操作の再実行や結果照合ではない。

`rcs956` の回復では pipe の状態整理と host ACK による未完了 command の中断を行い、その後は reset だけを許可する。USB pipe reset だけを firmware command の中断として扱わない。`port100` の回復では受信済み bytes を捨て、host ACK で未完了 command を中断し、もう一度受信済み bytes を捨ててから command を許可する。`port100` と `rcs310` の `Transport` は stall していない endpoint を回復で reset しない。該当機器は CLEAR_FEATURE(ENDPOINT_HALT) で data toggle を戻さないためである。中断前のカード操作の結果不明は caller に残る。

`port110` の回復では最大長のフレームと同じ長さのゼロ列と ACK を書き、2.8 秒間 Indication が届かなくなるまで受信値を捨ててから command を許可する。取引中は ACK 単独の値より前に届いた値を捨てる。

`port400` は CCID の最終応答を照合できなければ接続を失効させる。呼出側は同期が確立した接続から reader を作り直す。照合済みの機器応答が Transparent Session の順序エラーを示した場合は、`finish` または `initialize` でセッションを明示的に整理できる。

`rcs310` は ACK 後に `5C` が待ち切れた場合、カード選択を失効させる。次の選択は `54` の応答 `55 00` で RF 停止を確認し、受信済み bytes を破棄してから始める。応答を照合できず再同期できない場合は、同期を確立した接続から reader を作り直す。

`rf_off` や `finish` の失敗は caller が観測する。Drop は OS resource の解放だけを担当する。

NDEF の書込みはメッセージを非公開にしてから本文を更新し、最後に公開する。失敗はその段階と確認済み bytes 数を返すため、caller は再選択してタグの状態を確認してから回復操作を判断する。

## 検証境界

固定 packet vector はデバイスに送るフレームと応答の解釈を検証する。実機 capture は USB と RF の観測範囲を別途記録する。

NFC-A／B の固定 vector はカード実機の成功証拠ではない。`rcs310` の固定 vector は Sony のドライバーの静的解析と第三者実装の挙動から組み立てたもので、RC-S310 と RC-S320 の実機では FeliCa の Polling と packet 交換を確認している。`port100` の固定 vector は Sony のドライバーの静的解析と ISO/IEC 14443 の frame から組み立てたもので、RC-S380 の実機では FeliCa の Polling と packet 交換、NFC-A と NFC-B の活性化、ISO-DEP の block 交換を確認している。NFC-A の command 交換は CRC を host で検査し、InCommRF 応答の第 5 byte が 4 を示す 1 byte を 4-bit の ACK／NAK として受け取る。この byte をドライバーが 8 と比べることから最終 byte の有効 bit 数と推定したもので、実機の値は確認していない。`port110` の固定 vector は Sony のドライバーの静的解析から組み立てたもので、実機では確認していない。全 firmware、全カード command／APDU の意味と副作用の成立は、固定 vector の検証対象に含めない。

## 外部実装へ委譲する責務

`pasori` の `felica-lite-s`、`felica-standard-aes`、`felica-standard-des` は、ブロック暗号、AES-CMAC、DES-CBC を RustCrypto、MAC の比較を `subtle`、鍵用バッファの消去を `zeroize` に委譲する。カードごとの暗号フレーム、MAC の入力構成、認証状態は `pasori` が所有する。FeliCa Standard の公開コマンドは [Sony のカードユーザーズマニュアル抜粋版](https://www.sony.co.jp/Products/felica/business/tech-support/)、AES と DES の暗号化通信は [非公式版の相互認証・セキュアメッセージングの章](https://soltia48.github.io/felica-users-manual-unofficial/ja/) を参照する。カード鍵と認証ごとの CSPRNG challenge は呼出側が供給する。

`serde_json` は `rcs956` の固定 fixture の読取にだけ使う dev dependency で、通常の library へ入れない。JSON parser とその formatter／string 処理の依存、および Cargo target に基づく build script は test build の trust surface として扱う。
