# pasori

PaSoRi リーダーで NFC カードと通信する Rust ライブラリ。`pasori` crate がカードのプロトコルを担い、下位の reader crate がリーダーの制御を担う。`rcs956` は RC-S956 チップのリーダー、`rcs310` は FeliCa 専用の RC-S310 と RC-S320 を扱う。OS と USB backend への接続は利用側が各 reader crate の `Transport` として実装する。責務の境界、利用条件、検証手順は [DEVELOPMENT.md](DEVELOPMENT.md) を参照する。
