# pasori

PaSoRi リーダーで NFC カードと通信する Rust ライブラリ。`pasori` crate がカードのプロトコルを担い、下位の `rcs956` crate が RC-S956 チップの制御を担う。OS と USB backend への接続は利用側が `rcs956` の `Transport` として実装する。責務の境界、利用条件、検証手順は [DEVELOPMENT.md](DEVELOPMENT.md) を参照する。
