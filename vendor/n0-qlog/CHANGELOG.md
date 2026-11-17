# Changelog

All notable changes to iroh will be documented in this file.

## [0.2.0](https://github.com/n0-computer/iroh/compare/v0.1.1..0.2.0) - 2026-06-11

### ⛰️  Features

- [**breaking**] Merge upstream changes ([#16](https://github.com/n0-computer/iroh/issues/16)) - ([ad86431](https://github.com/n0-computer/iroh/commit/ad864314ec38849b648fe5a1ca913caeaaa24c85))

## [0.1.1](https://github.com/n0-computer/iroh/compare/v0.1.0..v0.1.1) - 2026-05-07

### ⚙️ Miscellaneous Tasks

- Update to edition 2024, bump MSRV to 1.88, update deps ([#15](https://github.com/n0-computer/iroh/issues/15)) - ([842ba84](https://github.com/n0-computer/iroh/commit/842ba847c2eb5f84b6bd0eded8f2d009b3b0c19f))
- Prepare 0.1.1 release - ([b280178](https://github.com/n0-computer/iroh/commit/b280178a8cb330edc6f0136f19dbaa008eff7595))

## [0.1.0](https://github.com/n0-computer/iroh/compare/tokio-quiche-0.12.0..v0.1.0) - 2025-12-05

### ⛰️  Features

- Ci ([#3](https://github.com/n0-computer/iroh/issues/3)) - ([453910f](https://github.com/n0-computer/iroh/commit/453910fe26f4fc4d7cb5798f1c2f2e6cd015844a))
- [**breaking**] Add support for quic-multipath extension ([#2](https://github.com/n0-computer/iroh/issues/2)) - ([230604e](https://github.com/n0-computer/iroh/commit/230604e8719eacc4eb0fda32886cd3c1eabb5f5e))
- [**breaking**] Add support for ack-frequency extension ([#7](https://github.com/n0-computer/iroh/issues/7)) - ([fe08b52](https://github.com/n0-computer/iroh/commit/fe08b526c3446803b08803c04df52ba6d6b83917))
- [**breaking**] Add support for quic-address-discovery extension ([#6](https://github.com/n0-computer/iroh/issues/6)) - ([74ec1a4](https://github.com/n0-computer/iroh/commit/74ec1a473822074ae1e6e3f8ec6f1e7d12a1c8f4))
- [**breaking**] Add support for quic-nat-traversal extension (iroh version) ([#8](https://github.com/n0-computer/iroh/issues/8)) - ([e5fe4c8](https://github.com/n0-computer/iroh/commit/e5fe4c81346e64a02f213a118f0e8660e59f5e50))
- Add Display derives for EventData and QuicFrame ([#10](https://github.com/n0-computer/iroh/issues/10)) - ([b706864](https://github.com/n0-computer/iroh/commit/b706864ff74adddf2eb632a60bb068751fa3a643))
- Add tuple field to Event ([#11](https://github.com/n0-computer/iroh/issues/11)) - ([e021c70](https://github.com/n0-computer/iroh/commit/e021c703ab92d5bf345efb1fc08d23793d294441))
- [**breaking**] Custom timers ([#12](https://github.com/n0-computer/iroh/issues/12)) - ([0d24ee5](https://github.com/n0-computer/iroh/commit/0d24ee5aae527c6659e7a19be63089ec06487660))

### 🐛 Bug Fixes

- CI - ([a2549b3](https://github.com/n0-computer/iroh/commit/a2549b3c5411c31191a0e9e064984185d09515fb))

### 🚜 Refactor

- Prepare fork - ([0fca654](https://github.com/n0-computer/iroh/commit/0fca6545fb5302c44ab54243616e4e53a7e8b504))
- Update to qlog-13 and qlog-quic-12 ([#1](https://github.com/n0-computer/iroh/issues/1)) - ([d3a90fc](https://github.com/n0-computer/iroh/commit/d3a90fcb4a6725da77a7f5494766f97e0f46f3ca))

### 📚 Documentation

- Add note about fork - ([cf28d11](https://github.com/n0-computer/iroh/commit/cf28d116adc14568891771e6afe33a2ad1da40dc))

### ⚙️ Miscellaneous Tasks

- *(deps)* Bump actions/checkout in the github-actions group ([#5](https://github.com/n0-computer/iroh/issues/5)) - ([f7b2566](https://github.com/n0-computer/iroh/commit/f7b2566bcb63036a73719d4ea9adc3b4c41e21f8))
- Disable fmt, make codespell green - ([cb99240](https://github.com/n0-computer/iroh/commit/cb992405caa7207217f28ab4894dd88489c3f679))
- Use upstream rustfmt - ([565c16b](https://github.com/n0-computer/iroh/commit/565c16bde3c30779d1d51dfac1a5e9c2d66dac24))
- Add rustfmt.toml - ([b9e31f6](https://github.com/n0-computer/iroh/commit/b9e31f6e256312a8684eea1fa01fef3216f0cd7d))
- Prepare 0.1.0 release ([#13](https://github.com/n0-computer/iroh/issues/13)) - ([1db260e](https://github.com/n0-computer/iroh/commit/1db260eff526a727da20ff2f7e7aa8c4fb74caa9))

## [tokio-quiche-0.12.0](https://github.com/n0-computer/iroh/compare/tokio-quiche-0.9.0..tokio-quiche-0.12.0) - 2025-11-03

### Cargo.toml

- Fix `readme` field and re-order - ([0cacdfd](https://github.com/n0-computer/iroh/commit/0cacdfd8f709c604c6ab2b3567eefd3d655610b1))

## [tokio-quiche-0.9.0](https://github.com/n0-computer/iroh/compare/tokio-quiche-0.3.1..tokio-quiche-0.9.0) - 2025-04-08

### Qlog

- Release 0.15.2 - ([57f2b5e](https://github.com/n0-computer/iroh/commit/57f2b5ecf6c29177ee04cb0a082159ada097a3be))

## [tokio-quiche-0.3.0](https://github.com/n0-computer/iroh/compare/tokio-quiche-0.1.0..tokio-quiche-0.3.0) - 2025-03-26

### 🐛 Bug Fixes

- Derive an additional `default` - ([3663dcf](https://github.com/n0-computer/iroh/commit/3663dcfcb2ed2f51d777361f66bdee5b744c2725))

### Qlog

- Add Clone and Debug for qlog::reader::Event - ([a1b6c70](https://github.com/n0-computer/iroh/commit/a1b6c7076343584d52e131b0cd45d17246caf210))
- Release 0.15.1 - ([fc94514](https://github.com/n0-computer/iroh/commit/fc945140d7d956f2ddee86284c37a41e37067721))

## [tokio-quiche-0.1.0](https://github.com/n0-computer/iroh/compare/qlog-0.15.0..tokio-quiche-0.1.0) - 2025-02-12

### ⚙️ Miscellaneous Tasks

- Derive `default` gor a bunch of types - ([33a4910](https://github.com/n0-computer/iroh/commit/33a49103d877c230e51fb83aae9f4e10b23da36e))
- Use qlog defaults inside quiche - ([2ad64e3](https://github.com/n0-computer/iroh/commit/2ad64e325ae1bdc2eba0e4badffb8df4ffa52d01))

### Cargo

- Unify some metadata across workspace - ([447f750](https://github.com/n0-computer/iroh/commit/447f7501b5198a3b0dc8e82ee82345ca4f6c5471))
- Move some more deps to workspace and reformat - ([caedfa8](https://github.com/n0-computer/iroh/commit/caedfa81b3f2a5ab03108fa6d949810c3f9c79f0))

## [qlog-0.15.0](https://github.com/n0-computer/iroh/compare/qlog-0.14.0..qlog-0.15.0) - 2025-01-24

### Qlog

- Release 0.15.0 - ([a0936fc](https://github.com/n0-computer/iroh/commit/a0936fc1271c2f6db40e41d7743541da8b60c9cd))

## [qlog-0.14.0](https://github.com/n0-computer/iroh/compare/qlog-0.13.0..qlog-0.14.0) - 2025-01-07

### ⚙️ Miscellaneous Tasks

- Add explicit lifetime parameter to QlogSeqReader - ([cbff9ae](https://github.com/n0-computer/iroh/commit/cbff9ae59d60a0c276b07dd8f9992a92700a1b8d))
- Add optional pretty-printing for JSON-SEQ streaming - ([54680b9](https://github.com/n0-computer/iroh/commit/54680b9ef13081940a58414fe0dd4eec7739e683))

### H3i/quiche/qlog/octets

- Fix clippy warnings - ([b13fe2c](https://github.com/n0-computer/iroh/commit/b13fe2c0187e04debd643bc4445bf92e21ea10c4))

### Qlog

- Bump to 0.14 - ([e0d59b4](https://github.com/n0-computer/iroh/commit/e0d59b4861ab20100d8ed8adad5f2ddb522de471))

## [qlog-0.13.0](https://github.com/n0-computer/iroh/compare/qlog-0.12.0..qlog-0.13.0) - 2024-04-15

### Lib

- Add qlogging of connection close - ([4e56c45](https://github.com/n0-computer/iroh/commit/4e56c455a08fb697eb7d557e8e7bc4e2b3c1eb99))

### Qlog

- Add length and payload_length fields to QUCI frames - ([88b075f](https://github.com/n0-computer/iroh/commit/88b075f35c812ec177ebfe68f44ed35f3984ebd2))
- Bump to 0.13 - ([0e90b8a](https://github.com/n0-computer/iroh/commit/0e90b8a115cf4eb971e4355fd354985b976ef1b4))

## [qlog-0.12.0](https://github.com/n0-computer/iroh/compare/qlog-0.11.0..qlog-0.12.0) - 2024-02-02

### Qlog

- Disable unused features from serde_with - ([66f2e26](https://github.com/n0-computer/iroh/commit/66f2e268552582f35118fde9ce58abd61c42929c))
- Add stream_type_value for unknown streams ([#1718](https://github.com/n0-computer/iroh/issues/1718)) - ([e2c31e7](https://github.com/n0-computer/iroh/commit/e2c31e70743253931d6a7e63ef8ce80ecf2e2a47))
- Bump to 0.12.0 - ([ffbde3d](https://github.com/n0-computer/iroh/commit/ffbde3db7300d9e880f99f941f6538a4234640f3))

## [qlog-0.11.0](https://github.com/n0-computer/iroh/compare/qlog-0.10.0..qlog-0.11.0) - 2024-01-09

### ⛰️  Features

- *(qlog)* Extend `From<EventType> for EventImportance` ([#1684](https://github.com/n0-computer/iroh/issues/1684)) - ([a9b900c](https://github.com/n0-computer/iroh/commit/a9b900cd914e50c4630ec9feb13b75006b001857))

### 🐛 Bug Fixes

- *(qlog)* Update serde rename of PacketsAcked ([#1682](https://github.com/n0-computer/iroh/issues/1682)) - ([28426be](https://github.com/n0-computer/iroh/commit/28426be6238553c762b4b60024033296e67a3bfd))

### ⚙️ Miscellaneous Tasks

- Extend serializer to support arbitrary types of event ([#1675](https://github.com/n0-computer/iroh/issues/1675)) - ([15ee833](https://github.com/n0-computer/iroh/commit/15ee833ed71c604c801180747ed5476cd9dc5322))

### Qlog

- Add MtuUpdated event missing from EventImportance implementation - ([5704d2a](https://github.com/n0-computer/iroh/commit/5704d2abbd4842a83d03b1c4ea1bbd201bb4e63d))
- Add QlogSeqReader helper ([#1672](https://github.com/n0-computer/iroh/issues/1672)) - ([a990eae](https://github.com/n0-computer/iroh/commit/a990eaec76a904eff9eff07c773dd32960dc175e))
- Add ex_data to Event ([#1692](https://github.com/n0-computer/iroh/issues/1692)) - ([a8ed21b](https://github.com/n0-computer/iroh/commit/a8ed21b8de1182faece1277fcb78329824d2bafa))
- Support reading JsonEvent too - ([5fd257c](https://github.com/n0-computer/iroh/commit/5fd257ccdb77a73818c9d0f336443122fba99c45))
- Release qlog 0.11 - ([bab9509](https://github.com/n0-computer/iroh/commit/bab95094650df93aa8996c751e4b5c62c93b9863))

## [qlog-0.10.0](https://github.com/n0-computer/iroh/compare/qlog-0.9.0..qlog-0.10.0) - 2023-11-10

### ⚙️ Miscellaneous Tasks

- *(deps)* Update serde_with requirement from 2.3.1 to 3.0.0 ([#1497](https://github.com/n0-computer/iroh/issues/1497)) - ([b75fb55](https://github.com/n0-computer/iroh/commit/b75fb5586a7ae945f8c6d96aef31ee1a23a174fe))

### Qlog

- Bump serde_with to 2.3.1 - ([6e5a244](https://github.com/n0-computer/iroh/commit/6e5a244ccc44ad95a995bb96163d4cd397f89da8))
- Packet number is optional - ([f55288f](https://github.com/n0-computer/iroh/commit/f55288fcbd95c039672da7de247e92f148e1ba13))
- Add MTUUpdated event - ([959c6a8](https://github.com/n0-computer/iroh/commit/959c6a8a41815227cfb3f929429b52dea49d3350))
- Fixup MTUUpdated event types serialization/parsing - ([036942b](https://github.com/n0-computer/iroh/commit/036942b541457252012f746143ce6adc679bff9a))
- Release 0.10 - ([dae5243](https://github.com/n0-computer/iroh/commit/dae5243f96b335ee3dfdbbc819028d02072e04d8))

## [qlog-0.9.0](https://github.com/n0-computer/iroh/compare/qlog-0.8.0..qlog-0.9.0) - 2023-03-30

### Qlog

- Add send_at_time to PacketSent event - ([c745eb8](https://github.com/n0-computer/iroh/commit/c745eb87ed53fd87d8b8ec8edb4bc5753a27fe3b))
- Add event for acked and dropped stream data - ([be55300](https://github.com/n0-computer/iroh/commit/be553005146ced5ce8b33d7ead598ca3dd3d9dfd))
- Align reference_time field with qlog spec ([#1392](https://github.com/n0-computer/iroh/issues/1392)) - ([e3d6fdd](https://github.com/n0-computer/iroh/commit/e3d6fdd8e9224d839428e5054ee3ce425d868583))
- Fix derivable_impls clippy warning - ([7e987b1](https://github.com/n0-computer/iroh/commit/7e987b13f41901d03d1958b7a1a13caf43adce69))
- Key_retired -> key_discarded - ([c7612f5](https://github.com/n0-computer/iroh/commit/c7612f557abac14526629c855c48b87af6a2d8f4))
- Update HTTP/3 settings fields - ([b0b2326](https://github.com/n0-computer/iroh/commit/b0b232685558e5c9e43ffe833598f5a18f8c2400))
- Update the H3StreamTypeSet event - ([f2ff435](https://github.com/n0-computer/iroh/commit/f2ff435cb612dc5acec38c5b9a804247e4acc6c1))
- Switch to RawInfo where needed - ([54c1ac8](https://github.com/n0-computer/iroh/commit/54c1ac863f5a2faa57dcf12e016a221c14d332eb))
- Update the packet dropped event - ([e6a3da3](https://github.com/n0-computer/iroh/commit/e6a3da36a6b570859e53a23c80ebd20d93bb4267))
- Update TransportError - ([d561429](https://github.com/n0-computer/iroh/commit/d5614291c2e04264816bc98a01b74e9c1f36d0aa))
- Release 0.9 - ([d4945b2](https://github.com/n0-computer/iroh/commit/d4945b253c37156f8118056d7014e4d445fe487e))

## [qlog-0.8.0](https://github.com/n0-computer/iroh/compare/qlog-0.7.0..qlog-0.8.0) - 2022-08-22

### Qlog

- Support new StatelessResetToken type - ([d38bbda](https://github.com/n0-computer/iroh/commit/d38bbda49666452d9131d83677d00cdea25306a4))

## [qlog-0.7.0](https://github.com/n0-computer/iroh/compare/qlog-0.6.0..qlog-0.7.0) - 2022-05-23

### ⚙️ Miscellaneous Tasks

- Make all streamer event additions atomic - ([29fee03](https://github.com/n0-computer/iroh/commit/29fee0375bcab94bee2fffa43ccef200fc7575c1))
- Align to draft-ietf-quic-qlog-quic-events-01 - ([3e67581](https://github.com/n0-computer/iroh/commit/3e67581648ea62a9594a8af41bfea5115d4cc9c8))

### Qlog

- Update HTTP/3 event definitions - ([86bc353](https://github.com/n0-computer/iroh/commit/86bc353ac56809e06605d97ff21e3a5446fc03c4))
- Add add_event_data_now() method and tidy up docs - ([77b1fac](https://github.com/n0-computer/iroh/commit/77b1face25deb86b1dd96bf0a29f55012db9ba24))
- Release 0.7 - ([1297fec](https://github.com/n0-computer/iroh/commit/1297feceedb9fc5fb17bf83d252e41d05791bbb5))

## [qlog-0.6.0](https://github.com/n0-computer/iroh/compare/0.10.0..qlog-0.6.0) - 2022-01-25

### Qlog

- Fmt - ([f6e9c22](https://github.com/n0-computer/iroh/commit/f6e9c22f91cb6c968892d347fe3af5ded2a16239))
- Support for JSON-SEQ serialization format - ([52c550c](https://github.com/n0-computer/iroh/commit/52c550cb2005f8800ccb847e61689ee9ef817031))
- Minimise temporary allocations - ([f49573c](https://github.com/n0-computer/iroh/commit/f49573c9db0fb802fabdabd02f58a16de4cd1d88))
- Update documents - ([2782f25](https://github.com/n0-computer/iroh/commit/2782f25b64fccdeb69527a73bf90f9a85cb627e4))
- Bump to 0.6.0 - ([f5b7633](https://github.com/n0-computer/iroh/commit/f5b7633053a09ebeb3aa730afde4e4b78dd9215e))


