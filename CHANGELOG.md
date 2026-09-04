# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning]. Being pre-1.0, breaking changes may land in a minor
release; they will always be listed here.

Entries record whether a change was verified on real hardware, because in this
project "implemented" and "seen to work on a device" are different claims.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- `Ncp::stack_version`, the NCP firmware's own version number from the
  negotiation exchange. It identifies the firmware build — `0x7440` for
  EmberZNet 7.4.4 — and firmware builds are what differ between reports. It was
  previously only visible in a debug log, which meant answering "which firmware
  was that?" required reproducing the connection.
- `Ncp::poll`, which reads for callbacks without issuing a command.
- `sendUnicast` (`0x0034`), with the `messageSentHandler` confirmation.
  **Hardware-confirmed:** a `genOnOff` command opened and closed a real water
  valve, and the delivery report's destination, APS sequence and tag all match
  the send that produced it.
- Project scaffolding for outside contributions: issue and pull request
  templates, a code of conduct, a security policy, and this changelog.
- `tests/extending_from_outside.rs`, which defines a command this crate does
  not implement from a *separate* crate and drives it through the runtime.
  `Command` is an ordinary public trait, so a user who needs a command nobody
  has needed yet can write it in their own crate rather than forking or waiting
  for a release — and because that test is an integration test, it can only
  reach what a real dependent can reach. If the public API ever loses a piece
  needed for this, it stops compiling.
- Usage and extensibility examples in the crate documentation and the README,
  both compiled as doctests.
- A `cargo package` job in CI, which builds the crate from only the files that
  would be published. It catches an `exclude` entry that drops something the
  build needs — invisible locally, because the file is still on disk.

### Fixed

- **`incomingMessageHandler` decoded its payload from the wrong offset.** Seven
  bytes of radio metadata sit between the APS header and the application
  payload — LQI, RSSI, the sender's short address, a binding index, an address
  index and a length prefix — and all seven were being prepended to the ZCL
  message. Nothing failed: the frame parsed, the payload was non-empty, and its
  first byte was a plausible ZCL frame control value.
- **`messageSentHandler` decoded every field from the wrong offset.** It
  started eleven bytes early, reading the message type as the tag and the low
  byte of the destination address as the status. With a destination of `0x3a41`
  a delivered message was reported as failure status `0x41`.
- Payloads are now taken through their length prefix rather than as the rest of
  the frame, which also drops the source-route-overhead byte some firmware
  appends instead of folding it into the application message.
- A callback arriving with no command outstanding is parsed with the extended
  header rather than whatever format the previous command used.
- A broken documentation link to zigbee-herdsman in the crate root.

### Notes

Both decoder bugs had passing unit tests. The tests asserted against bytes
assembled from the same wrong belief as the decoder, so they confirmed the bug
rather than catching it. Only a real device found them. The captures are now in
`tests/hardware_regression.rs`, and the replacement unit tests assert on
offsets.

## [0.1.0] — unreleased

Initial implementation. Not yet published to crates.io.

- ASH: framing, byte stuffing, CRC-16/CCITT, data randomisation, ACK, NAK,
  retransmission with a bounded window, the reset handshake, duplicate
  suppression, sequence rollover, and recovery after a corrupt frame.
- EZSP: both header formats, version-aware field widths, response and callback
  correlation, and nine commands.
- EZSP versions 13 through 19.
- Four fuzz targets, built and smoke-run in CI.
- Hardware-confirmed on a Sonoff ZBDongle-E (EFR32MG21), EmberZNet 7.4.4,
  EZSP 13: coordinator bringup, a real device joining, and commissioning.

[Unreleased]: https://github.com/deatherving/rsezsp/compare/main...HEAD
[0.1.0]: https://github.com/deatherving/rsezsp/releases/tag/v0.1.0
