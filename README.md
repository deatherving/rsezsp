# rsezsp

[![CI](https://github.com/deatherving/rsezsp/actions/workflows/ci.yml/badge.svg)](https://github.com/deatherving/rsezsp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.90+](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)

**rsezsp is a hardware-driven Rust implementation of Silicon Labs EZSP for Ember NCP devices.**

The project intentionally implements EZSP incrementally. Command coverage is
based on real hardware and application requirements rather than protocol
completeness.

```text
Application / Zigbee runtime
        │
   typed EZSP API              ezsp::command, ezsp::callback
        │
EZSP codec + correlation       ezsp::codec, ezsp::frame, ezsp::correlation
        │
   ASH transport               ash::
        │
       serial                  transport::
        │
 Silicon Labs Ember NCP
```

This crate owns the host-to-NCP conversation and nothing above it. No ZCL, no
ZDO interview logic, no device definitions, no MQTT.

**It is a driver.** It carries EZSP frames and has no opinion about Zigbee. The
distinction is not which layer of the stack a name comes from — it is who
decides. An APS header is part of the frame this crate encodes, so `ApsFrame`
belongs here; what goes *inside* that payload does not, and neither does the
choice of when to send one. Nothing here should have an opinion about a device.

## Using it

```toml
[dependencies]
rsezsp = "0.1"
```

```rust
use rsezsp::Ncp;
use rsezsp::ezsp::command::GetEui64;
use rsezsp::transport::serial::{SerialSettings, SerialTransport};

let transport = SerialTransport::open("/dev/ttyUSB0", SerialSettings::default())?;
let mut ncp = Ncp::connect(transport).await?;

println!("EZSP {}, firmware {:#06x}", ncp.version(), ncp.stack_version());

let response = ncp.command(GetEui64).await?;
println!("coordinator {}", response.eui64);
```

`Ncp::connect` does the ASH reset handshake and EZSP version negotiation, and
from then on every field width follows the negotiated version. Callbacks arrive
out of band — `ncp.poll(timeout)` reads them without issuing a command.

Try it against your own dongle:

```bash
cargo run --example startup -- /dev/ttyUSB0
```

That runs coordinator bringup and prints a pass/fail line per step. Add
`--permit-join` to open the network, and `--onoff <nwk> on|off` to command a
device that joined.

The codecs are sans-I/O and the runtime is optional. If you have your own I/O
story, `default-features = false` drops tokio entirely and leaves the ASH and
EZSP codecs, which are pure functions over bytes.

## Adding a command this crate does not have

Command coverage grows from real need rather than from working through the
specification, so at any moment there are commands nobody has needed yet. That
is only a reasonable design if it does not block you — so `Command` is an
ordinary public trait, not a sealed one. You can implement it **in your own
crate**, for a command this one has never heard of, and send it today:

```rust
/// `setRadioPower` — frame id 0x0099.
struct SetRadioPower { dbm: i8 }

impl EzspEncode for SetRadioPower {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u8(self.dbm as u8);
        Ok(())
    }
}

impl EzspDecode for SetRadioPowerResponse {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        // Applies the version boundary for you: a status is one byte below
        // EZSP 14 and four at or above it.
        Ok(Self { status: SlStatus::decode(input)? })
    }
}

impl Command for SetRadioPower {
    type Response = SetRadioPowerResponse;
    const ID: FrameId = FrameId(0x0099);
}
```

`tests/extending_from_outside.rs` is a worked example that proves this: it
defines `getChildData`, a command this crate does not implement, from a
separate crate, and drives it through the whole runtime. It is an integration
test precisely so it can only reach what a real dependent can reach — if the
public API ever loses a piece needed for this, that test stops compiling.

If you write one worth sharing, please send it back. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Status

Milestones 1 and 2 are confirmed on real hardware:

| step | result |
|---|---|
| serial open | **PASS** |
| ASH reset handshake | **PASS** |
| EZSP version negotiation | **PASS** (v13) |
| `getEui64` | **PASS** — `0x94a081fffed96e5c` |
| `addEndpoint` | **PASS** |
| `setConfigurationValue` | **PASS** |
| `setPolicy` | **PASS** — joins and unsecured rejoins allowed |
| `networkInit` (resume) | **PASS** — resumed the stored network |
| `stackStatusHandler` callback | **PASS** — decoded as a callback, not a response |
| `importTransientKey` | **PASS** |
| `permitJoining` | **PASS** — 240s window |
| **a real device joined** | **PASS** — `trustCenterJoin` for `0xa4c138142d62ffff` |
| `sendUnicast` | **PASS** — accepted, APS sequence returned |
| `messageSentHandler` callback | **PASS** — delivered, tag and destination match the send |
| **the device physically actuated** | **PASS** — a `genOnOff` command opened and closed a real water valve |

Coordinator bringup passes **8/8**; with `--permit-join` a real device joins
and its `trustCenterJoin` callback decodes; with `--onoff` a command reaches
that device and the delivery confirmation decodes: **10/10**. Not yet attempted
on hardware: recovery across a host restart. See
[Hardware validation](#hardware-validation).

## It drives a real Zigbee stack

[`rszigbee`](https://github.com/deatherving/rszigbee) uses this crate as its
EZSP transport, having replaced its previous one. On the same dongle it brings
a coordinator up, resumes a stored network, admits a device, interviews it over
ZDO, resolves it against a device definition, binds, configures reporting, and
controls it — a `genOnOff` command through this crate opens and closes a real
water valve.

That matters more than any test count: the command set here is the set a
working Zigbee coordinator actually needs, and it is that because a working
Zigbee coordinator needed it.

## Two properties the design is built around

**The protocol version is part of the wire format.** Field widths change
between EZSP versions, so the negotiated version is threaded through every
codec rather than stored once and consulted ad hoc:

| field | below EZSP 14 | 14 and above |
|---|---|---|
| a status value | `u8` (`EmberStatus`) | `u32` (`sl_status_t`) |
| `sendUnicast` message tag | `u8` | `u16` |
| `importTransientKey` flags | present | absent |

A status is the first field of most responses, so the wrong width shifts
everything after it: the frame still parses and every value is plausible and
wrong. Boundaries are named predicates — `version.has_wide_status()` — not
`if version >= 14` repeated across the codebase.

**Parsing is sans-I/O.** Bytes in, typed values out, no runtime involved. That
is what makes the parsers deterministic to test, cheap to fuzz, and able to
replay a captured wire trace as a regression test. `cargo build
--no-default-features` drops the runtime entirely, and CI builds that way to
keep it true.

## Implemented

### Commands

| command | id | hardware |
|---|---|---|
| `version` | `0x0000` | confirmed |
| `addEndpoint` | `0x0002` | confirmed |
| `networkInit` | `0x0017` | confirmed |
| `getEui64` | `0x0026` | confirmed |
| `permitJoining` | `0x0022` | confirmed |
| `setManufacturerCode` | `0x0015` | confirmed |
| `formNetwork` | `0x001e` | not yet |
| `getNetworkParameters` | `0x0028` | confirmed |
| `networkState` | `0x0018` | confirmed |
| `sendUnicast` | `0x0034` | confirmed |
| `sendBroadcast` | `0x0036` | not yet |
| `sendMulticast` | `0x0038` | not yet |
| `getConfigurationValue` | `0x0052` | confirmed |
| `setInitialSecurityState` | `0x0068` | not yet |
| `clearTransientLinkKeys` | `0x006b` | confirmed |
| `getValue` | `0x00aa` | confirmed |
| `exportKey` | `0x0114` | confirmed |
| `getNetworkKeyInfo` | `0x0116` | confirmed |
| `setConfigurationValue` | `0x0053` | confirmed |
| `setPolicy` | `0x0055` | confirmed |
| `importTransientKey` | `0x0111` | confirmed |

### Callbacks

`stackStatusHandler`, `trustCenterJoinHandler`, `incomingMessageHandler` and
`messageSentHandler`, all confirmed on hardware. A callback this build does not
decode is carried through as `Callback::Unknown` with its bytes intact rather
than guessed at.

### ASH

Framing, byte stuffing, CRC-16/CCITT, data randomisation, ACK, NAK,
retransmission with a bounded window, the reset handshake, duplicate
suppression, sequence rollover, and recovery after a corrupt frame.

### EZSP versions

13 through 19. Below 13 every command was framed differently, and claiming
support without a device to test against would be a guess presented as a
feature.

## Six bugs real hardware found

Unit tests and fuzzing did not find any of these. Each is now a permanent
regression test in `tests/hardware_regression.rs`.

**Version negotiation takes two exchanges.** The host offers a version and the
NCP answers with the one it runs. If they differ, the host must send `version`
*again carrying the NCP's version*, and only then is negotiation complete. A
single exchange looks entirely successful — the NCP replies, nothing errors —
and then the very next command comes back `INVALID_COMMAND` with
`ERROR_VERSION_NOT_SET`.

**The header format belongs to the connection, not the command.** The legacy
three-byte header may be used exactly once, for the bootstrap `version`. It
first appeared natural to make that a property of the command; doing so sent a
second `version` in the legacy format, which is a different bug with the same
symptom.

**`networkInit` needs the stack profile set first.** It returned
`EMBER_NOT_JOINED` on a dongle that demonstrably had a stored network. This NCP
defaults `STACK_PROFILE` to `0`, and the stack will not adopt a stored ZigBee
Pro network until it is `2`. Found by running a known-good implementation
against the same dongle seconds later and comparing.

**Two callbacks were decoded from the wrong offsets, and both looked fine.**
`incomingMessageHandler` carries seven bytes of radio metadata between the APS
header and the application payload — LQI, RSSI, the sender, two table indices
and a length prefix. The decoder took everything after the APS header as the
payload, so all seven were handed to the caller as the start of the ZCL
message. Nothing failed: the frame parsed, the payload was non-empty, and its
first byte was a plausible ZCL frame control value. It was caught only because
the sender's address, `0x3a41`, was legible in the middle of a payload hex
dump.

`messageSentHandler` was worse. Its decoder started at the message tag, eleven
bytes early, so it read the message *type* as the tag and the low byte of the
destination address as the status. The destination was `0x3a41`, so a
successfully delivered message was reported as failure status `0x41` — and the
example dutifully printed "not delivered".

Both had unit tests, and both tests passed, because the tests asserted against
bytes assembled from the same wrong belief as the decoder. That is the specific
failure `CONTRIBUTING.md` warns about, and writing it there did not stop it
happening; only the device did.

**Frame logging published key material.** Every EZSP frame is logged at debug
level, because a wire trace is the most useful thing a bug report can carry —
and `CONTRIBUTING.md` asks reporters for exactly that. For four frames the
payload *is* the secret: an `exportKey` response is sixteen bytes of network
key, and `importTransientKey` and `setInitialSecurityState` carry keys
outbound. Filing a bug report would have published the reporter's network key.

Found by reading the code rather than by running it, which is worth saying: the
key types redact in `Debug` and always had, so every test of *that* passed. The
leak was one layer below, in the raw bytes, before anything had been decoded
into a type that could redact itself.

## Security

The threat model is untrusted input from the NCP. A Zigbee coordinator is
reachable over the air by anything in radio range, and a malformed payload
relayed by a device reaches these decoders.

- **No `unsafe`**, forbidden at the crate level.
- **No panics on NCP input.** No slice indexing, no `unwrap`, no arithmetic
  that can wrap; the lints enforce it and relax only inside tests. A malformed
  frame is a typed error.
- **Key material is redacted** in `Debug`, in `Display`, and in frame logging,
  with tests pinning all three.
- **Bounded reads.** Length prefixes are checked against what is actually
  present rather than trusted.

Fuzzing is part of the build rather than an occasional exercise. See
[SECURITY.md](SECURITY.md) for what counts as a security issue and how to
report one.

## Verification

| | |
|---|---|
| unit and integration tests | **132** (including 2 doctests) |
| fuzz targets | 4 |
| fuzz executions to date | ~89.2M, no crashes |
| hardware-confirmed paths | bringup end to end, a real device join, and a command that actuated it |

Fuzzing is part of the build rather than an occasional exercise. CI compiles
every target and runs a 30-second smoke campaign on each; long campaigns are a
separate, deliberate activity. Any crashing input worth keeping goes into
`tests/hardware_regression.rs`, where it runs on stable forever instead of only
during a campaign.

```bash
./scripts/verify.sh              # everything CI runs, in CI's order
cargo +nightly fuzz run ash_frame_decode -- -max_total_time=300
```

## Hardware validation

Tested against a **Sonoff ZBDongle-E** (EFR32MG21), EmberZNet **7.4.4**, EZSP
**13**, stack version `0x7440`, at 115200 baud with hardware flow control off.

Flow control is not a preference here: opening a tty with RTS/CTS enabled
blocks in `open(2)` until CTS is asserted, and on a dongle that does not wire
those lines that is an uninterruptible hang — a timeout cannot interrupt a
blocking syscall.

| path | unit | fuzz | hardware |
|---|---|---|---|
| ASH framing, CRC, randomisation | yes | yes | yes |
| ASH reset handshake | yes | — | yes |
| ASH retransmission, window, rollover | yes | — | not yet |
| EZSP header, both formats | yes | yes | yes |
| version negotiation | yes | — | yes |
| response/callback correlation | yes | — | yes |
| `getEui64`, `networkInit`, `setConfigurationValue` | yes | yes | yes |
| `addEndpoint`, `setPolicy` | yes | yes | yes |
| `permitJoining`, `importTransientKey` | yes | yes | yes |
| `sendUnicast` | yes | yes | yes |
| `sendBroadcast`, `sendMulticast` | yes | yes | **not yet** |
| callback decoding, all four | yes | yes | yes |
| device join, commissioning | yes | — | yes |
| a command reaching a device | yes | — | yes |
| network parameters, key export | yes | yes | yes |
| forming a network | yes | — | **not yet** |
| key material kept out of logs | yes | — | yes |
| recovery across a host restart | — | — | **not yet** |

A row is only marked hardware-confirmed if it ran against the dongle. "The
tests pass" is not the same claim.

## Protocol references

Silicon Labs' EZSP documentation is the authority. Command ids, field widths,
version boundaries, callback behaviour and startup sequencing were
cross-checked against [zigbee-herdsman]'s Ember adapter (MIT, © Koen Kanters
and contributors), a mature behavioural reference, and against wire traces
captured from real hardware.

Nothing here is a mechanical translation of that source. Where the references
disagreed, the wire trace decided — which is how all three bugs above were
found. No GPL source was read or copied.

[zigbee-herdsman]: https://github.com/Koenkk/zigbee-herdsman

## Known limitations

- Nothing here reads the child table, so after a host restart there is no way
  to learn a joined device's short address from the NCP alone — it has to come
  from a join callback or from the caller. `getChildData` is the missing piece
  and is listed as a first task in `CONTRIBUTING.md`.
- Broadcast and multicast sends are implemented and unit-tested but have not
  been exercised against hardware; neither has forming a network, which is
  deliberately the one operation this crate will not let you do by accident.
- The `messageSentHandler` and `incomingMessageHandler` field order is
  confirmed on EZSP 13 only. Field *widths* above 14 follow the boundaries this
  crate models, but whether those callbacks reorder their fields at 14 has not
  been verified against either a device or a reference.
- One command in flight at a time. EZSP over ASH has a small window and the NCP
  answers in order, so pipelining would buy little and cost certainty about
  which frame answers which command.
- No network *forming*, only resuming. Forming writes to the dongle's tokens
  and orphans every joined device if done by mistake.
- ASH retransmission and the window are unit-tested but have not been provoked
  on hardware; nothing has dropped a frame yet.
- **Only one dongle and one firmware version have been tested.** Every
  compatibility claim above rests on a single Sonoff ZBDongle-E running
  EmberZNet 7.4.4. Reports from other hardware are the most useful thing anyone
  can send — see `CONTRIBUTING.md`.
- Statuses are carried as raw values rather than mapped between `EmberStatus`
  and `sl_status_t`. `is_ok()` behaves identically either way, which is what
  almost every caller needs, but a caller matching a specific non-zero status
  must know which firmware it is talking to.

## Relationship to other crates

There is an existing, actively maintained [`ezsp`] crate. It is a mature,
general-purpose implementation with a well-organised actor model, and it is a
reasonable choice. `rsezsp` differs in emphasis rather than quality: the
negotiated version is threaded into field decoding, the codecs are sans-I/O, and
the command surface grows only when real hardware needs it. If those are not
properties you need, the other crate is likely the better fit.

[`ezsp`]: https://crates.io/crates/ezsp

## Contributing

Contributions are welcome, and the most valuable ones are often the smallest.
[CONTRIBUTING.md](CONTRIBUTING.md) has a **Where to start** section listing real
open tasks, marked by whether they need hardware.

The single most useful thing anyone can do right now needs no Rust at all: run
the `startup` example against your dongle and
[report what happened](https://github.com/deatherving/rsezsp/issues/new?template=hardware_report.yml).
Exactly one dongle and one firmware build have ever been tested, so every
compatibility claim here rests on a single data point. "Everything worked" is a
real result and genuinely helps.

Also see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [SECURITY.md](SECURITY.md)
and [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
