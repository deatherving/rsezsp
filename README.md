# rsezsp

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

## Status

Milestone 1 is confirmed on real hardware:

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

Coordinator bringup passes **8/8**, and with `--permit-join` a real device
joins and its `trustCenterJoin` callback decodes: **10/10**. Not yet attempted
on hardware: sending a unicast to the joined device, and recovery across a host
restart. See [Hardware validation](#hardware-validation).

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
| `sendUnicast` | `0x0034` | not yet |
| `setConfigurationValue` | `0x0053` | confirmed |
| `setPolicy` | `0x0055` | confirmed |
| `importTransientKey` | `0x0111` | confirmed |

### Callbacks

`stackStatusHandler` (confirmed), `trustCenterJoinHandler` (confirmed),
`incomingMessageHandler`, `messageSentHandler`. A callback this build does not
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

## Three bugs real hardware found

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

## Verification

| | |
|---|---|
| unit and integration tests | **114** |
| fuzz targets | 4 |
| fuzz executions to date | ~89.2M, no crashes |
| hardware-confirmed paths | bringup end to end, plus a real device join |

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
| `sendUnicast` | yes | yes | **not yet** |
| device join, commissioning | yes | — | yes |
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

- Milestone 2 is half done: a device joins, but nothing has been sent to it
  yet. Milestone 3 (restart recovery) is not started.
- One command in flight at a time. EZSP over ASH has a small window and the NCP
  answers in order, so pipelining would buy little and cost certainty about
  which frame answers which command.
- No network *forming*, only resuming. Forming writes to the dongle's tokens
  and orphans every joined device if done by mistake.
- ASH retransmission and the window are unit-tested but have not been provoked
  on hardware; nothing has dropped a frame yet.
- Only one dongle and one firmware version have been tested. Reports from other
  hardware are welcome — see `CONTRIBUTING.md`.
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

## License

MIT. See [LICENSE](LICENSE).
