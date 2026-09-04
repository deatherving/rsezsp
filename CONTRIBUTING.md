# Contributing to rsezsp

Contributions are welcome, and the most valuable ones are often the smallest:
a report that this crate does or does not work with your dongle is worth more
than a speculative feature.

## What is especially wanted

- **New EZSP commands and callbacks**, when you have a use for them.
- **Firmware compatibility fixes.** Different EmberZNet versions frame the
  same command differently, and only one has been tested here.
- **Hardware validation reports.** See below — a report on a dongle nobody has
  tried is a real contribution even if everything works.
- **ASH improvements.** Retransmission and the window are unit-tested but have
  never been provoked on real hardware.
- **Parser robustness and fuzzing.** New targets, longer campaigns, or a
  crashing input.
- **Documentation**, particularly anywhere the protocol's reasoning is
  implicit.
- **Bug fixes**, with a test that fails before and passes after.

## What belongs in this crate

`rsezsp` implements the host-to-NCP conversation: ASH framing and the EZSP
command protocol. Nothing above that layer belongs here.

**In scope:** EZSP commands and callbacks, their wire encodings, version
boundaries, ASH framing and flow control, correlation, the serial transport,
and the types those frames carry — APS headers, node ids, statuses, security
manager structures.

**Out of scope:** ZCL, ZDO interview logic, device definitions and quirks,
attribute reporting policy, binding and group management as *behaviour*,
network topology, MQTT, Home Assistant, and anything that decides what a
Zigbee network *should* do.

The distinction is not about which layer of the Zigbee stack a name comes
from — it is about who decides. `sendUnicast` carries an APS payload, and the
APS header is part of the frame this crate encodes, so `ApsFrame` belongs
here. What goes *inside* that payload does not, and neither does the choice of
when to send one.

A useful test: if a change would need updating because a new device model
behaves oddly, or because a Zigbee specification revision changed what a
cluster means, it belongs in the layer above. Nothing here should have an
opinion about a device.

The `startup` example deliberately hand-builds three ZCL bytes to actuate a
real device, with a comment saying why. That is the boundary being
demonstrated, not crossed: the example is the caller, and the caller is where
ZCL lives.

This is enforced by review rather than by the compiler, so please raise it if
you see it slipping.

## Where to start

These are real open tasks, not filler. Each says what it needs, so you can
find one that matches what you have.

**Run it against your dongle and say what happened.** No Rust required, and it
is the most useful thing anyone can do right now — exactly one dongle and one
firmware build have ever been tested, so every compatibility claim in the
README rests on a single data point. `cargo run --example startup -- <port>`,
then open a hardware report. "Everything worked" is a real result.

**Add `getChildData` (`0x004a`).** *Needs a device to test properly.* After a
host restart there is currently no way to learn a joined device's short
address; it has to come from a join callback or from the caller. Reading the
child table is what closes that, and it is the concrete blocker on restart
recovery. Self-contained: one command, one response type, a loop that stops
when the NCP says there are no more children.

**Add property tests.** *No hardware needed.* There are none, and there is
obvious ground for them: ASH encode/decode round-trips across arbitrary
payloads, byte stuffing and randomisation being their own inverse, the
sequence-number window never admitting an ambiguous acknowledgement. `proptest`
would fit the existing suite directly.

**Map `EmberStatus` to `sl_status_t`.** *No hardware needed, but a reference
does.* Statuses are currently carried as raw values. `is_ok()` behaves
identically either way, which covers almost every caller, but a caller matching
a specific non-zero status has to know which firmware it is talking to.

**Verify the callback field order above EZSP 14.** *Needs newer firmware.*
`messageSentHandler` and `incomingMessageHandler` are confirmed on EZSP 13
only. Field *widths* above 14 follow the boundaries this crate models, but
whether those callbacks reorder their fields has not been verified against
either a device or a reference — and getting it wrong produces plausible wrong
values rather than an error.

**Provoke ASH retransmission on hardware.** *Needs a device and patience.* The
window and retransmission logic are unit-tested but have never fired against a
real dongle, because nothing has dropped a frame yet.

If none of these fit, open an issue describing what you want to do. A command
that is not implemented because nobody has needed it yet is not a decision
against it.

## Before you open a pull request

```bash
./scripts/verify.sh
```

That runs exactly what CI runs, in the same order, and stops at the first
failure. Check its exit code rather than reading its output.

## Adding a command

The bar is not high, but it is specific. A new command should come with:

- **Its frame id**, and where you got it — the Silicon Labs documentation, or a
  reference implementation, named.
- **The EZSP versions it applies to**, if the encoding differs between them.
  This is the part most easily missed: several fields change width at version
  14, and a command that is right on one firmware can be silently wrong on
  another. If you are unsure, say so in the PR rather than guessing.
- **Encode and decode tests**, including at least one truncated input. Assert
  on the *bytes*, not only on a round trip — a codec that reads back its own
  wrong byte order passes a round-trip test and fails against every device.
- **Hardware confirmation, if you have it.** Not required. An honestly-labelled
  untested command is more useful than a confidently-labelled one.

Document each command with its id, version applicability, reference source and
hardware-tested status, as the existing ones do. "Implemented" and "seen to
work on a device" are different claims and the documentation keeps them apart.

## Reporting hardware results

Open an issue with:

- the dongle (chip, if you know it) and how it appears on your system
- the EmberZNet and EZSP versions from `cargo run --example startup`
- the output of that example, and whatever failed

A failure report with a wire trace is the most useful thing anyone can send.
`RUST_LOG=debug` logs every EZSP frame in and out.

## When hardware disagrees with the protocol

This is the workflow the project runs on, and it is why the crate exists:

1. **Capture evidence.** `RUST_LOG=debug` gives the frames.
2. **Identify the layer.** ASH and EZSP fail differently — a bad CRC is
   answered with a NAK and a resend, a malformed EZSP frame has nothing to
   resend.
3. **Add a regression test** in `tests/hardware_regression.rs` with the
   captured bytes, and watch it fail.
4. **Make the smallest correct fix.**
5. **Verify on hardware**, and say in the PR that you did.
6. **Keep the capture.** A fixed bug with no test is a bug waiting for the next
   refactor.

Do not work around unexpected hardware behaviour silently. If a device needs a
compatibility quirk, document what the device does and why the quirk is
correct — the next person needs to know it was a decision.

## Style

- **Never panic on input from the NCP.** Every byte came off a serial line from
  a device we do not control. No slice indexing, no `unwrap`, no arithmetic
  that can wrap. The lints enforce this and are relaxed only inside tests.
- **No `unsafe`.** It is forbidden at the crate level. If you have a case that
  genuinely needs it, open an issue first.
- **Typed errors, no `Other(String)`.** A variant that absorbs everything
  absorbs exactly the cases that turn up on unfamiliar hardware.
- **Redact key material.** Keys are newtypes whose `Debug` redacts, because a
  struct containing one ends up in a log line eventually.
- **Keep ASH and EZSP separate.** No EZSP type belongs in `ash::`, and no ASH
  concern belongs above it.
- **Comments explain why, not what.** The protocol has a lot of non-obvious
  detail; that is what the comments are for.

## Licensing

MIT. By contributing you agree your work is licensed the same way.

If you take behaviour, constants or tables from another project, say so in the
PR and keep the attribution in the code. [zigbee-herdsman] is MIT and may be
used as a behavioural reference with attribution; do not copy GPL sources,
including Zigbee2MQTT, into this repository.

[zigbee-herdsman]: https://github.com/Koenkk/zigbee-herdsman
