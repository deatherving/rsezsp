# Security policy

## Supported versions

This crate is pre-1.0 and only the latest release is supported. Fixes land on
`main`.

## What counts as a security issue here

This crate parses bytes arriving from a device on a serial line, and a Zigbee
coordinator is reachable over the air by anything within radio range. The
threat model that matters is therefore **untrusted input from the NCP**.

Treat as a security issue:

- A panic, hang, or unbounded allocation reachable from bytes an NCP can send.
  This includes anything an attacker could induce a device to relay: a
  malformed ZCL payload arriving in `incomingMessageHandler` reaches this
  crate's decoders.
- Key material appearing in a `Debug` output, a log line, or an error message.
  Key types redact in `Debug` precisely so a struct containing one can be
  logged safely; a leak through any path is a bug of this kind.
- Anything that lets a malformed frame be silently accepted as a well-formed
  one, where the result is a typed value built from the wrong bytes.

Ordinary decoding bugs — a wrong field width, a command that fails on some
firmware — are regular issues. Please open those publicly; they are more
useful discussed in the open.

## Reporting

Use GitHub's [private vulnerability reporting] on this repository. That opens a
private channel with the maintainers.

If you are not sure whether what you have found is a security issue, report it
privately and we will sort it out. A misfiled private report costs nothing; a
public one about something that turns out to be exploitable cannot be taken
back.

Please include the bytes. A minimised input that triggers the behaviour is
worth more than a description of it, and becomes a permanent regression test.

[private vulnerability reporting]: https://github.com/deatherving/rsezsp/security/advisories/new

## What to expect

- An acknowledgement within a week.
- An assessment of whether it reproduces, and a fix or an explanation.
- Credit in the changelog, unless you would rather not be named.

There is no bug bounty. This is a small project maintained in spare time, and
the honest expectation to set is best effort rather than a service level.

## A note on the fuzzers

Four fuzz targets cover the decoders and run in CI on every push. If you find a
crash, `cargo fuzz` will hand you a minimised artifact — that file is exactly
what a report should contain.
