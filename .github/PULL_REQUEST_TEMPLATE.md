<!--
Thanks for sending this. The checklist is short on purpose — delete anything
that does not apply, and open the PR even if you cannot tick everything. A
partial contribution with an honest note about what is untested is welcome and
gets reviewed; nothing here is a gate you have to pass alone.
-->

## What this changes

<!-- One or two sentences. If it fixes an issue, link it. -->

## How it was verified

- [ ] `./scripts/verify.sh` passes (check the exit code, not the output)
- [ ] Tested against real hardware — dongle, firmware and EZSP version:
- [ ] Not tested on hardware, and the documentation says so

<!--
"Implemented" and "seen to work on a device" are different claims, and this
project keeps them apart everywhere. An honestly-labelled untested change is
more useful than a confidently-labelled one, so please say which this is.
-->

## If this adds a command or callback

- [ ] Frame id, and where the layout came from (Silicon Labs' documentation, or
      a reference implementation, named)
- [ ] Which EZSP versions it applies to, if the encoding differs between them —
      several fields change width at version 14
- [ ] Encode and decode tests, including at least one truncated input, and
      asserting on the **bytes** rather than only on a round trip

<!--
That last point is not boilerplate. Two callbacks in this crate shipped with
passing unit tests and wrong field offsets, because the test bytes were built
from the same wrong belief as the decoder. Only a device caught it. Asserting
on offsets against a real capture is what stops that.
-->

## If a device disagreed with the documentation

Say what the device did. In this project the wire trace wins, and the capture
belongs in `tests/hardware_regression.rs` so the next refactor cannot undo it.
