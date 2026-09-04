//! Milestone 1 against a real dongle.
//!
//! ```text
//! cargo run --example startup -- /dev/ttyUSB0
//! ```
//!
//! ```text
//! open serial
//!   -> ASH reset/handshake
//!   -> negotiate EZSP version
//!   -> read the NCP's EUI64
//!   -> resume the stored network
//!   -> clean shutdown
//! ```
//!
//! Read-only apart from `networkInit`, which resumes a network the NCP already
//! holds and never forms one. Nothing here writes to the dongle's tokens, so it
//! is safe to run against a coordinator with devices joined to it.

use std::time::Duration;

use rsezsp::Ncp;
use rsezsp::ezsp::command::{GetEui64, NetworkInit, SetConfigurationValue};
use rsezsp::transport::serial::{SerialSettings, SerialTransport};
use rsezsp::types::network::{ConfigId, NetworkInitBitmask};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let path = std::env::args()
        .nth(1)
        .ok_or("usage: startup <serial-path>")?;

    let mut step = Checklist::new();

    println!("=== rsezsp startup, {path} ===\n");

    // Flow control off: on a dongle that does not wire RTS/CTS, enabling it
    // blocks in open(2) until CTS is asserted, and no timeout can interrupt a
    // blocking syscall.
    let transport = match SerialTransport::open(&path, SerialSettings::default()) {
        Ok(transport) => {
            step.pass("serial open");
            transport
        }
        Err(e) => {
            step.fail("serial open", &e.to_string());
            step.report();
            return Ok(());
        }
    };

    // `connect` performs the ASH handshake and the version negotiation
    // together, because neither is useful alone.
    let mut ncp = match Ncp::connect(transport).await {
        Ok(ncp) => {
            step.pass("ASH reset");
            step.pass(&format!("EZSP version ({})", ncp.version()));
            ncp
        }
        Err(e) => {
            // Which of the two failed is in the error: an ASH failure names
            // ASH, a version failure names the version.
            step.fail("ASH reset / EZSP version", &e.to_string());
            step.report();
            return Ok(());
        }
    };

    // `version` is deliberately *not* sent again. It is a negotiation command,
    // and this firmware treats a second one as re-opening negotiation: every
    // command after it is answered `INVALID_COMMAND` with
    // `ERROR_VERSION_NOT_SET`. Found on hardware -- see the note in
    // `ezsp::command::Version`.

    match ncp.command(GetEui64).await {
        Ok(response) => {
            println!("   coordinator {}", response.eui64);
            step.pass("getEui64 (and correlation past the bootstrap)");
        }
        Err(e) => step.fail(
            "getEui64 (and correlation past the bootstrap)",
            &e.to_string(),
        ),
    }

    // Stack configuration *before* `networkInit`, and the order is not
    // cosmetic. This NCP defaults `STACK_PROFILE` to 0, and resuming a stored
    // ZigBee Pro network with a stack profile of 0 fails with
    // `EMBER_NOT_JOINED` (0x93) -- the network is there, the stack just will
    // not adopt it. Found by differential comparison: a working stack resumed
    // the same dongle seconds later, and the only difference was that it had
    // configured these first.
    //
    // EZSP refuses these writes once the network is up, so before is also the
    // only time they can be sent.
    let configuration = [
        (ConfigId::STACK_PROFILE, 2u16),
        (ConfigId::SECURITY_LEVEL, 5),
    ];
    let mut configured = true;
    for (config_id, value) in configuration {
        match ncp
            .command(SetConfigurationValue { config_id, value })
            .await
        {
            Ok(response) if response.status.is_ok() => {}
            Ok(response) => {
                println!("   {config_id:?} refused: {}", response.status);
                configured = false;
            }
            Err(e) => {
                println!("   {config_id:?} failed: {e}");
                configured = false;
            }
        }
    }
    if configured {
        step.pass("setConfigurationValue (stack profile, security level)");
    } else {
        step.fail(
            "setConfigurationValue",
            "the NCP refused a configuration item",
        );
    }

    // Resumes; never forms. A failure status here means "this NCP holds no
    // network", which is information rather than an error.
    match ncp
        .command(NetworkInit {
            bitmask: NetworkInitBitmask::PARENT_INFO_IN_TOKEN,
        })
        .await
    {
        Ok(response) if response.status.is_ok() => {
            println!("   resumed the stored network");
            step.pass("networkInit (resume)");
        }
        Ok(response) => {
            println!("   no stored network to resume: {}", response.status);
            step.pass("networkInit (no network, reported cleanly)");
        }
        Err(e) => step.fail("networkInit", &e.to_string()),
    }

    // Callbacks that arrived during startup. A stack coming up emits at least
    // one, and seeing them proves they were not mistaken for responses.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let callbacks = ncp.take_callbacks();
    if callbacks.is_empty() {
        println!("\nno callbacks during startup");
    } else {
        println!("\ncallbacks during startup:");
        for callback in &callbacks {
            println!("   {callback:?}");
        }
    }

    step.report();
    Ok(())
}

/// Records what actually passed, so the summary cannot overstate it.
struct Checklist {
    lines: Vec<(String, bool)>,
}

impl Checklist {
    fn new() -> Self {
        Self { lines: Vec::new() }
    }

    fn pass(&mut self, name: &str) {
        println!("{name:<34} PASS");
        self.lines.push((name.to_owned(), true));
    }

    fn fail(&mut self, name: &str, reason: &str) {
        println!("{name:<34} FAIL  {reason}");
        self.lines.push((name.to_owned(), false));
    }

    fn report(&self) {
        let passed = self.lines.iter().filter(|(_, ok)| *ok).count();
        println!("\n=== {passed}/{} passed ===", self.lines.len());
        for (name, ok) in &self.lines {
            println!("  {} {name}", if *ok { "PASS" } else { "FAIL" });
        }
    }
}
