//! Milestone 1 against a real dongle.
//!
//! ```text
//! cargo run --example startup -- /dev/ttyUSB0
//! cargo run --example startup -- /dev/ttyUSB0 --permit-join
//! cargo run --example startup -- /dev/ttyUSB0 --onoff 14913 on
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
//!
//! `--permit-join` opens the network for four minutes and installs the
//! well-known commissioning key for the duration, then reports whatever
//! callbacks arrive. That is the only mode that changes anything observable
//! from outside, and it undoes itself when the window closes.

use std::time::Duration;

use rsezsp::ezsp::callback::Callback;
use rsezsp::ezsp::command::{
    AddEndpoint, GetEui64, ImportTransientKey, NetworkInit, PermitJoining, SendUnicast,
    SetConfigurationValue, SetPolicy,
};
use rsezsp::transport::Transport;
use rsezsp::transport::serial::{SerialSettings, SerialTransport};
use rsezsp::types::aps::{ApsFrame, ApsOptions, UnicastType};
use rsezsp::types::network::{ConfigId, Decision, NetworkInitBitmask, NodeId, PolicyId};
use rsezsp::types::security::{SecurityKey, SecurityManFlags};
use rsezsp::{Eui64, Ncp};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or("usage: startup <serial-path> [--permit-join] [--onoff <nwk> on|off]")?
        .clone();
    let permit_join = args.iter().any(|a| a == "--permit-join");
    // `--onoff <nwk> <on|off>`: the short address comes from a join callback,
    // which `--permit-join` prints.
    let onoff = args.iter().position(|a| a == "--onoff").and_then(|i| {
        let nwk = args.get(i + 1)?.parse::<u16>().ok()?;
        let on = matches!(args.get(i + 2).map(String::as_str), Some("on"));
        Some((NodeId(nwk), on))
    });

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

    register_endpoint(&mut ncp, &mut step).await;
    configure_stack(&mut ncp, &mut step).await;
    configure_policies(&mut ncp, &mut step).await;

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

    if permit_join {
        open_for_joining(&mut ncp, &mut step).await;
    }

    if let Some((node_id, on)) = onoff {
        println!("\n=== commanding {node_id} ===");
        send_onoff(&mut ncp, node_id, on, &mut step).await;
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

/// Registers the coordinator's application endpoint.
///
/// Before the network comes up: EZSP refuses `addEndpoint` once it is, and a
/// coordinator with no endpoint answers an active-endpoint request with an
/// empty list -- so it reads as a node with no functionality rather than as a
/// misconfiguration.
async fn register_endpoint<T: Transport>(ncp: &mut Ncp<T>, step: &mut Checklist) {
    // Endpoint 1, Home Automation profile, and the clusters a coordinator
    // serves. Deliberately minimal: what a device needs to see, not a
    // complete descriptor.
    let command = AddEndpoint {
        endpoint: 1,
        profile_id: 0x0104,
        device_id: 0x0065,
        app_flags: 0,
        input_clusters: vec![0x0000, 0x000a, 0x0019],
        output_clusters: vec![0x0000, 0x0006, 0x0019],
    };
    match ncp.command(command).await {
        Ok(response) if response.status.is_ok() => step.pass("addEndpoint"),
        // A re-run re-registers the same endpoint, which some firmware
        // refuses. Worth reporting distinctly from a dongle that stopped
        // answering.
        Ok(response) => {
            println!("   refused: {} (already registered?)", response.status);
            step.pass("addEndpoint (refused, reported cleanly)");
        }
        Err(e) => step.fail("addEndpoint", &e.to_string()),
    }
}

/// Sets the stack configuration `networkInit` depends on.
///
/// The order is not cosmetic. This NCP defaults `STACK_PROFILE` to 0, and
/// resuming a stored `ZigBee` Pro network with a stack profile of 0 fails with
/// `EMBER_NOT_JOINED` -- the network is there, the stack just will not adopt
/// it. Found by differential comparison against a working implementation.
///
/// EZSP also refuses these writes once the network is up, so before is the
/// only time they can be sent at all.
async fn configure_stack<T: Transport>(ncp: &mut Ncp<T>, step: &mut Checklist) {
    let items = [
        // Both are advertised in beacons and both must match what a joining
        // device expects. The NCP defaults STACK_PROFILE to 0, which is not
        // ZigBee Pro -- `networkInit` will not adopt a stored network until
        // this is 2.
        (ConfigId::STACK_PROFILE, 2u16),
        (ConfigId::SECURITY_LEVEL, 5),
        // How long the NCP holds a message for a sleeping child. A battery
        // device is not listening when the unicast is sent; it hears the
        // message the next time it polls its parent. The default is 3s, which
        // is shorter than some devices' poll interval -- the send then reports
        // success and the message is silently dropped before delivery.
        (ConfigId::INDIRECT_TRANSMISSION_TIMEOUT, 30_000),
        // How long a child may go quiet before the NCP ages it out of the
        // child table. Once that happens its short address is gone and the
        // device has to rejoin, so this wants to outlive a host restart.
        (ConfigId::END_DEVICE_POLL_TIMEOUT, 8),
    ];
    let mut ok = true;
    for (config_id, value) in items {
        match ncp
            .command(SetConfigurationValue { config_id, value })
            .await
        {
            Ok(response) if response.status.is_ok() => {}
            Ok(response) => {
                println!("   {config_id:?} refused: {}", response.status);
                ok = false;
            }
            Err(e) => {
                println!("   {config_id:?} failed: {e}");
                ok = false;
            }
        }
    }
    if ok {
        step.pass("setConfigurationValue (stack profile, security level)");
    } else {
        step.fail(
            "setConfigurationValue",
            "the NCP refused a configuration item",
        );
    }
}

/// Sets the trust-centre policies that decide whether a device may join.
///
/// `permitJoining` only opens the MAC association window. Whether a device is
/// *admitted*, and whether it is given the network key, is this decision.
///
/// The value is assembled from named bits rather than taken from a composite
/// constant, because the historical trap is that a legacy enumeration called
/// 0x00 `ALLOW_JOINS` while 0x00 on modern firmware is the default
/// configuration -- which denies every join. A library offering that name for
/// that value sets deny and logs allow.
async fn configure_policies<T: Transport>(ncp: &mut Ncp<T>, step: &mut Checklist) {
    let policies = [
        (
            PolicyId::TRUST_CENTER,
            Decision::ALLOW_JOINS.union(Decision::ALLOW_UNSECURED_REJOINS),
        ),
        (
            PolicyId::TC_KEY_REQUEST,
            Decision::ALLOW_TC_KEY_REQUEST_SAME_KEY,
        ),
        (PolicyId::APP_KEY_REQUEST, Decision::DENY_APP_KEY_REQUESTS),
    ];
    let mut ok = true;
    for (policy_id, decision) in policies {
        match ncp
            .command(SetPolicy {
                policy_id,
                decision,
            })
            .await
        {
            Ok(response) if response.status.is_ok() => {}
            Ok(response) => {
                println!("   {policy_id:?} refused: {}", response.status);
                ok = false;
            }
            Err(e) => {
                println!("   {policy_id:?} failed: {e}");
                ok = false;
            }
        }
    }
    if ok {
        println!("   trust centre: joins and unsecured rejoins allowed, link keys answered");
        step.pass("setPolicy (trust centre, key requests)");
    } else {
        step.fail("setPolicy", "the NCP refused a policy");
    }
}

/// Opens the network for joining, and watches what arrives.
///
/// Two commands, because either alone produces an ambiguous result. The
/// transient key is what a Zigbee 3.0 device without an install code uses to
/// protect the one exchange in which it receives the network key: without it a
/// device joins at the MAC layer, cannot finish commissioning, and rejoins
/// every few seconds indefinitely -- while every call here reports success.
///
/// The key is well-known and public by design (`ZigBeeAlliance09`). The
/// security it provides is that the window in which it is accepted is short
/// and operator-initiated.
async fn open_for_joining<T: Transport>(ncp: &mut Ncp<T>, step: &mut Checklist) {
    match ncp
        .command(ImportTransientKey {
            // Whichever device joins: which one that will be is not known
            // until it does. A specific address here is the install-code flow.
            eui64: Eui64::WILDCARD,
            key: SecurityKey::ZIGBEE_ALLIANCE_09,
            flags: SecurityManFlags::NONE,
        })
        .await
    {
        Ok(response) if response.status.is_ok() => step.pass("importTransientKey"),
        Ok(response) => step.fail("importTransientKey", &response.status.to_string()),
        Err(e) => step.fail("importTransientKey", &e.to_string()),
    }

    match ncp.command(PermitJoining::for_seconds(240)).await {
        Ok(response) if response.status.is_ok() => {
            step.pass("permitJoining (240s)");
            println!("\n   put the device in pairing mode now\n");
        }
        Ok(response) => step.fail("permitJoining", &response.status.to_string()),
        Err(e) => step.fail("permitJoining", &e.to_string()),
    }

    // Streamed as they arrive rather than collected at the end: a join window
    // is finite, and output that only appears afterwards cannot tell you
    // whether the device is being seen while there is still time to retry.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(240);
    let mut joined = None;
    while tokio::time::Instant::now() < deadline {
        let Ok(callbacks) = ncp.poll(Duration::from_secs(5)).await else {
            break;
        };
        for callback in callbacks {
            println!("   {callback:?}");
            if let Callback::TrustCenterJoin { node_id, eui64, .. } = callback {
                joined = Some((node_id, eui64));
            }
        }
        if joined.is_some() {
            break;
        }
    }

    match joined {
        Some((node_id, eui64)) => {
            step.pass("device join (trustCenterJoin callback)");
            println!("\n   joined: {eui64} at {node_id}");
            println!("   to command it:  --onoff {} on\n", node_id.0);
        }
        None => step.fail("device join", "no trustCenterJoin callback within 240s"),
    }
}

/// Sends a `genOnOff` command to a joined device.
///
/// # This crate does not do ZCL
///
/// The three payload bytes below are a ZCL frame, hand-built here because
/// `rsezsp` deliberately has no ZCL layer: it sends APS payloads and what is
/// inside them is the caller's business. A real application would build this
/// with a ZCL library. Doing it inline in an example is the honest way to show
/// where the boundary is.
///
/// This physically actuates the device.
async fn send_onoff<T: Transport>(
    ncp: &mut Ncp<T>,
    node_id: NodeId,
    on: bool,
    step: &mut Checklist,
) {
    // ZCL: frame control 0x01 (cluster-specific, client to server), a
    // transaction sequence number, then the command -- 0x00 off, 0x01 on.
    let zcl = vec![0x01, 0x42, u8::from(on)];

    let command = SendUnicast {
        unicast_type: UnicastType::Direct,
        index_or_destination: node_id.0,
        aps_frame: ApsFrame {
            profile_id: 0x0104,
            cluster_id: 0x0006,
            source_endpoint: 1,
            destination_endpoint: 1,
            // The caller chooses these, not the crate: without retry a single
            // lost frame reads as an unreachable device, and without route
            // discovery the first message to a device behind a router fails.
            // Both are decisions about how the network should behave, which is
            // the application's business rather than the driver's.
            options: ApsOptions::RETRY.union(ApsOptions::ENABLE_ROUTE_DISCOVERY),
            group_id: 0,
            sequence: 0,
        },
        // Echoed back by the matching `messageSent` callback, which is how
        // delivery is learned. The command's own response only says the NCP
        // accepted the frame for sending.
        message_tag: 0x01,
        message: zcl,
    };

    let label = if on {
        "sendUnicast (on)"
    } else {
        "sendUnicast (off)"
    };
    match ncp.command(command).await {
        Ok(response) if response.status.is_ok() => {
            println!("   accepted, APS sequence {}", response.aps_sequence);
            step.pass(label);
        }
        Ok(response) => step.fail(label, &response.status.to_string()),
        Err(e) => step.fail(label, &e.to_string()),
    }

    // Delivery is reported separately and asynchronously. A sleepy device has
    // to poll its parent before it hears anything, so this can take a while --
    // up to the indirect transmission timeout set during bringup.
    //
    // Polling has to continue until `messageSent` specifically arrives.
    // `poll` returns on the first callback of any kind, and other callbacks
    // are genuinely in flight here: `networkInit` produces a `stackStatus`
    // that is only observed once something reads. Treating the first callback
    // as the answer reports whatever happened to arrive first.
    println!("   waiting for messageSent...");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    let mut outcome = None;
    while outcome.is_none() && tokio::time::Instant::now() < deadline {
        match ncp.poll(Duration::from_secs(5)).await {
            Ok(callbacks) => {
                for callback in callbacks {
                    println!("   {callback:?}");
                    if let Callback::MessageSent { status, .. } = callback {
                        outcome = Some(status);
                    }
                }
            }
            Err(e) => {
                step.fail("messageSent callback", &e.to_string());
                return;
            }
        }
    }

    match outcome {
        Some(status) if status.is_ok() => step.pass("messageSent callback (delivered)"),
        // A delivery failure is the device not answering, not a bad frame: the
        // NCP built and transmitted the message and nothing acknowledged it.
        Some(status) => step.fail("messageSent callback", &format!("not delivered: {status}")),
        None => step.fail(
            "messageSent callback",
            "no messageSent within 40s (the device may never have polled)",
        ),
    }
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
