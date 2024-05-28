/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

//! This example demonstrates using correspondent to create a basic LAN chat
//! application.
//!
//! To try out it out, run multiple instances of this example.
//! The instances should automatically connect, and entering a message on one
//! will cause it to appear on the other(s).
//!
//! The example uses process ids as identity values.

use std::{
    collections::HashMap,
    convert::TryFrom,
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::stream::StreamExt;

use quinn::Connection;

use correspondent::{
    CertificateResponse, Event, Events, IdentityCanonicalizer, PeerId, Socket,
    SocketBuilder,
};

const ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);

// These certificates are publicly available, and should not be used for
// real applications
const CA_CERT: &str = include_str!("debug-cert.pem");
const CA_KEY_PK8: &[u8] = include_bytes!("debug-cert.pk8");

// A type alias for the set of active connections shared between tasks
type SharedConnectionSet = Arc<Mutex<HashMap<PeerId<u32>, Connection>>>;

pub struct ProcessIdCanonicalizer;

/// IdentityCanonicalizer specifies some essential conversions for the
/// protocols that correspondent uses.
impl IdentityCanonicalizer for ProcessIdCanonicalizer {
    type Identity = u32;

    fn to_dns(&self, id: &Self::Identity) -> String {
        format!("id-{}.example.com", id)
    }

    fn to_txt(&self, id: &Self::Identity) -> Vec<u8> {
        id.to_string().into_bytes()
    }

    fn parse_txt(&self, txt: &[u8]) -> Option<Self::Identity> {
        std::str::from_utf8(txt).ok()?.parse().ok()
    }
}

// Utility to re-show the prompt after printing
fn show_prompt(process_id: u32) {
    print!("{process_id}: ");
    let _ = std::io::stdout().flush();
}

#[tokio::main]
async fn main() {
    rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    // Create the certificate signing callback from the debug-cert files
    let ca_key = rcgen::KeyPair::try_from(CA_KEY_PK8).unwrap();
    let params = rcgen::CertificateParams::from_ca_cert_pem(CA_CERT).unwrap();
    let ca_cert = params.self_signed(&ca_key).unwrap();
    let certificate_signing_callback = |csr: &str| {
        std::future::ready((|| -> Result<_, Box<rcgen::Error>> {
            let csr = rcgen::CertificateSigningRequestParams::from_pem(csr)?;
            let chain_pem = csr.signed_by(&ca_cert, &ca_key)?.pem();
            Ok(CertificateResponse {
                chain_pem,
                authority_pem: CA_CERT.to_string(),
            })
        })())
    };

    // Get the current process id to use as our socket identity
    let process_id = std::process::id();

    // Configure correspondent socket
    let mut builder = SocketBuilder::new()
        .with_identity(process_id, ProcessIdCanonicalizer)
        .with_service_name("Correspondent Chat Example".to_string())
        .with_recommended_socket()
        .expect("Failed to bind UDP socket")
        .with_new_certificate(ONE_DAY, certificate_signing_callback)
        .await
        .expect("Failed to setup socket certificate");

    // For applications that are not constantly sending data (like this
    // chat app, which may idle when messages are not being typed) setting a
    // keep-alive value will prevent connections from closing due to timeout
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    builder.client_cfg.transport_config(Arc::new(transport));

    let connection_set: Arc<Mutex<HashMap<PeerId<u32>, Connection>>> =
        Arc::default();

    let (socket, events) = builder.start().expect("Failed to start socket");

    // Run the network event handling on tokio's async workers
    let event_task = tokio::spawn(handle_events(
        process_id,
        events,
        Arc::clone(&connection_set),
    ));
    // Run the input handling on tokio's blocking thread pool
    let input_task = tokio::task::spawn_blocking(move || {
        read_from_stdin(process_id, socket, connection_set)
    });
    // Wait for both tasks to complete
    let _ = tokio::join!(event_task, input_task);
    println!();
}

fn read_from_stdin(
    process_id: u32,
    socket: Socket<ProcessIdCanonicalizer>,
    connection_set: SharedConnectionSet,
) {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    show_prompt(process_id);
    while let Some(Ok(line)) = lines.next() {
        let current_peers: Vec<Connection> = {
            let current_peers = connection_set.lock().unwrap();
            // Clone the connections in the set so the mutex can
            // be released early
            current_peers.values().cloned().collect()
        };
        for conn in current_peers {
            let line = line.clone();
            // Use tokio::spawn so messages are sent to peers concurrently
            tokio::spawn(async move {
                let mut stream = conn.open_uni().await.ok()?;
                stream.write_all(line.as_bytes()).await.ok()?;
                stream.finish().ok()?;
                stream.stopped().await.ok()?;
                Some(())
            });
        }
        show_prompt(process_id);
    }
    // We're done with input, so shutdown the socket
    socket.endpoint().close(0u8.into(), b"");
}

async fn handle_events(
    process_id: u32,
    mut events: Events<u32>,
    connection_set: SharedConnectionSet,
) {
    while let Some(event) = events.next().await {
        match event {
            Event::NewPeer(peer_id, connection) => {
                {
                    connection_set.lock().unwrap().insert(peer_id, connection);
                }
                println!("\r{} joined.", peer_id.identity);
                show_prompt(process_id);
            }
            Event::PeerGone(peer_id) => {
                {
                    connection_set.lock().unwrap().remove(&peer_id);
                }
                println!("\r{} left.", peer_id.identity);
                show_prompt(process_id);
            }
            Event::UniStream(peer_id, mut stream) => {
                tokio::spawn(async move {
                    if let Ok(message) = stream.read_to_end(1024).await {
                        let text = String::from_utf8_lossy(&message);
                        println!("\r{}: {}", peer_id.identity, text);
                        show_prompt(process_id);
                    }
                });
            }
            // This example does not use bidirectional streams, or handle
            // any events which may be added in a future version
            Event::BiStream(..) => {}
            _ => (),
        }
    }
}
