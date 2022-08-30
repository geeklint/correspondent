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
    collections::HashMap, io::Write, sync::Arc, sync::Mutex, time::Duration,
};

use futures_util::stream::StreamExt;

use quinn::Connection;

use correspondent::{
    CertificateResponse, Event, IdentityCanonicalizer, PeerId, SocketBuilder,
};

// These certificates are publicly available, and should not be used for
// real applications
const CA_CERT: &str = include_str!("debug-cert.pem");
const CA_KEY_PK8: &[u8] = include_bytes!("debug-cert.pk8");

pub struct ProcessIdCanonicalizer;

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

#[tokio::main]
async fn main() {
    // create the signing certificate from the debug-cert files
    let ca_key = rcgen::KeyPair::from_der(CA_KEY_PK8).unwrap();
    let params =
        rcgen::CertificateParams::from_ca_cert_pem(CA_CERT, ca_key).unwrap();
    let ca_cert = rcgen::Certificate::from_params(params).unwrap();

    // get the current process id
    let process_id = std::process::id();

    // utility closure to re-show the prompt after printing
    let show_prompt = move || {
        print!("{}: ", process_id);
        let _ = std::io::stdout().flush();
    };

    // configure correspondent socket
    let mut builder = SocketBuilder::new()
        .with_identity(process_id, ProcessIdCanonicalizer)
        .with_service_name("Correspondent Chat Example".to_string())
        .with_default_socket()
        .expect("Failed to bind UDP socket")
        .with_default_endpoint_cfg()
        .with_new_certificate(
            Duration::from_secs(60 * 60 * 24),
            |csr: &str| {
                let csr = csr.to_string();
                std::future::ready(
                    (|| -> Result<_, Box<rcgen::RcgenError>> {
                        let csr =
                            rcgen::CertificateSigningRequest::from_pem(&csr)?;
                        let chain_pem =
                            csr.serialize_pem_with_signer(&ca_cert)?;
                        Ok(CertificateResponse {
                            chain_pem,
                            authority_pem: CA_CERT.to_string(),
                        })
                    })(),
                )
            },
        )
        .await
        .expect("Failed to setup socket certificate");

    // Recomend setting a keep-alive for at least one side of the connections.
    Arc::get_mut(&mut builder.client_cfg.transport)
        .expect("there should not be any other references at this point")
        .keep_alive_interval(Some(Duration::from_secs(5)));

    let connection_set_send: Arc<Mutex<HashMap<PeerId<u32>, Connection>>> =
        Arc::default();
    let connection_set_recv = Arc::clone(&connection_set_send);

    let (socket, mut events) =
        builder.start().expect("Failed to start socket");
    let _ = tokio::join!(
        // spawn a blocking task to handle stdin input
        tokio::task::spawn_blocking(move || {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            let mut lines = stdin.lock().lines();
            show_prompt();
            while let Some(Ok(line)) = lines.next() {
                let current_peers: Vec<Connection> = {
                    let current_peers = connection_set_send.lock().unwrap();
                    current_peers.values().cloned().collect()
                };
                for conn in current_peers {
                    let line = line.clone();
                    tokio::spawn(async move {
                        let mut stream = conn.open_uni().await.ok()?;
                        stream.write_all(line.as_bytes()).await.ok()?;
                        stream.finish().await.ok()?;
                        Some(())
                    });
                }
                show_prompt();
            }
            socket.endpoint().close(0u8.into(), b"");
        }),
        // spawn a regular task to handle events as they come in
        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                match event {
                    Event::NewPeer(peer_id, connection) => {
                        {
                            connection_set_recv
                                .lock()
                                .unwrap()
                                .insert(peer_id, connection);
                        }
                        println!("\r{} joined.", peer_id.identity);
                        show_prompt();
                    }
                    Event::PeerGone(peer_id) => {
                        {
                            connection_set_recv
                                .lock()
                                .unwrap()
                                .remove(&peer_id);
                        }
                        println!("\r{} left.", peer_id.identity);
                        show_prompt();
                    }
                    Event::UniStream(peer_id, stream) => {
                        tokio::spawn(async move {
                            if let Ok(message) = stream.read_to_end(1024).await
                            {
                                let text = String::from_utf8_lossy(&message);
                                println!("\r{}: {}", peer_id.identity, &*text);
                                show_prompt();
                            }
                        });
                    }
                    _ => (),
                }
            }
        })
    );
    println!();
}
