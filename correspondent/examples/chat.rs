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

use std::{future::Ready, io::Write, path::PathBuf, sync::Arc};

use correspondent::{CertificateResponse, Peer, PeerId, Socket};

// These certificates are publicly available, and should not be used for
// real applications
const CA_CERT: &str = include_str!("debug-cert.pem");
const CA_KEY_PK8: &[u8] = include_bytes!("debug-cert.pk8");

#[tokio::main]
async fn main() {
    // create the signing certificate from the debug-cert files
    let ca_key = rcgen::KeyPair::from_der(CA_KEY_PK8).unwrap();
    let params =
        rcgen::CertificateParams::from_ca_cert_pem(CA_CERT, ca_key).unwrap();
    let ca_cert = rcgen::Certificate::from_params(params).unwrap();

    let process_id = std::process::id();
    let app = Application {
        process_id,
        ca_cert,
    };
    let socket = Socket::start(Arc::new(app)).await.unwrap();
    tokio::task::spawn_blocking(move || {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let mut lines = stdin.lock().lines();
        socket.app().show_prompt();
        while let Some(Ok(line)) = lines.next() {
            socket.send_to_all(line.into_bytes());
            socket.app().show_prompt();
        }
        println!();
    })
    .await
    .unwrap();
}

pub struct Application {
    process_id: u32,
    ca_cert: rcgen::Certificate,
}

impl Application {
    fn show_prompt(&self) {
        print!("{}: ", self.process_id);
        let _ = std::io::stdout().flush();
    }
}

impl correspondent::Application for Application {
    fn application_data_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(file!());
        path.set_file_name("data-dir");
        path
    }

    type Identity = u32;

    fn identity(&self) -> &Self::Identity {
        &self.process_id
    }

    fn identity_to_dns(&self, id: &Self::Identity) -> String {
        format!("id-{}.example.com", id)
    }

    fn identity_to_txt(&self, id: &Self::Identity) -> Vec<u8> {
        id.to_string().into_bytes()
    }

    fn identity_from_txt(&self, txt: &[u8]) -> Option<Self::Identity> {
        std::str::from_utf8(txt).ok()?.parse().ok()
    }

    type SigningError = rcgen::RcgenError;
    type SigningFuture = Ready<Result<CertificateResponse, rcgen::RcgenError>>;

    fn sign_certificate(&self, csr_pem: &str) -> Self::SigningFuture {
        std::future::ready((|| {
            let csr = rcgen::CertificateSigningRequest::from_pem(csr_pem)?;
            let client_chain_pem =
                csr.serialize_pem_with_signer(&self.ca_cert)?;
            Ok(CertificateResponse {
                client_chain_pem,
                authority_pem: CA_CERT.to_string(),
            })
        })())
    }

    fn max_message_size(&self) -> usize {
        1024
    }

    fn handle_message(&self, sender: &PeerId<Self::Identity>, msg: Vec<u8>) {
        let text = String::from_utf8_lossy(&msg);
        println!("\r{}: {}", sender.identity, &*text);
        self.show_prompt();
    }

    fn handle_new_peer(&self, id: &PeerId<Self::Identity>, _peer: &Peer) {
        println!("\r{} joined.", id.identity);
        self.show_prompt();
    }

    fn handle_peer_gone(&self, id: &PeerId<Self::Identity>) {
        print!("\r{} left.", id.identity);
        self.show_prompt();
    }

    fn service_name(&self) -> String {
        "Correspondent Example Service".to_string()
    }
}
