use std::{error::Error, future::Future, hash::Hash, path::PathBuf};

use crate::socket::{Peer, PeerId};

pub trait Application: 'static + Send + Sync {
    fn application_data_dir(&self) -> PathBuf;

    type Identity: 'static + Clone + Hash + Ord + Send + Sync;

    fn identity(&self) -> &Self::Identity;
    fn identity_to_dns(id: &Self::Identity) -> String;
    fn identity_to_txt(id: &Self::Identity) -> Vec<u8>;
    fn identity_from_txt(txt: &[u8]) -> Option<Self::Identity>;

    type SigningError: Error;
    type SigningFuture: Future<
        Output = Result<CertificateResponse, Self::SigningError>,
    >;

    fn sign_certificate(&self, csr_pem: &str) -> Self::SigningFuture;

    const MAX_MESSAGE_SIZE: usize;

    fn handle_message(&self, sender: PeerId<Self::Identity>, msg: Vec<u8>);
    fn handle_new_peer(&self, id: PeerId<Self::Identity>, peer: &Peer);
    fn handle_peer_gone(&self, peer: PeerId<Self::Identity>);

    const SERVICE_NAME: &'static str;
}

#[derive(Clone, Debug)]
pub struct CertificateResponse {
    pub client_chain_pem: String,
    pub authority_pem: String,
}
