use std::{error::Error, future::Future, hash::Hash, path::PathBuf};

use crate::socket::{Peer, PeerId};

/// The Application trait is the primary way to configure a sea-level socket,
/// and respond to network events.
///
/// There are two big things an application must define: an "identity" and a
/// method for signing TLS certificates.
///
/// The identity is used to communicate with other peers who you are.
/// sea-level does not assume identities are unique - the PeerId type passed
/// into the event handlers may contain the same identity without itself
/// comparing equal.  Suggested choices for Identity include:
///
/// * `()` - in the case that all peers are the same, you can use the unit type
///   to effectively ignore identities.
/// * Integers
/// * `String`
///
/// You must also define certain operations over the identity, including
/// converting it to a domain name and TXT value.  The domain names do not
/// need to be registered, but they must be syntactically valid.  TXT values
/// should preferably be ASCII text, and as short as possible (under 200
/// bytes).
///
/// Common approaches to signing certificates include storing the CA
/// certificate in the application binary.  This is the simplest option, and
/// does provide encryption, however anyone with access to the application
/// binary can authenticate with the network. (The examples in this crate
/// demonstrate this approach).  Another alternative is to have
/// a 3rd party server which authenticates clients and signs the certificates.
pub trait Application: 'static + Send + Sync {
    /// Provide a location for sea-level to store some information, notably
    /// offline copies of signed certificates.
    fn application_data_dir(&self) -> PathBuf;

    /// The maximum message size to accept from a peer.
    ///
    /// This is an approximate upper bound on the memory usage when receiving a
    /// message.  This is important to avoid a situation where a malicious peer
    /// might cause a denial of service by sending an incredibly large message.
    /// This does not effect the amount of memory allocated for small messages;
    /// it only imposes a maximum.
    fn max_message_size(&self) -> usize;

    /// The name of the DNS-SD service to use.
    fn service_name(&self) -> &'static str;

    /// The identity type.  See trait documentation for more information.
    type Identity: 'static + Clone + Hash + Ord + Send + Sync;

    /// Get the identity to be used by this instance.
    fn identity(&self) -> &Self::Identity;

    /// Convert an identity to an domain name.  See trait documentation for
    /// more information.
    fn identity_to_dns(&self, id: &Self::Identity) -> String;

    /// Convert an identity to an TXT value.  See trait documentation for
    /// more information.
    fn identity_to_txt(&self, id: &Self::Identity) -> Vec<u8>;

    /// Parse a TXT value to an identity.  See trait documentation for
    /// more information.
    fn identity_from_txt(&self, txt: &[u8]) -> Option<Self::Identity>;

    /// Type to return if certificate signing fails.
    type SigningError: Error;

    /// Future for signing certificate.
    type SigningFuture: Future<
        Output = Result<CertificateResponse, Self::SigningError>,
    >;

    /// Sign a certificate based on a PEM-formatted certificate signing
    /// request.
    fn sign_certificate(&self, csr_pem: &str) -> Self::SigningFuture;

    /// Callback called when a peer sends a message.
    fn handle_message(&self, sender: &PeerId<Self::Identity>, msg: Vec<u8>);

    /// Callback called when a new peer connects.
    fn handle_new_peer(&self, id: &PeerId<Self::Identity>, peer: &Peer);

    /// Callback called when a peer is no longer connected.
    fn handle_peer_gone(&self, peer: &PeerId<Self::Identity>);
}

/// Type to return from Application::sign_certificate.
#[derive(Clone, Debug)]
pub struct CertificateResponse {
    /// PEM-formatted signed certificate chain.
    pub client_chain_pem: String,

    /// PEM-formatted certificate authority to validate peer certificates
    /// against.
    pub authority_pem: String,
}
