/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{error::Error, future::Future, hash::Hash, path::PathBuf};

/// A correspondent socket must be created with a specific identity.
///
/// The identity is used to communicate with other peers who you are.
/// `Correspondent` does not assume identities are unique - the PeerId type
/// passed into the event handlers may contain the same identity without itself
/// comparing equal.  Suggested choices for Identity include:
///
/// * `()` - in the case that all peers are the same, you can use the unit type
///   to effectively ignore identities.
/// * Integers
/// * `String`
///
/// This trait is used to define certain required operations over the identity,
/// namely converting it to a domain name and TXT value.  The domain names do
/// not need to be registered, but they must be syntactically valid.  TXT values
/// should preferably be ASCII text, and as short as possible (under 200 bytes).
pub trait IdentityCanonicalizer: 'static + Send + Sync {
    /// The type used to represent an identity.  See trait documentation for
    /// more information.
    type Identity: 'static + Clone + Hash + Ord + Send + Sync;

    /// Convert an identity to an domain name.  See trait documentation for
    /// more information.
    fn to_dns(&self, id: &Self::Identity) -> String;

    /// Convert an identity to an TXT value.  See trait documentation for
    /// more information.
    fn to_txt(&self, id: &Self::Identity) -> Vec<u8>;

    /// Parse a TXT value to an identity.  See trait documentation for
    /// more information.
    fn parse_txt(&self, txt: &[u8]) -> Option<Self::Identity>;
}

/// The Application trait is the primary way to configure a correspondent
/// socket.
///
/// There are two important things an application must define: an "identity"
/// and a method for signing TLS certificates.
///
/// The identity is used to communicate with other peers who you are.
/// `Correspondent` does not assume identities are unique - the PeerId type
/// passed into the event handlers may contain the same identity without itself
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
    /// Provide a location for correspondent to store some information, notably
    /// offline copies of signed certificates.
    fn application_data_dir(&self) -> PathBuf;

    /// The name of the DNS-SD service to use.
    fn service_name(&self) -> String;

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
