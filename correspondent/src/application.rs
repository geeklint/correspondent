/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::hash::Hash;

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
