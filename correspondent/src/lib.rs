/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

//! # Overview
//!
//! correspondent is a high-level networking library which facilitates a
//! non-hierarchical network of peers to send messages.
//!
//! correspondent uses
//! [DNS-SD](https://en.wikipedia.org/wiki/Zero-configuration_networking#DNS-based_service_discovery)
//! to discover peers on the local network.
//!
//! To use correspondent, define an [`Application`](Application) type, and
//! create a [`Socket`](Socket) with it.
//!
//! # Supported Services
//!
//! | Operating System | Service          |
//! | ---------------- |:----------------:|
//! | Windows 10       | Dnsapi.dll       |
//! | Linux            | Avahi (via dbus) |

#![warn(missing_docs)]
#![warn(clippy::clone_on_ref_ptr)]
#![deny(clippy::unwrap_used)]
#![warn(clippy::default_trait_access)]
#![warn(clippy::cast_lossless)]
#![warn(clippy::explicit_into_iter_loop)]
#![warn(clippy::explicit_iter_loop)]
#![warn(clippy::implicit_clone)]
#![warn(clippy::if_then_some_else_none)]
#![warn(clippy::fn_params_excessive_bools)]
#![warn(clippy::inefficient_to_string)]
#![warn(clippy::let_unit_value)]
#![warn(clippy::manual_ok_or)]
#![warn(clippy::match_bool)]
#![deny(clippy::mem_forget)]
#![warn(clippy::mut_mut)]
#![warn(clippy::mutex_integer)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_continue)]
#![warn(clippy::option_option)]
#![warn(clippy::path_buf_push_overwrite)]
#![warn(clippy::rc_buffer)]
#![warn(clippy::redundant_pub_crate)]
#![warn(clippy::ref_option_ref)]
#![warn(clippy::rest_pat_in_fully_bound_structs)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::type_repetition_in_bounds)]
#![warn(clippy::unreadable_literal)]
#![warn(clippy::unseparated_literal_suffix)]
#![warn(clippy::useless_let_if_seq)]
#![warn(clippy::verbose_file_reads)]

mod application;
mod nsd;
mod socket;
mod socket_builder;
mod util;

pub use self::{
    application::{Application, CertificateResponse, IdentityCanonicalizer},
    socket::{Event, Events, Peer, PeerId, Socket},
    socket_builder::SocketBuilder,
};
