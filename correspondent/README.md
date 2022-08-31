# Overview

[![crates.io](https://img.shields.io/crates/v/correspondent.svg)](https://crates.io/crates/correspondent)
[![docs.rs](https://docs.rs/correspondent/badge.svg)](https://docs.rs/correspondent/)
![License](https://img.shields.io/crates/l/correspondent?color=blueviolet)
[![Build Status](https://github.com/geeklint/correspondent/workflows/Rust/badge.svg)](https://github.com/geeklint/correspondent/actions)

correspondent is a high-level networking library which facilitates a
non-hierarchical network of peers to send messages.

correspondent uses
[DNS-SD](https://en.wikipedia.org/wiki/Zero-configuration_networking#DNS-based_service_discovery)
to discover peers on the local network.

correspondent uses [Quinn](https://github.com/quinn-rs/quinn), an
implementation of the QUIC protocol, as a transport layer.

See `examples/chat.rs` for a simple example application.

# Supported Services

| Operating System | Service          |
| ---------------- |:----------------:|
| Windows 10       | Dnsapi.dll       |
| Linux            | Avahi (via dbus) |
