# Overview

[![crates.io](https://img.shields.io/crates/v/correspondent.svg)](https://crates.io/crates/correspondent)
[![docs.rs](https://docs.rs/correspondent/badge.svg)](https://docs.rs/correspondent/)
![License](https://img.shields.io/crates/l/correspondent?color=blueviolet)

correspondent is a high-level networking library which facilitates a
non-hierarchical network of peers to send messages.

correspondent uses
[DNS-SD](https://en.wikipedia.org/wiki/Zero-configuration_networking#DNS-based_service_discovery)
to discover peers on the local network.

# Supported Services

| Operating System | Service          |
| ---------------- |:----------------:|
| Linux            | Avahi (via dbus) |
