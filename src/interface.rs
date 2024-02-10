use once_cell::sync::Lazy;
use pnet::datalink::{interfaces, NetworkInterface};

use crate::{abort, error::ScanError};

pub static DEFAULT: Lazy<NetworkInterface> = Lazy::new(|| {
    let default = interfaces()
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty())
        .cloned()
        .unwrap_or_else(|| abort(ScanError::MissingInterface));

    log::debug!("Using interface `{}`", default.name);

    default
});
