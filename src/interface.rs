use default_net::get_default_gateway;
use once_cell::sync::Lazy;
use pnet::{
    datalink::{interfaces, NetworkInterface},
    util::MacAddr,
};

use crate::{abort, error::ScanError};

pub static DEFAULT: Lazy<NetworkInterface> = Lazy::new(|| {
    let mut default = interfaces()
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty())
        .cloned()
        .unwrap_or_else(|| abort(ScanError::MissingInterface));

    if default.mac.is_none() {
        abort(ScanError::MissingMacAddr);
    }

    default.ips.retain(|ip| ip.is_ipv4());
    if default.ips.is_empty() {
        abort(ScanError::Ipv6NotSupported);
    }

    log::debug!("Using network interface `{}`", default.name);

    default
});

pub static GATEWAY: Lazy<MacAddr> = Lazy::new(|| match get_default_gateway() {
    Ok(gateway) => {
        let mac = gateway.mac_addr;

        log::debug!("Gateway MAC address `{}`", mac);

        MacAddr::new(mac.0, mac.1, mac.2, mac.3, mac.4, mac.5)
    }
    Err(e) => abort(ScanError::GatewayFailed(e)),
});
