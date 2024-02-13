use std::net::Ipv4Addr;

use default_net::get_default_gateway;
use once_cell::sync::Lazy;
use pnet::{
    datalink::{interfaces, NetworkInterface},
    ipnetwork::IpNetwork,
    util::MacAddr,
};

use crate::{abort, error::ScanError};

pub struct Board {
    mac: MacAddr,
    ip: Ipv4Addr,
    raw: NetworkInterface,
}

impl Board {
    fn new(mac: MacAddr, ip: Ipv4Addr, raw: NetworkInterface) -> Self {
        Self { mac, ip, raw }
    }

    #[inline]
    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    #[inline]
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    #[inline]
    pub fn raw(&self) -> &NetworkInterface {
        &self.raw
    }
}

pub static DEFAULT: Lazy<Board> = Lazy::new(|| {
    let default = interfaces()
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty())
        .cloned()
        .unwrap_or_else(|| abort(ScanError::MissingDefaultInterface));

    let mac = match default.mac {
        Some(addr) => addr,
        None => abort(ScanError::MissingMacAddr),
    };

    let ip = match default.ips.iter().find(|ip| ip.is_ipv4()) {
        Some(IpNetwork::V4(ipnet)) => ipnet.ip(),
        _ => abort(ScanError::OnlyIpv4InterfaceSupported),
    };

    log::debug!(
        "Using network interface `{}` with MAC address `{}` and IPv4 address `{}`",
        default.name,
        mac,
        ip
    );

    Board::new(mac, ip, default)
});

pub static GATEWAY: Lazy<MacAddr> = Lazy::new(|| match get_default_gateway() {
    Ok(gateway) => {
        let mac = gateway.mac_addr;

        log::debug!("Found gateway MAC address `{}`", mac);

        MacAddr::new(mac.0, mac.1, mac.2, mac.3, mac.4, mac.5)
    }
    Err(e) => abort(ScanError::GatewayLookupFailed(e)),
});
