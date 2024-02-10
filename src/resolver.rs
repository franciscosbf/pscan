use std::net::IpAddr;
use std::net::ToSocketAddrs;

use url::Host;

use crate::error::ScanError;

pub fn lookup(target: &str) -> Result<IpAddr, ScanError> {
    let ip = match Host::parse(target).map_err(ScanError::HostParseFailed)? {
        Host::Domain(dmn) => (dmn, 0 /* dummy port */)
            .to_socket_addrs()
            .map_err(ScanError::ResolverFailed)?
            .next() // Tries to pick the first mapped address.
            .map(|saddr| saddr.ip())
            .ok_or(ScanError::NoMappedAddr(target.into()))?,
        Host::Ipv4(ip) => IpAddr::V4(ip),
        Host::Ipv6(_) => Err(ScanError::Ipv6NotSupported)?,
    };

    Ok(ip)
}
