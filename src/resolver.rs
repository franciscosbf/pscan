use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use url::Host;

use crate::error::ScanError;

pub fn lookup(target: &str) -> Result<Ipv4Addr, ScanError> {
    let ip = match Host::parse(target).map_err(ScanError::HostParseFailed)? {
        Host::Domain(dmn) => (dmn, 0 /* dummy port */)
            .to_socket_addrs()
            .map_err(ScanError::ResolverFailed)?
            .find_map(|saddr| match saddr {
                SocketAddr::V4(sip) => {
                    let ip = *sip.ip();

                    log::debug!("Found IPv4 `{}` mapped by target `{}`", ip, target);

                    Some(ip)
                }
                SocketAddr::V6(_) => None,
            })
            .ok_or(ScanError::DomainLookupFailed(target.into()))?,
        Host::Ipv4(ip) => ip,
        Host::Ipv6(_) => Err(ScanError::OnlyIpv4TargetSupported)?,
    };

    Ok(ip)
}
