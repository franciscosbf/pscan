use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Port `{0}` is invalid")]
    InvalidPort(String),
    #[error("Failed to check target kind (ensure it's a domain or IPv4). Origin: {0}")]
    HostParseFailed(#[source] url::ParseError),
    #[error("Failed to resolve the given target. Origin: {0}")]
    ResolverFailed(#[source] std::io::Error),
    #[error("Resolver didn't find any IPv4 address mapped by. Origin: `{0}`")]
    DomainLookupFailed(String),
    #[error("You must run the scanner as sudo")]
    NormalUserRequired,
    #[error("No network interfaces available")]
    MissingDefaultInterface,
    #[error("Failed to create socket. Origin: {0}")]
    DatalinkChannelFailed(#[source] std::io::Error),
    #[error("Make sure the default network interface has an IPv4")]
    OnlyIpv4InterfaceSupported,
    #[error("Only supports IPv4 addresses or domains that map addresses with this IP version")]
    OnlyIpv4TargetSupported,
    #[error("Failed to get MAC address of gateway. Origin: {0}")]
    GatewayLookupFailed(String),
    #[error("Failed to get MAC address")]
    MissingMacAddr,
    #[error("Failed to send packet to `{0}`. Origin: {1}")]
    PacketSendFailed(IpAddr, #[source] std::io::Error),
    #[error("Failed to receive packet to `{0}`. Origin: {1}")]
    PacketRecvFailed(IpAddr, #[source] std::io::Error),
}
