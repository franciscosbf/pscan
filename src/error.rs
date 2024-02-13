use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("port `{0}` is invalid")]
    InvalidPort(String),
    #[error("failed to check target kind (ensure it's a domain or IPv4)")]
    HostParseFailed(#[source] url::ParseError),
    #[error("failed to resolve the given target: {0}")]
    ResolverFailed(#[source] std::io::Error),
    #[error("resolver didn't find any IPv4 address mapped by `{0}`")]
    DomainLookupFailed(String),
    #[error("you must run the scanner as sudo")]
    NormalUserRequired,
    #[error("no network interfaces available")]
    MissingDefaultInterface,
    #[error("failed to create socket: {0}")]
    DatalinkChannelFailed(#[source] std::io::Error),
    #[error("make sure the default network interface has an IPv4")]
    OnlyIpv4InterfaceSupported,
    #[error("only supports IPv4 addresses or domains that map addresses with this IP version")]
    OnlyIpv4TargetSupported,
    #[error("failed to get MAC address of gateway: {0}")]
    GatewayLookupFailed(String),
    #[error("failed to get MAC address")]
    MissingMacAddr,
    #[error("failed to send packet to `{0}`: {1}")]
    PacketSendFailed(IpAddr, #[source] std::io::Error),
    #[error("failed to receive packet to `{0}`: {1}")]
    PacketRecvFailed(IpAddr, #[source] std::io::Error),
}
