use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("port `{0}` is invalid")]
    InvalidPort(String),
    #[error("failed to check target kind (ensure it's a domain, ipv4 or ipv6 address)")]
    HostParseFailed(#[source] url::ParseError),
    #[error("failed to resolve the given target: {0}")]
    ResolverFailed(#[source] std::io::Error),
    #[error("resolver didn't find any address mapped by `{0}`")]
    NoMappedAddr(String),
    #[error("you must run the scanner as sudo")]
    NormalUser,
    #[error("no network interfaces available")]
    MissingInterface,
    #[error("failed to create socket: {0}")]
    DatalinkChannelFailed(#[source] std::io::Error),
    #[error("IPv6 protocol isn't supported")]
    Ipv6NotSupported,
    #[error("failed to get MAC address of gateway: {0}")]
    GatewayFailed(String),
    #[error("failed to get MAC address")]
    MissingMacAddr,
}
