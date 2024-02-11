use std::{net::SocketAddr, time::Duration};

use once_cell::sync::Lazy;
use pnet::datalink::{channel, ChannelType, Config};

use crate::{abort, error::ScanError, interface};

use super::{Executor, PortState};

const TIMEOUT: Duration = Duration::from_millis(1500);

static CONFIG: Lazy<Config> = Lazy::new(|| Config {
    read_timeout: TIMEOUT.into(),
    write_timeout: TIMEOUT.into(),
    channel_type: ChannelType::Layer2, // Default type, but I want to make sure.
    ..Default::default()
});

#[derive(Debug)]
pub struct Scan;

impl Executor for Scan {
    fn scan(&self, addr: &SocketAddr) -> PortState {
        use pnet::datalink::Channel::Ethernet;
        let (tx, rs) = match channel(&interface::DEFAULT, *CONFIG) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            // INFO: make sure that ethernet is the only datalink channel available.
            Ok(_) => unreachable!(), // This wont happen in the current pnet version.
            Err(e) => abort(ScanError::DatalinkChannelFailed(e)),
        };

        let ip = addr.ip();
        let port = addr.port();

        let _ = tx;
        let _ = rs;
        let _ = ip;
        let _ = port;

        todo!()
    }
}
