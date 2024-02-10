use std::net::SocketAddr;

use pnet::datalink::channel;

use crate::{abort, error::ScanError, interface};

use super::{Executor, PortState};

#[derive(Debug)]
pub struct Scan;

impl Executor for Scan {
    fn scan(&self, addr: &SocketAddr) -> PortState {
        use pnet::datalink::Channel::Ethernet;
        let (tx, rs) = match channel(&interface::DEFAULT, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            // INFO: make sure that ethernet is the only datalink channel available.
            Ok(_) => unreachable!(),
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
