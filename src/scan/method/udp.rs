use std::net::SocketAddrV4;

use crate::scan::{Executor, PortState};

#[derive(Debug)]
pub struct UdpScan;

impl Executor for UdpScan {
    fn scan(&self, addr: &SocketAddrV4) -> PortState {
        let _ = addr;

        todo!()
    }
}
