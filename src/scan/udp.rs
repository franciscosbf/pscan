use std::net::SocketAddrV4;

use super::{Executor, PortState};

#[derive(Debug)]
pub struct Scan;

impl Executor for Scan {
    fn scan(&self, addr: &SocketAddrV4) -> PortState {
        let _ = addr;

        todo!()
    }
}
