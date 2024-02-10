use std::net::SocketAddr;

use super::{Executor, PortState};

#[derive(Debug)]
pub struct Scan;

impl Executor for Scan {
    fn scan(&self, addr: &SocketAddr) -> PortState {
        let _ = addr;

        todo!()
    }
}
