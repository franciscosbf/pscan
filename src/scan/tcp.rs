use std::{
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use super::{Executor, PortState};

const TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Debug)]
pub struct Scan;

impl Executor for Scan {
    fn scan(&self, addr: &SocketAddr) -> PortState {
        TcpStream::connect_timeout(addr, TIMEOUT).map_or(PortState::_Closed, |_| PortState::Open)
    }
}
