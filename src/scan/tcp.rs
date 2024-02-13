use std::{
    net::{SocketAddr, SocketAddrV4, TcpStream},
    time::Duration,
};

use super::{Executor, PortState};

const TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Debug)]
pub struct Scan;

impl Executor for Scan {
    fn scan(&self, addr: &SocketAddrV4) -> PortState {
        TcpStream::connect_timeout(&SocketAddr::V4(*addr), TIMEOUT)
            .map_or(PortState::_Closed, |_| PortState::Open)
    }
}
