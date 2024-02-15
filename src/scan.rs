use std::{
    fmt::{Debug, Display},
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};

use rayon::prelude::{IntoParallelIterator, ParallelIterator};

use self::{
    method::{SynScan, TcpScan},
    port::COMMON_PORTS,
};

mod channel;
mod interface;
mod method;
mod pckt;
mod port;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Filtered,
    Unknown,
    _Closed, // Closed ports aren't exposed.
}

impl Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PortState::Open => "open",
                PortState::Filtered => "filtered",
                PortState::Unknown => "unknown",
                PortState::_Closed => unreachable!(),
            }
        )
    }
}

trait Executor: Debug + Sync {
    fn scan(&self, addr: &SocketAddrV4) -> PortState;
}

#[derive(Debug, Clone, Copy)]
pub enum ScanType {
    Tcp,
    Syn,
    Udp,
}

impl Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ScanType::Tcp => "TCP",
                ScanType::Syn => "TCP SYN",
                ScanType::Udp => "UDP",
            }
        )
    }
}

#[derive(Debug)]
pub struct Technique {
    executor: &'static dyn Executor,
    pub kind: ScanType,
}

impl Technique {
    fn new(executor: &'static dyn Executor, kind: ScanType) -> Self {
        Self { executor, kind }
    }

    pub fn from(raw: &str) -> Technique {
        match raw {
            "tcp" => Self::new(&TcpScan, ScanType::Tcp),
            "syn" => Self::new(&SynScan, ScanType::Syn),
            _ => unreachable!(),
        }
    }
}

pub enum PortsToScan {
    All,
    Selected(Vec<u16>),
}

#[derive(Debug, Clone, Copy)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub kind: ScanType,
}

impl PortResult {
    fn new(port: u16, state: PortState, kind: ScanType) -> Self {
        Self { port, state, kind }
    }
}

#[derive(Debug)]
pub struct ScanResult {
    pub elapsed: Duration,
    pub ports: Vec<PortResult>,
}

impl ScanResult {
    #[inline]
    fn new(elapsed: Duration, ports: Vec<PortResult>) -> Self {
        Self { elapsed, ports }
    }
}

pub struct Scanner {
    ip: Ipv4Addr,
    ports: PortsToScan,
    techniques: Vec<Technique>,
}

impl Scanner {
    pub fn new(ip: Ipv4Addr, ports: PortsToScan, techniques: Vec<Technique>) -> Self {
        Self {
            ip,
            ports,
            techniques,
        }
    }

    fn scan_port(&self, executor: &'static dyn Executor, port: u16) -> Option<PortState> {
        let addr = SocketAddrV4::new(self.ip, port);
        let state = executor.scan(&addr);
        if state == PortState::_Closed {
            return None;
        }
        Some(state)
    }

    fn scan_all(&self) -> rayon::slice::Iter<'_, u16> {
        COMMON_PORTS.into_par_iter()
    }

    fn scan_selected<'a>(&self, ports: &'a [u16]) -> rayon::slice::Iter<'a, u16> {
        ports.into_par_iter()
    }

    pub fn start(&self) -> ScanResult {
        let iter = match self.ports {
            PortsToScan::All => self.scan_all(),
            PortsToScan::Selected(ref ports) => self.scan_selected(ports),
        }
        .filter_map(|&port| {
            self.techniques.iter().find_map(|t| {
                self.scan_port(t.executor, port)
                    .map(|state| PortResult::new(port, state, t.kind))
            })
        });

        let now = Instant::now();
        let ports = iter.collect();
        let elapsed = now.elapsed();

        ScanResult::new(elapsed, ports)
    }
}
