use crate::port::{Protocol, COMMON_PORTS};
use std::{
    fmt::{Debug, Display},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

mod syn;
mod tcp;
mod udp;

#[derive(Debug, PartialEq, Eq)]
pub enum PortState {
    Open,
    Unknown,
    _Closed, // Closed ports arent exposed.
}

impl Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PortState::Open => "open",
                PortState::Unknown => "unknown",
                PortState::_Closed => unreachable!(),
            }
        )
    }
}

trait Executor: Debug + Sync {
    fn scan(&self, addr: &SocketAddr) -> PortState;
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
            "{} scan",
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
            "tcp" => Self::new(&tcp::Scan, ScanType::Tcp),
            "syn" => Self::new(&syn::Scan, ScanType::Syn),
            "udp" => Self::new(&udp::Scan, ScanType::Udp),
            _ => unreachable!(),
        }
    }
}

pub enum Ports {
    All,
    Selected(Vec<u16>),
}

use Ports::*;

#[derive(Debug)]
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
    ip: IpAddr,
    ports: Ports,
    techniques: Vec<Technique>,
}

impl Scanner {
    pub fn new(ip: IpAddr, ports: Ports, techniques: Vec<Technique>) -> Self {
        Self {
            ip,
            ports,
            techniques,
        }
    }

    fn scan_port(&self, executor: &'static dyn Executor, port: u16) -> Option<PortState> {
        let addr = SocketAddr::new(self.ip, port);
        let state = executor.scan(&addr);
        if state == PortState::_Closed {
            return None;
        }
        Some(state)
    }

    fn scan_all(&self) -> Vec<PortResult> {
        use rayon::prelude::*;

        COMMON_PORTS
            .into_par_iter()
            .filter_map(|info| {
                self.techniques
                    .iter()
                    .find_map(|t| match (t.kind, info.protocol) {
                        (_, Protocol::Both)
                        | (ScanType::Syn | ScanType::Tcp, Protocol::Tcp)
                        | (ScanType::Udp, Protocol::Udp) => self
                            .scan_port(t.executor, info.port)
                            .map(|state| PortResult::new(info.port, state, t.kind)),
                        _ => None,
                    })
            })
            .collect()
    }

    fn scan_selected(&self, ports: &[u16]) -> Vec<PortResult> {
        ports
            .iter()
            .cloned()
            .filter_map(|port| {
                self.techniques.iter().find_map(|t| {
                    self.scan_port(t.executor, port)
                        .map(|state| PortResult::new(port, state, t.kind))
                })
            })
            .collect()
    }

    pub fn start(&self) -> ScanResult {
        let now = Instant::now();
        let ports = match self.ports {
            All => self.scan_all(),
            Selected(ref ports) => self.scan_selected(ports),
        };
        let elapsed = now.elapsed();

        ScanResult::new(elapsed, ports)
    }
}