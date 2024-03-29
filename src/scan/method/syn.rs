use std::{
    fmt::Display,
    io::ErrorKind,
    net::{IpAddr, SocketAddrV4},
    time::{Duration, Instant},
};

use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    icmp::{destination_unreachable::IcmpCodes, IcmpCode, IcmpPacket, IcmpTypes},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket},
    Packet,
};

use crate::{
    abort,
    error::ScanError,
    scan::{channel, interface, pckt, Executor, PortState},
};

const SEND_ATTEMPTS: usize = 3;
const SEND_TIMOUT: Duration = Duration::from_millis(4000);

const TCP_PKT_SZ: usize = 40;
const TCP_HDR_SZ: u8 = TCP_PKT_SZ as u8;
const TCP_HDR_WORDS: u8 = TCP_HDR_SZ / 4;

const SYN_ACK: u8 = TcpFlags::SYN | TcpFlags::ACK;
const RST_ACK: u8 = TcpFlags::RST | TcpFlags::ACK;

const ICMP_TYPE_3_CODES: &[IcmpCode] = &[
    IcmpCodes::DestinationHostUnreachable,
    IcmpCodes::DestinationProtocolUnreachable,
    IcmpCodes::DestinationPortUnreachable,
    IcmpCodes::NetworkAdministrativelyProhibited,
    IcmpCodes::HostAdministrativelyProhibited,
    IcmpCodes::CommunicationAdministrativelyProhibited,
];

struct TcpKnownFlags(u8);

impl TcpKnownFlags {
    #[inline]
    fn syn_ack(&self) -> bool {
        self.0 == SYN_ACK
    }
}

impl Display for TcpKnownFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            SYN_ACK => write!(f, "SYN/ACK"),
            RST_ACK => write!(f, "RST/ACK"),
            unknown => write!(f, "{:#x}", unknown),
        }
    }
}

#[derive(Debug)]
pub struct SynScan;

impl Executor for SynScan {
    fn scan(&self, addr: &SocketAddrV4) -> PortState {
        let (mut sender, mut receiver) = channel::link();

        // Prepare SYN packet.

        let interface = &interface::DEFAULT;

        let source_ip = interface.ip();
        let source_port = rand::random();

        let destination_ip = *addr.ip();
        let destination_port = addr.port();

        // -> TCP packet.
        let mut raw_tcp_pckt = [0; TCP_PKT_SZ];
        let mut tcp_pckt = MutableTcpPacket::new(&mut raw_tcp_pckt).unwrap();
        tcp_pckt.set_source(source_port);
        tcp_pckt.set_destination(destination_port);
        tcp_pckt.set_data_offset(TCP_HDR_WORDS);
        tcp_pckt.set_flags(TcpFlags::SYN);
        tcp_pckt.set_window(u16::MAX);
        tcp_pckt.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);
        tcp_pckt.set_checksum(ipv4_checksum(
            &tcp_pckt.to_immutable(),
            &source_ip,
            &destination_ip,
        ));

        let ethernet_pckt = pckt::build(
            source_ip,
            destination_ip,
            IpNextHeaderProtocols::Tcp,
            tcp_pckt.packet(),
        );

        let mut trials = 0..SEND_ATTEMPTS;

        // The following algorithm is based on https://nmap.org/book/synscan.html

        loop {
            match sender.send_to(ethernet_pckt.packet(), None).unwrap() {
                Ok(_) => log::debug!("Sent `SYN` TCP packet to port `{}`", destination_port),
                Err(e) if e.kind() == ErrorKind::TimedOut => return PortState::Unknown,
                Err(e) => abort(ScanError::PacketSendFailed(IpAddr::V4(destination_ip), e)),
            };

            let timeout = Instant::now();

            'rcv_lp: loop {
                match receiver.next() {
                    Ok(raw) => 'ok_blk: {
                        let ethernet_pckt = EthernetPacket::new(raw).unwrap();
                        if ethernet_pckt.get_ethertype() != EtherTypes::Ipv4 {
                            break 'ok_blk;
                        }

                        let ipv4_pckt = Ipv4Packet::new(ethernet_pckt.payload()).unwrap();
                        if !(ipv4_pckt.get_destination() == source_ip
                            && ipv4_pckt.get_source() == destination_ip)
                        {
                            break 'ok_blk;
                        }

                        match ipv4_pckt.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                let tcp_pckt = TcpPacket::new(ipv4_pckt.payload()).unwrap();
                                if !(tcp_pckt.get_destination() == source_port
                                    && tcp_pckt.get_source() == destination_port)
                                {
                                    break 'ok_blk;
                                }

                                let tcp_flags = TcpKnownFlags(tcp_pckt.get_flags());

                                log::debug!(
                                    "Received `{}` TCP packet from port `{}`",
                                    tcp_flags,
                                    destination_port,
                                );

                                if tcp_flags.syn_ack() {
                                    return PortState::Open;
                                }

                                // RST flag means closed and everyone else.
                            }
                            IpNextHeaderProtocols::Icmp => {
                                let icmp_pckt = IcmpPacket::new(ipv4_pckt.payload()).unwrap();
                                let icmp_type = icmp_pckt.get_icmp_type();
                                let icmp_code = icmp_pckt.get_icmp_code();

                                log::debug!(
                                    "Received ICMP packet from port `{}` with type `{}` and code `{}`",
                                    destination_port,
                                    icmp_type.0,
                                    icmp_code.0
                                );

                                if icmp_type == IcmpTypes::DestinationUnreachable
                                    && ICMP_TYPE_3_CODES.contains(&icmp_code)
                                {
                                    return PortState::Filtered;
                                }
                            }
                            _ => (), // Assumes that's closed.
                        }

                        return PortState::_Closed; // Gives up.
                    }
                    Err(e) if e.kind() == ErrorKind::TimedOut => (),
                    Err(e) => abort(ScanError::PacketRecvFailed(IpAddr::V4(destination_ip), e)),
                }

                if timeout.elapsed() <= SEND_TIMOUT {
                    continue;
                }

                if trials.next().is_some() {
                    break 'rcv_lp; // Tries to resend SYN packet.
                }

                return PortState::Filtered;
            }
        }
    }
}
