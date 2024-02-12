use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use pnet::{
    packet::{
        ip::IpNextHeaderProtocols,
        ipv4::{self, Ipv4Flags, MutableIpv4Packet},
        tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption},
        Packet,
    },
    transport::{ipv4_packet_iter, transport_channel, TransportChannelType},
};

use crate::{abort, error::ScanError, interface};

use super::{Executor, PortState};

const TRIALS: usize = 3;
const TCP_PKT_SZ: usize = 40;
const TCP_HDR_SZ: u8 = TCP_PKT_SZ as u8;
const TCP_HDR_WORDS: u8 = TCP_HDR_SZ / 4;
const IPV4_HDR_SZ: u8 = 20;
const IPV4_HDR_WORDS: u8 = IPV4_HDR_SZ / 4;
const IPV4_PKT_SZ: usize = IPV4_HDR_SZ as usize + TCP_PKT_SZ;
const IPV4_TTL: u8 = 64;

fn to_ipv4(ip: IpAddr) -> Ipv4Addr {
    match ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!(),
    }
}

#[derive(Debug)]
pub struct Scan;

impl Executor for Scan {
    fn scan(&self, addr: &SocketAddr) -> PortState {
        let (mut sender, mut receiver) = match transport_channel(
            4048,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        ) {
            Ok(pair) => pair,
            Err(e) => abort(ScanError::DatalinkChannelFailed(e)),
        };

        // Prepare SYN packet.

        let source_ip = to_ipv4(interface::DEFAULT.ips.first().unwrap().ip());
        let destination_ip = to_ipv4(addr.ip());

        // -> TCP packet.
        let mut raw_tcp_pckt = [0; TCP_PKT_SZ];
        let mut tcp_pckt = MutableTcpPacket::new(&mut raw_tcp_pckt).unwrap();
        tcp_pckt.set_source(rand::random());
        tcp_pckt.set_destination(addr.port());
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

        // -> IPv4 packet.
        let mut raw_ipv4_pckt = [0; IPV4_PKT_SZ];
        let mut ipv4_pckt = MutableIpv4Packet::new(&mut raw_ipv4_pckt).unwrap();
        ipv4_pckt.set_version(4);
        ipv4_pckt.set_header_length(IPV4_HDR_WORDS);
        ipv4_pckt.set_total_length(IPV4_PKT_SZ as u16);
        ipv4_pckt.set_identification(rand::random());
        ipv4_pckt.set_flags(Ipv4Flags::DontFragment);
        ipv4_pckt.set_ttl(IPV4_TTL);
        ipv4_pckt.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_pckt.set_source(source_ip);
        ipv4_pckt.set_destination(destination_ip);
        ipv4_pckt.set_checksum(ipv4::checksum(&ipv4_pckt.to_immutable()));
        ipv4_pckt.set_payload(tcp_pckt.packet());

        // Send SYN packet.
        if !(0..TRIALS).any(|_| sender.send_to(ipv4_pckt.to_immutable(), addr.ip()).is_ok()) {
            return PortState::_Closed;
        }

        // Evaluate result.
        let mut ipv4_pckts = ipv4_packet_iter(&mut receiver);
        loop {
            match ipv4_pckts.next() {
                Ok((_, IpAddr::V4(source))) if source == destination_ip => {
                    // TODO: evaluate TCP flag (check RST, SYN/ACK) and ip protocol type.
                    // Also don't forget to send a RST as response when SYN/ACK is received.
                    return PortState::Open;
                }
                Ok(_) => continue,
                Err(_) => return PortState::_Closed,
            };
        }
    }
}
