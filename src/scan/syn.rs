use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use once_cell::sync::Lazy;
use pnet::{
    datalink::{channel, Channel, Config},
    packet::{
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        icmp::{destination_unreachable::IcmpCodes, IcmpCode, IcmpPacket, IcmpTypes},
        ip::IpNextHeaderProtocols,
        ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
        tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket},
        Packet,
    },
};

use crate::{abort, error::ScanError, interface};

use super::{Executor, PortState};

const SEND_TRIALS: usize = 3;
const SEND_TIMOOUT: Duration = Duration::from_millis(4000);

const TCP_PKT_SZ: usize = 40;
const TCP_HDR_SZ: u8 = TCP_PKT_SZ as u8;
const TCP_HDR_WORDS: u8 = TCP_HDR_SZ / 4;

const IPV4_HDR_SZ: u8 = 20;
const IPV4_HDR_WORDS: u8 = IPV4_HDR_SZ / 4;
const IPV4_PKT_SZ: usize = IPV4_HDR_SZ as usize + TCP_PKT_SZ;
const IPV4_TTL: u8 = 64;

const ETHERNET_PKT_SZ: usize = 14 + IPV4_PKT_SZ;

const SYN_ACK: u8 = TcpFlags::SYN | TcpFlags::ACK;

const ICMP_TYPE_3_CODES: &[IcmpCode] = &[
    IcmpCodes::DestinationHostUnreachable,
    IcmpCodes::DestinationProtocolUnreachable,
    IcmpCodes::DestinationPortUnreachable,
    IcmpCodes::NetworkAdministrativelyProhibited,
    IcmpCodes::HostAdministrativelyProhibited,
    IcmpCodes::CommunicationAdministrativelyProhibited,
];

const CHANNEL_RW_TIMEOUT: Duration = Duration::from_millis(3000);

static CHANNEL_CONFIG: Lazy<Config> = Lazy::new(|| Config {
    read_timeout: Some(CHANNEL_RW_TIMEOUT),
    write_timeout: Some(CHANNEL_RW_TIMEOUT),
    ..Default::default()
});

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
        let interface = &interface::DEFAULT;
        let gateway_mac = *interface::GATEWAY;
        let config = *CHANNEL_CONFIG;

        let (mut sender, mut receiver) = match channel(interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => unreachable!(),
            Err(e) => abort(ScanError::DatalinkChannelFailed(e)),
        };

        // Prepare SYN packet.

        let source_ip = to_ipv4(interface.ips.first().unwrap().ip());
        let source_port = rand::random();
        let destination_ip = to_ipv4(addr.ip());
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

        // -> Ethernet packet.
        let mut raw_ethernet_pckt = [0; ETHERNET_PKT_SZ];
        let mut ethernet_pckt = MutableEthernetPacket::new(&mut raw_ethernet_pckt).unwrap();
        ethernet_pckt.set_ethertype(EtherTypes::Ipv4);
        ethernet_pckt.set_source(interface.mac.unwrap());
        ethernet_pckt.set_destination(gateway_mac);
        ethernet_pckt.set_payload(ipv4_pckt.packet());

        let mut send_syn = || {
            sender
                .send_to(ethernet_pckt.packet(), None)
                .unwrap()
                .is_ok()
        };

        send_syn();

        let mut trials = 0..SEND_TRIALS;
        let timeout = Instant::now();

        while let Ok(raw) = receiver.next() {
            if timeout.elapsed() > SEND_TIMOOUT {
                if trials.next().is_none() {
                    return PortState::Filtered;
                }
                send_syn();
            }

            let ethernet_pckt = EthernetPacket::new(raw).unwrap();
            if ethernet_pckt.get_ethertype() != EtherTypes::Ipv4 {
                continue;
            }

            let ipv4_pckt = Ipv4Packet::new(ethernet_pckt.payload()).unwrap();
            if !(ipv4_pckt.get_destination() == source_ip
                && ipv4_pckt.get_source() == destination_ip)
            {
                continue;
            }

            match ipv4_pckt.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_pckt = TcpPacket::new(ipv4_pckt.payload()).unwrap();
                    if !(tcp_pckt.get_destination() == source_port
                        && tcp_pckt.get_source() == destination_port)
                    {
                        continue;
                    } else if tcp_pckt.get_flags() == SYN_ACK {
                        return PortState::Open;
                    }

                    // RST flag means closed.
                }
                IpNextHeaderProtocols::Icmp => {
                    let icmp_pckt = IcmpPacket::new(ipv4_pckt.payload()).unwrap();
                    if icmp_pckt.get_icmp_type() == IcmpTypes::DestinationUnreachable
                        && ICMP_TYPE_3_CODES.contains(&icmp_pckt.get_icmp_code())
                    {
                        return PortState::Filtered;
                    }
                }
                _ => (), // Assumes that's closed.
            }

            break;
        }

        PortState::_Closed
    }
}
