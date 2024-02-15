use std::net::Ipv4Addr;

use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::IpNextHeaderProtocol,
    ipv4::{self, Ipv4Flags, MutableIpv4Packet},
    Packet,
};

use crate::scan::interface;

const IPV4_HDR_SZ: u8 = 20;
const IPV4_HDR_WORDS: u8 = IPV4_HDR_SZ / 4;
const IPV4_TTL: u8 = 64;

const ETHERNET_HDR_SZ: usize = 14;

pub fn build(
    src: Ipv4Addr,
    dest: Ipv4Addr,
    next_level_proto: IpNextHeaderProtocol,
    raw_packet: &[u8],
) -> EthernetPacket {
    let interface = &interface::DEFAULT;
    let gateway = *interface::GATEWAY;

    // -> IPv4 packet.
    let ipv4_pckt_sz = IPV4_HDR_SZ as usize + raw_packet.len();
    let raw_ipv4_pckt = vec![0; ipv4_pckt_sz];
    let mut ipv4_pckt = MutableIpv4Packet::owned(raw_ipv4_pckt).unwrap();
    ipv4_pckt.set_version(4);
    ipv4_pckt.set_header_length(IPV4_HDR_WORDS);
    ipv4_pckt.set_total_length(ipv4_pckt_sz as u16);
    ipv4_pckt.set_identification(rand::random());
    ipv4_pckt.set_flags(Ipv4Flags::DontFragment);
    ipv4_pckt.set_ttl(IPV4_TTL);
    ipv4_pckt.set_next_level_protocol(next_level_proto);
    ipv4_pckt.set_source(src);
    ipv4_pckt.set_destination(dest);
    ipv4_pckt.set_checksum(ipv4::checksum(&ipv4_pckt.to_immutable()));
    ipv4_pckt.set_payload(raw_packet);

    // -> Ethernet packet.
    let ethernet_pckt_sz = ETHERNET_HDR_SZ + ipv4_pckt_sz;
    let raw_ethernet_pckt = vec![0; ethernet_pckt_sz];
    let mut ethernet_pckt = MutableEthernetPacket::owned(raw_ethernet_pckt).unwrap();
    ethernet_pckt.set_ethertype(EtherTypes::Ipv4);
    ethernet_pckt.set_source(interface.mac());
    ethernet_pckt.set_destination(gateway);
    ethernet_pckt.set_payload(ipv4_pckt.packet());

    ethernet_pckt.consume_to_immutable()
}
