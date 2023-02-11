// gluion_packets_relay: Program that relays the packets from
// the Gluions to the software bridge to bypass some problem
//
// Largely based on libpnet example {https://github.com/libpnet/libpnet/blob/master/examples/packetdump.rs}
//
// 2023-02 Bowen Cui <bowen.cui@mail.mcgill.ca>
extern crate pnet;

use pnet::datalink::{self, NetworkInterface};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use pnet::transport::{TransportSender, TransportChannelType, TransportProtocol};
//use pnet::util::MacAddr;

use std::env;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process;

fn handle_udp_packet(tx: &mut TransportSender, packet: &[u8], dest: IpAddr) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        let dest_port = udp.get_destination();
        match tx.send_to(udp, dest) {
            Ok(udpsize) => println!("Relayed a packet of size {} to {}:{}", udpsize, dest, dest_port),
            Err(e) => println!("Failed to relay packet: {}", e.to_string()),
        };

    } else {
        println!("Malformed UDP Packet");
    }
}

fn handle_ipv4_packet(tx: &mut TransportSender, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        if header.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
            return handle_udp_packet(tx, header.payload(), IpAddr::V4(header.get_destination()));
        }
    } else {
        println!("Malformed IPv4 Packet");
    }
}

fn handle_ethernet_frame(tx: &mut TransportSender, ethernet: &EthernetPacket, test: bool) {
    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
        // If the MAC address matches the gluion magic, pass the content to handle_ipv4_packet
        let src_octets = ethernet.get_source().octets();
        if test || (src_octets[0] == 0x05
            && src_octets[1] == 0xe2
            && src_octets[2] == 0x87) {
            return handle_ipv4_packet(tx, ethernet);
        }
    }
}

#[cfg(not(target_family = "unix"))]
fn main() {
    writeln!(io::stderr(), "Non *nix OSes are not supported!").unwrap();
    process::exit(1);
}

#[cfg(target_family = "unix")]
fn main() {
    use pnet::{datalink::Channel::Ethernet, transport};

    // get rx interface name from argument
    let rx_iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: glrelay <RX NETWORK INTERFACE>").unwrap();
            write!(io::stderr(), "Available interfaces: ").unwrap();
            for interface in datalink::interfaces() {
                write!(io::stderr(), "{} ", interface.name).unwrap();
            }
            write!(io::stderr(), "\n").unwrap();
            process::exit(1);
        }
    };
    let rx_if_names_match = |rx_iface: &NetworkInterface| rx_iface.name == rx_iface_name;

    // check test flag
    let test: bool = match env::args().nth(2) {
        Some(n) => if n.eq_ignore_ascii_case("test") { true } else { false },
        None => false,
    };
    if test { println!("Test mode enabled: MAC address filtering is disabled.") };

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let rx_interface = interfaces
        .into_iter()
        .filter(rx_if_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", rx_iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&rx_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("unable to create data link channel: {}", e),
    };

    // create a transport channel to send udp packets
    let (mut tx, _) = match transport::transport_channel(8192, 
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("Unable to create transport channel: {}", e),
    };

    // print some info
    println!("Monitoring {} for Gluion packets.", rx_interface.name);

    loop {
        //let mut buf: [u8; 1600] = [0u8; 1600];
        match rx.next() {
            Ok(packet) => {
                // got new packet on the interface, try to process it
                handle_ethernet_frame(&mut tx, &EthernetPacket::new(packet).unwrap(), test);
            }
            Err(e) => panic!("glrelay: unable to receive packet: {}", e),
        }
    }
}
