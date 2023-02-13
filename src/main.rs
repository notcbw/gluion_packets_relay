// gluion_packets_relay: Program that relays the packets from
// the Gluions to the software bridge to bypass some problem
//
// Largely based on libpnet example {https://github.com/libpnet/libpnet/blob/master/examples/packetdump.rs}
//
// 2023-02 Bowen Cui <bowen.cui@mail.mcgill.ca>
extern crate pnet;

use pnet::datalink::{self, NetworkInterface, DataLinkSender};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{Packet, MutablePacket};

use std::env;
use std::io::{self, Write};
use std::process;

fn handle_ipv4_packet(tx: &mut Box<dyn DataLinkSender>, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        // if packet is udp, fix the source address of the ethernet packet then relay.
        if header.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
            tx.build_and_send(1, ethernet.packet().len(), 
                &mut |new_packet| {
                    // attempt to clone the old ethernet packet
                    let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();
                    new_packet.clone_from(ethernet);

                    // fix the source address
                    let mut src_mac = new_packet.get_source();
                    src_mac.0 &= 0xfe;
                    new_packet.set_source(src_mac);
                });
        }
    } else {
        println!("Malformed IPv4 Packet");
    }
}

fn handle_ethernet_frame(tx: &mut Box<dyn DataLinkSender>, ethernet: &EthernetPacket, test: bool) {
    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
        // If the MAC address matches the gluion magic, pass the content to handle_ipv4_packet
        let src_octets = ethernet.get_source().octets();
        if test || (src_octets[0] == 0x05
            && src_octets[1] == 0xe2
            && src_octets[2] == 0x87) {
            handle_ipv4_packet(tx, ethernet);
        }
    }
}

fn bad_argument() {
    writeln!(io::stderr(), "USAGE: glrelay <RX NETWORK INTERFACE> <TX NETWORK INTERFACE>").unwrap();
    write!(io::stderr(), "Available interfaces: ").unwrap();
    for interface in datalink::interfaces() {
        write!(io::stderr(), "{} ", interface.name).unwrap();
    }
    write!(io::stderr(), "\n").unwrap();
}

#[cfg(not(target_family = "unix"))]
fn main() {
    writeln!(io::stderr(), "Non *nix OSes are not supported!").unwrap();
    process::exit(1);
}

#[cfg(target_family = "unix")]
fn main() {
    use pnet::{datalink::Channel::Ethernet};

    // get rx interface name from argument
    let rx_iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            bad_argument();
            process::exit(1);
        }
    };
    let rx_if_names_match = |rx_iface: &NetworkInterface| rx_iface.name == rx_iface_name;

    // get tx interface name from argument
    let tx_iface_name = match env::args().nth(2) {
        Some(n) => n,
        None => {
            bad_argument();
            process::exit(1);
        }
    };
    let tx_if_names_match = |tx_iface: &NetworkInterface| tx_iface.name == tx_iface_name;

    // check test flag
    let test: bool = match env::args().nth(3) {
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

    let interfaces = datalink::interfaces();
    let tx_interface = interfaces
        .into_iter()
        .filter(tx_if_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", tx_iface_name));

    // Create a data link channel to receive on
    let (_, mut rx) = match datalink::channel(&rx_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("unable to create RX data link channel: {}", e),
    };

    // Create a data link channel to transmit
    let (mut tx, _) = match datalink::channel(&tx_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("unable to create TX data link channel: {}", e),
    };

    // print some info
    println!("Relaying Gluion packets from {} to {}", rx_interface.name, tx_interface.name);

    loop {
        match rx.next() {
            Ok(packet) => {
                // got new packet on the interface, try to process it
                handle_ethernet_frame(&mut tx, &EthernetPacket::new(packet).unwrap(), test);
            }
            Err(e) => panic!("glrelay: failed to receive packet: {}", e),
        }
    }
}
