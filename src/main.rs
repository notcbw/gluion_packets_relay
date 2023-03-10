// gluion_packets_relay: Program that relays the packets from
// the Gluions to the software bridge to bypass some problem
//
// Largely based on libpnet example {https://github.com/libpnet/libpnet/blob/master/examples/packetdump.rs}
//
// 2023-02 Bowen Cui <bowen.cui@mail.mcgill.ca>
extern crate pnet;

use pnet::datalink::{self, DataLinkSender, NetworkInterface};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{MutablePacket, Packet};

use std::env;
use std::io::{self, Write};
use std::process;

fn handle_ethernet_frame(
    tx_taps: &mut [Box<dyn DataLinkSender>],
    ethernet: &EthernetPacket,
    test: bool,
) {
    match ethernet.get_ethertype() {
        EtherTypes::Arp => {
            // forward all ARP packets to all taps without changing the MAC addresses
            for tx in tx_taps.iter_mut() {
                tx.build_and_send(1, ethernet.packet().len(), &mut |new_packet| {
                    // attempt to clone the old ethernet packet
                    let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();
                    new_packet.clone_from(ethernet);
                });
            }
        }
        EtherTypes::Ipv4 => {
            // For all IPv4 packets,
            // If the MAC address matches the gluion magic, pass the content to handle_ipv4_packet
            let src_octets = ethernet.get_source().octets();
            if test || (src_octets[0] == 0x05 && src_octets[1] == 0xe2 && src_octets[2] == 0x87) {
                // get the target machine by checking the IPv4 destination
                let ipv4_payload = Ipv4Packet::new(ethernet.payload());
                if let Some(ipv4_payload) = ipv4_payload {
                    let ipv4_octets = ipv4_payload.get_destination().octets();
                    // check if ip address is in the range of the mac minis
                    if ipv4_octets[0] == 192
                        && ipv4_octets[1] == 168
                        && ipv4_octets[2] == 5
                        && ipv4_octets[3] >= 81
                    {
                        // get machine number, then get the respective data link channel
                        let tap_num: usize = (ipv4_octets[3] - 81).into();

                        // relay the packet
                        match tx_taps[tap_num].build_and_send(1, ethernet.packet().len(), &mut |new_packet| {
                            // attempt to clone the old ethernet packet
                            let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();
                            new_packet.clone_from(ethernet);

                            // fix the source address
                            let mut src_mac = new_packet.get_source();
                            src_mac.0 &= 0xff;
                            new_packet.set_source(src_mac);
                        }) {
                            Some(n) => match n {
                                Ok(_) => println!(
                                    "Gluion packet relayed to {}!",
                                    ethernet.get_destination()
                                ),
                                Err(e) => println!(
                                    "Failed to relay gluion packet to {}: {}",
                                    ethernet.get_destination(),
                                    e.to_string()
                                ),
                            },
                            None => println!("New packet size error????"),
                        }
                    }
                } else {
                    println!("Invalid IPv4 payload detected.");
                }
            }
        }
        _ => {
            // do nothing for all other packet types
        }
    }
}

fn bad_argument() {
    writeln!(
        io::stderr(),
        "USAGE: glrelay <RX NETWORK INTERFACE> <TAP1>,<TAP2>,<TAP3>,<TAP4>,<TAP5>,<TAP6>"
    )
    .unwrap();
    write!(io::stderr(), "Available interfaces: ").unwrap();
    for interface in datalink::interfaces() {
        write!(io::stderr(), "{} ", interface.name).unwrap();
    }
    write!(io::stderr(), "\n").unwrap();
}

fn main() {
    use pnet::datalink::Channel::Ethernet;

    const TEST: bool = false;

    // get rx interface name from argument
    let rx_iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            bad_argument();
            process::exit(1);
        }
    };
    let rx_if_names_match = |rx_iface: &NetworkInterface| rx_iface.name == rx_iface_name;

    // get a list of comma separated list of tap devices. Use default tap1~6 if not found.
    let ni_taps: [NetworkInterface; 6] = match env::args().nth(2) {
        Some(n) => {
            let taps_names: Vec<&str> = n.split(",").collect();
            core::array::from_fn::<NetworkInterface, 6, _>(|i| {
                if let Some(tx_iface_name) = taps_names.get(i) {
                    let tx_iface_name = tx_iface_name.to_string();
                    let tx_if_names_match =
                        |tx_iface: &NetworkInterface| tx_iface.name == tx_iface_name;
                    let interfaces = datalink::interfaces();
                    let tx_interface = interfaces
                        .into_iter()
                        .filter(tx_if_names_match)
                        .next()
                        .unwrap_or_else(|| panic!("Cannot find {}! ", tx_iface_name));
                    return tx_interface;
                } else {
                    bad_argument();
                    panic!("Please enter exactly 6 tap interfaces separated by commas!");
                }
            })
        },
        None => {
            core::array::from_fn::<NetworkInterface, 6, _>(|i| {
                let tx_iface_name = format!("tap{:1}", i + 1);
                let tx_if_names_match =
                    |tx_iface: &NetworkInterface| tx_iface.name == tx_iface_name;
                let interfaces = datalink::interfaces();
                let tx_interface = interfaces
                    .into_iter()
                    .filter(tx_if_names_match)
                    .next()
                    .unwrap_or_else(|| panic!("Cannot find {}! ", tx_iface_name));
                return tx_interface;
            })
        },
    };

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let rx_interface = interfaces
        .into_iter()
        .filter(rx_if_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", rx_iface_name));

    // Create a data link channel to receive on
    let (_, mut rx) = match datalink::channel(&rx_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("unable to create RX data link channel: {}", e),
    };

    // put all NetworkInterface in an array for tap1~6
    // let ni_taps: [NetworkInterface; 6] = core::array::from_fn(|i| {
    //     let tx_iface_name = format!("tap{:1}", i + 1);
    //     let tx_if_names_match =
    //         |tx_iface: &NetworkInterface| tx_iface.name == tx_iface_name;
    //     let interfaces = datalink::interfaces();
    //     let tx_interface = interfaces
    //         .into_iter()
    //         .filter(tx_if_names_match)
    //         .next()
    //         .unwrap_or_else(|| panic!("Cannot find {}! ", tx_iface_name));
    //     return tx_interface;
    // });

    // Create an array of data link channel for all tap interfaces
    let mut tx_taps: [Box<dyn DataLinkSender>; 6] = core::array::from_fn(|i| {
        let (tx, _) = match datalink::channel(&ni_taps[i], Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("unhandled channel type"),
            Err(e) => panic!("unable to create TX data link channel: {}", e),
        };
        return tx;
    });

    // print some info
    println!("Relaying Gluion packets from {}", rx_interface.name);

    loop {
        match rx.next() {
            Ok(packet) => {
                // got new packet on the interface, try to process it
                handle_ethernet_frame(&mut tx_taps, &EthernetPacket::new(packet).unwrap(), TEST);
            }
            Err(e) => panic!("glrelay: failed to receive packet: {}", e),
        }
    }
}
