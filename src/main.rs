use std::io;
use std::collections::HashMap;
use std::net::Ipv4Addr;

mod tcp;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
	src: (Ipv4Addr, u16), // (<ip_addr>, <port>)
	dst: (Ipv4Addr, u16),
}


fn main() -> io::Result<()> {
	let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
	let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
	let mut buf = [0u8; 1504];
	loop {
		let nbytes = nic.recv(&mut buf[..])?;
		// let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
		// let eth_protocol = u16::from_be_bytes([buf[2], buf[3]]);
		// if eth_protocol != 0x0800 { //ignore packets that are not ipv4
        //         continue;
		// }

		match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
			Ok(iph) => {
				let src = iph.source_addr();
				let dst = iph.destination_addr();
				let protocol = iph.protocol();
				if protocol != 0x06 {
					// ignore packets that are not TCP
					continue;
				}
 
				match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..]) {
					Ok(tcph) => {
						use std::collections::hash_map::Entry;
						let datai = iph.slice().len() + tcph.slice().len();
						match connections.entry(Quad{
							src: (src, tcph.source_port()),
							dst: (dst, tcph.destination_port()),
						}) {
							Entry::Occupied(mut c) => {
								c.get_mut()
									.on_packet(&mut nic, iph, tcph, &buf[datai..nbytes])?;
							}
							Entry::Vacant(mut e) => {
								if let Some(c) = tcp::Connection::accept(
									&mut nic,
									iph, 
									tcph, 
									&buf[datai..nbytes]
								)? {
									e.insert(c);
								}
							}
						}
					}
					Err(e) => {
						eprintln!("Ignoring weird tcp packet {:?}", e);
					}
				}
			},
			Err(e) => {
				// eprintln!("ignoring weird packet {:?}", e);
			}
		}
	}
}
