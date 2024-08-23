use std::{io::{Read, Write}, thread, time::Duration};

extern crate tun;

fn main() {
	let mut config = tun::Configuration::default();
	config 
		   .address((10, 0, 0, 1))
	       .netmask((255, 255, 255, 0))
           .layer(tun::Layer::L3)
	       .up();

	#[cfg(target_os = "linux")]
	config.platform(|config| {
		config.packet_information(true);
	});

	let mut dev = tun::create(&config).unwrap();
	let mut buf = [0; 4096];

	println!("tun interface: {:?}", config);


	let packet: [u8; 40] = [
        // IP Header (20 bytes)
        0x45, 0x00, 0x00, 0x28, // Version, IHL, Type of Service, Total Length
        0x00, 0x00, 0x40, 0x00, // Identification, Flags, Fragment Offset
        0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Header Checksum
        0x0a, 0x00, 0x00, 0x01, // Source IP Address
        0x0a, 0x00, 0x00, 0x02, // Destination IP Address
        
        // TCP Header (20 bytes)
        0x00, 0x50, 0x00, 0x50, // Source Port, Destination Port
        0x00, 0x00, 0x00, 0x00, // Sequence Number
        0x00, 0x00, 0x00, 0x00, // Acknowledgment Number
        0x50, 0x02, 0x20, 0x00, // Data Offset, Flags, Window Size
        0x00, 0x00, 0x00, 0x00  // Checksum, Urgent Pointer
    ];

	let packet2 = [69, 0, 0, 64, 0, 0, 64, 0, 64, 6, 245, 87, 10, 0, 0, 5, 163, 70, 152, 21, 201, 143, 1, 187, 78, 208, 107, 60, 0, 0, 0, 0, 176, 194, 255, 255, 57, 81, 0, 0, 2, 4, 5, 180, 1, 3, 3, 6, 1, 1, 8, 10, 48, 89, 1, 218, 0, 0, 0, 0, 4, 2, 0, 0];

	let af_inet: u32 = libc::AF_INET as u32;
	let mut packet3: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0xf5, 0x57, 0x0a, 0x00, 0x00, 0x05,
        0xa3, 0x46, 0x98, 0x15, 0xc9, 0x8f, 0x01, 0xbb,
        0x4e, 0xd0, 0x6b, 0x3c, 0x00, 0x00, 0x00, 0x00,
        0xb0, 0xc2, 0xff, 0xff, 0x39, 0x51, 0x00, 0x00,
        0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x06,
        0x01, 0x01, 0x08, 0x0a, 0x30, 0x59, 0x01, 0xda,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00
    ];

	match packet3[0] >> 4 {
		4 => {
			println!("IPV4")
		}
		6 => {
			println!("IPV6")
		}
		
		_ => {
			println!("uknotwn protocol")
		}
	}

    // Prefix packet with address family (AF_INET)
    let mut prefixed_packet = af_inet.to_be_bytes().to_vec();
    prefixed_packet.append(&mut packet3);

	match prefixed_packet[0] >> 4 {
		4 => {
			println!("IPV4")
		}
		6 => {
			println!("IPV6")
		}
		
		_ => {
			println!("uknotwn protocol")
		}
	}
	loop {
		dev.write_all(&mut prefixed_packet.to_vec()).unwrap();
		println!("Sent");
		thread::sleep(Duration::from_secs(5));
	}
}