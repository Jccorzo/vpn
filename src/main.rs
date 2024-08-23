use std::{
    io::{Read, Write},
    sync::Arc,
};

use pnet::packet::{
    ipv4::MutableIpv4Packet, ipv6::MutableIpv6Packet, Packet,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tun::platform::posix::{Reader, Writer};

const BUFFER_SIZE: usize = 1500;
const AF_INET: [u8; 4] = [0x00, 0x00, 0x00, 0x02];

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut config = tun::Configuration::default();
    config
        .name("tun0")
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .layer(tun::Layer::L3)
        .mtu(1500)
        .queues(2)
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let dev2 = tun::create(&config).expect("hah");

    let (reader, writer) = dev2.split();
    let reader = Arc::new(RwLock::new(reader));
    let writer = Arc::new(RwLock::new(writer));

    let listener = TcpListener::bind("0.0.0.0:7878")
        .await
        .expect("Error starting server");
    println!("Server is running on port 7878");

    loop {
        let (stream, _address) = listener.accept().await?;
        let reader = reader.clone();
        let writer = writer.clone();

        println!("Connection established!");
        tokio::spawn(async move {
            let (stream_r, stream_w) = tokio::io::split(stream);

            // handle_connection_with_nat(stream_r, device_clone).await;
            tokio::spawn(handle_connection_with_nat(stream_r, writer));
            tokio::spawn(handle_tun_with_nat(stream_w, reader));
        });
    }
}

async fn handle_connection_with_nat(
    mut stream: ReadHalf<TcpStream>,
    tun_writer: Arc<RwLock<Writer>>,
) {
    let mut buffer = [0; BUFFER_SIZE];

    loop {
        let mut packet = Vec::new();

        {
            loop {
                let n = match stream.read(&mut buffer).await {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Failed to read data from client: {}", e);
                        return;
                    }
                };
                if n == 0 {
                    println!("Client disconnected:");
                    return;
                }
                packet.extend_from_slice(&buffer[..n]);
                if n < BUFFER_SIZE {
                    // If less than buffer size is read, assume end of message
                    break;
                }
            }
        }

        if packet.is_empty() {
            continue;
        }

        /* println!();
        println!("Raw packet from client: {:?}", &packet);
        println!(); */

        // This Data is coming from a tun interface, so packets are either ipv4 or ipv6
        match packet[0] >> 4 {
            4 => {
                println!("IP 4 version from client");
                if let Some(mut_pack) = MutableIpv4Packet::new(&mut packet) {
                    println!(
                        "TCP IPV4 Source IP: {:?}",
                        mut_pack.get_source().to_string()
                    );
                    println!(
                        "TCP IPV4 Destination IP: {:?}",
                        mut_pack.get_destination().to_string()
                    );

                    // TODO: update this from locally getting public ip
                    //let source = Ipv4Addr::new(34, 44, 215, 250);
                    //mut_pack.set_source(source);
                    //mut_pack.set_checksum(pnet::packet::ipv4::checksum(&mut_pack.to_immutable()));

                    /* if mut_pack.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                        let packet = mut_pack.packet();
                        if let Some(mut tcp_packet) = MutableTcpPacket::new(&mut packet.to_owned()) {
                            // Recalculate the TCP checksum
                            tcp_packet.set_checksum(pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &mut_pack.get_destination(), &mut_pack.get_destination()));
                        }
                    } */

                    {
                        // write to tun
                        match tun_writer.write().await.write_all(
                            &[AF_INET.to_vec().to_owned(), mut_pack.packet().to_vec()].concat(),
                        ) {
                            Ok(_n) => {
                                println!("Data written to tun interface");
                            }
                            Err(err) => {
                                eprintln!("Failed to write data to tun interface: {}", err);
                                return;
                            }
                        }
                    }

                    println!()
                }
            }
            6 => {
                println!("IP 6 version from client");
                if let Some(mut_pack) = MutableIpv6Packet::new(&mut packet) {
                    println!(
                        "TCP IPV6 Source IP: {:?}",
                        mut_pack.get_source().to_string()
                    );
                    println!(
                        "TCP IPV6 Destination IP: {:?}",
                        mut_pack.get_destination().to_string()
                    );

                    /* let source = Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped();
                    mut_pack.set_source(source); */

                    {
                        // write to tun
                        match tun_writer.write().await.write_all(
                            &[AF_INET.to_vec().to_owned(), mut_pack.packet().to_vec()].concat(),
                        ) {
                            Ok(_n) => {
                                println!("Data written to tun interface");
                            }
                            Err(err) => {
                                eprintln!("Failed to write data to tun interface: {}", err);
                                return;
                            }
                        }
                    }
                }
            }
            _ => println!("Unknown IP version from client"),
        }
    }
}

async fn handle_tun_with_nat(mut stream: WriteHalf<TcpStream>, tun_reader: Arc<RwLock<Reader>>) {
    let mut buffer = [0; BUFFER_SIZE];

    loop {
        let mut packet = Vec::new();

        {
            loop {
                let n = match tun_reader.write().await.read(&mut buffer) {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Failed to read data: {}", e);
                        break;
                    }
                };
                if n == 0 {
                    println!("Client disconnected:");
                    break;
                }
                packet.extend_from_slice(&buffer[..n]);
                if n < BUFFER_SIZE {
                    // If less than buffer size is read, assume end of message
                    break;
                }
            }
        }

        if packet.is_empty() {
            continue;
        }

        /* println!();
        println!("Raw packet from tun: {:?}", packet);
        println!(); */

        let mut packet = packet[4..].to_vec();

        /* println!();
               println!("Raw packet from tun AFTER removing header: {:?}", packet);
               println!();
        */
        match packet[0] >> 4 {
            4 => {
                println!("IP 4 version from tun");
                if let Some(mut_pack) = MutableIpv4Packet::new(&mut buffer) {
                    println!(
                        "TUN IPV4 Source IP: {:?}",
                        mut_pack.get_source().to_string()
                    );
                    println!(
                        "TUN IPV4 Destination IP: {:?}",
                        mut_pack.get_destination().to_string()
                    );

                    //let destination = Ipv4Addr::new(10, 0, 0, 5);
                    //mut_pack.set_destination(destination);
                    //mut_pack.set_checksum(pnet::packet::ipv4::checksum(&mut_pack.to_immutable()));

                    // write to stream
                    {
                        match stream.write_all(&mut_pack.packet()).await {
                            Ok(_n) => {
                                println!("Data written to tcp client");
                            }
                            Err(err) => {
                                eprintln!("Failed to write data to tcp client: {}", err);
                                println!();
                            }
                        }
                    }
                }
            }
            6 => {
                println!("IP 6 version from tun");
                if let Some(mut_pack) = MutableIpv6Packet::new(&mut packet) {
                    println!(
                        "TCP IPV6 Source IP: {:?}",
                        mut_pack.get_source().to_string()
                    );
                    println!(
                        "TCP IPV6 Destination IP: {:?}",
                        mut_pack.get_destination().to_string()
                    );

                    // let source = Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped();
                    // mut_pack.set_destination(source);

                    {
                        match stream.write_all(&mut_pack.packet()).await {
                            Ok(_n) => {
                                println!("Data written to tcp client");
                            }
                            Err(err) => {
                                eprintln!("Failed to write data to tcp client: {}", err);
                                println!();
                            }
                        }
                    }
                }
            }
            _ => {
                println!("Unknown IP version from tun")
            }
        }

        println!("Packet from tun - client finished");
    }
}
