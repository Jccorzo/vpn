use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use pnet::packet::{ipv4::MutableIpv4Packet, ipv6::MutableIpv6Packet, Packet};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, RwLock},
};
use tun::AsyncDevice;

const BUFFER_SIZE: usize = 1500;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut config = tun::Configuration::default();
    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    /*     // Create channels for communication between client handlers and the TUN task
    let (tun_tx, mut tun_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);
    let (client_tx, mut client_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100); */

    let dev = tun::create_as_async(&config).expect("Error opening tun interface");

    /*let tun = Arc::new(dev);
     let tun_task = tokio::spawn (async move{
        let mut tun = tun.clone();
        let mut buf = [0; BUFFER_SIZE];


        loop {
            tokio::select! {
                /* tun_packet = tun.read(&mut buf).await => {
                    match tun_packet {
                        Ok(size) => {
                            //client_tx.send((buf[..size].to_vec(), SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 0)));
                        },
                        Err(e) => {
                            eprintln!("Failed to read from Tun: {}", e)
                        }
                    }
                } */

                // Receive packets from client handlers to send to TUN
                Some((packet, _client_addr)) = tun_rx.recv() => {
                    println!("TUN task received packet to send to TUN");
                    if let Err(e) = tun.write_all(&packet).await {
                        eprintln!("Failed to write packet to TUN: {}", e);
                    }
                }

            }
        }
    }); */

    let pointer_dev = Arc::new(RwLock::new(dev));

    let listener = TcpListener::bind("0.0.0.0:7878")
        .await
        .expect("Error starting server");
    println!("Server is running on port 7878");

    loop {
        let (stream, address) = listener.accept().await?;
        let device_clone = pointer_dev.clone();
        let device_clone2 = pointer_dev.clone();

        println!("Connection established!");
        tokio::spawn(async move {
            let (stream_r, stream_w) = tokio::io::split(stream);
            tokio::spawn(handle_connection_with_nat(stream_r, device_clone, address));
            tokio::spawn(handle_tun_with_nat(stream_w, device_clone2, address));
        });
    }
}

async fn handle_connection_with_nat(
    mut stream: ReadHalf<TcpStream>,
    tun: Arc<RwLock<AsyncDevice>>,
    client_ip: SocketAddr,
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

            if packet.is_empty() {
                continue;
            }
        }

        println!();
        println!("Raw packet from client: {:?}", packet);
        println!();

        // This Data is coming from a tun interface, so packets are either ipv4 or ipv6
        match packet[0] >> 4 {
            4 => {
                println!("IP 4 version from client");
                if let Some(mut mut_pack) = MutableIpv4Packet::new(&mut packet) {
                    println!(
                        "TCP IPV4 Source IP: {:?}",
                        mut_pack.get_source().to_string()
                    );
                    println!(
                        "TCP IPV4 Destination IP: {:?}",
                        mut_pack.get_destination().to_string()
                    );

                    // TODO: update this from locally getting public ip
                    let source = Ipv4Addr::new(34, 121, 29, 210);
                    mut_pack.set_source(source);
                    mut_pack.set_checksum(pnet::packet::ipv4::checksum(&mut_pack.to_immutable()));

                    let packet = mut_pack.packet();

                    println!();
                    println!("Raw Packet going to tun {:?}", packet);
                    println!();

                    {
                        // write to tun
                        match tun.write().await.write_all(packet).await {
                            Ok(_n) => {
                                println!("Data written to tun interface");
                            }
                            Err(err) => {
                                eprintln!("Failed to write data to tun interface: {}", err);
                                return;
                            }
                        }

                        println!("Packet from client - tun finished");
                    }
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

                    // write to stream
                    /* if let Err(e) = stream.write_all(mut_pack.packet()).await {
                        eprintln!("Failed to send data: {}", e);
                        break;
                    } else {
                        println!("ipv6 data sent");
                        println!();
                    } */
                }
            }
            _ => println!("Unknown IP version from client"),
        }
    }
}

async fn handle_tun_with_nat(
    mut stream: WriteHalf<TcpStream>,
    tun_reader: Arc<RwLock<AsyncDevice>>,
    client_ip: SocketAddr,
) {
    let mut buffer = [0; BUFFER_SIZE];
    
    loop {
        let mut packet = Vec::new();

        {
            loop {
                let n = match tun_reader.write().await.read(&mut buffer).await {
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

            if packet.is_empty() {
                continue;
            }
        }

        println!();
        println!("Raw packet from tun: {:?}", packet);
        println!();

        let ip_start = if buffer[0] == 0 && buffer[1] == 0 {
            2 // Skip the first 2 bytes (padding or extra data)
        } else {
            0 // IP packet starts at the first byte
        };

        match packet[ip_start] >> 4 {
            4 => {
                if let Some(mut mut_pack) = MutableIpv4Packet::new(&mut buffer) {
                    println!(
                        "TUN IPV4 Source IP: {:?}",
                        mut_pack.get_source().to_string()
                    );
                    println!(
                        "TUN IPV4 Destination IP: {:?}",
                        mut_pack.get_destination().to_string()
                    );

                    let source = Ipv4Addr::new(10, 0, 0, 5);
                    mut_pack.set_destination(source);
                    mut_pack.set_checksum(pnet::packet::ipv4::checksum(&mut_pack.to_immutable()));

                    // write to stream
                    if let Err(e) = stream.write_all(mut_pack.packet()).await {
                        eprintln!("Failed to send data to tcp client {}", e);
                    } else {
                        println!("ipv4 data sent to vpn client");
                        println!();
                    }

                    match stream.write_all(&mut_pack.packet()).await {
                        Ok(_n) => {
                            println!("Data written to tcp client");
                        }
                        Err(err) => {
                            eprintln!("Failed to write data to tcp client: {}", err);
                            return;
                        }
                    }

                    println!("Packet from tun - client finished");
                }
            }
            6 => {
                println!("IP 6 version from tun");
                if let Some(mut mut_pack) = MutableIpv6Packet::new(&mut packet) {
                    println!(
                        "TCP IPV6 Source IP: {:?}",
                        mut_pack.get_source().to_string()
                    );
                    println!(
                        "TCP IPV6 Destination IP: {:?}",
                        mut_pack.get_destination().to_string()
                    );

                    let source = Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped();
                    mut_pack.set_destination(source);

                    // write to tun
                    // read from tun
                    // write to stream

                    /* if let Err(e) = stream.write_all(mut_pack.packet()).await {
                        eprintln!("Failed to send data: {}", e);
                        break;
                    } else {
                        println!("ipv6 data sent");
                        println!();
                    } */
                }
            }
            _ => println!("Unknown IP version from tun"),
        }
    }
}
