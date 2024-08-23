use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use pnet::packet::{ipv4::MutableIpv4Packet, ipv6::MutableIpv6Packet, Packet};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf}, net::{TcpListener, TcpStream}, select, sync::{mpsc, RwLock}
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

    // Create channels for communication between client handlers and the TUN task
    let (tun_tx, mut tun_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);
    let (client_tx, mut client_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);

    let client_rx = Arc::new(client_rx);

    let dev = tun::create_as_async(&config).expect("Error opening tun interface");


    let tun = Arc::new(RwLock::new(dev));
    /* let tun_task = tokio::spawn(async move {
        let mut tun = tun.clone();
        let mut buf = [0; BUFFER_SIZE];

        loop {
            tokio::select! {

                //tun_packet = tun.read()

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
                    {
                        if let Err(e) = tun.write().await.write_all(&packet).await {
                            eprintln!("Failed to write packet to TUN: {}", e);
                        }
                    }
                }

            }
        }
    }); */

    let listener = TcpListener::bind("0.0.0.0:7878")
        .await
        .expect("Error starting server");
    println!("Server is running on port 7878");

    loop {
        let (stream, address) = listener.accept().await?;
        //let tun_tx = tun_tx.clone();
        //let client_rx = client_rx.clone();
        let device_clone = tun.clone();
        let device_clone2 = tun.clone();

        println!("Connection established!");
        tokio::spawn(async move {
            let (stream_r, stream_w) = tokio::io::split(stream);

            handle_connection_with_nat(stream_r, device_clone).await;
            // tokio::spawn(handle_connection_with_nat(stream_r, device_clone));
            // tokio::spawn(handle_tun_with_nat(stream_w, device_clone2));
        });
    }
}

async fn handle_connection_with_nat(
    mut stream: ReadHalf<TcpStream>,
    tun: Arc<RwLock<AsyncDevice>>
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

        match tun.write().await.write_all(&packet).await {
            Ok(_n) => {
                println!("Data written to tun interface");
                tun.write().await.flush();
            }
            Err(err) => {
                eprintln!("Failed to write data to tun interface: {}", err);
                return;
            }
        }

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
/*                     let source = Ipv4Addr::new(34, 121, 29, 210);
                    mut_pack.set_source(source);
                    mut_pack.set_checksum(pnet::packet::ipv4::checksum(&mut_pack.to_immutable())); */

                    // let packet = ;

                    println!();
                    println!("Raw Packet going to tun {:?}", mut_pack.packet());
                    println!();

                    {
                        // write to tun
                        

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
    tun_reader: Arc<RwLock<AsyncDevice>>
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
                    match stream.write_all(&mut_pack.packet()).await {
                        Ok(_n) => {
                            println!("Data written to tcp client");
                        }
                        Err(err) => {
                            eprintln!("Failed to write data to tcp client: {}", err);
                            println!();
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


/* async fn handle_connection_and_tun(
    mut stream_r: ReadHalf<TcpStream>,
    mut stream_w: WriteHalf<TcpStream>,
    tun: Arc<RwLock<AsyncDevice>>,
) {
    let mut buffer = [0; BUFFER_SIZE];
    let mut buffer_2 = [0; BUFFER_SIZE];

    let mut packet_from_client = Vec::new();
    let mut packet_from_tun = Vec::new();

    loop {

        let read_from_tun = tun.write().await.read(&mut buffer_2);
        select! {
            // Handling incoming data from the TCP stream (client)
            result = stream_r.read(&mut buffer) => {
                match result {
                    Ok(n) => {
                        if n > 0 {
                            packet_from_client.extend_from_slice(&buffer[..n]);
                            if n < BUFFER_SIZE {
                                // If less than buffer size is read, assume end of message
                                println!();
                                println!("Raw packet from client: {:?}", packet_from_client);
                                println!();
    
                                match packet_from_client[0] >> 4 {
                                    4 => {
                                        if let Some(mut mut_pack) = MutableIpv4Packet::new(&mut packet_from_client) {
                                            println!(
                                                "TCP IPV4 Source IP: {:?}",
                                                mut_pack.get_source().to_string()
                                            );
                                            println!(
                                                "TCP IPV4 Destination IP: {:?}",
                                                mut_pack.get_destination().to_string()
                                            );
    
                                            let source = Ipv4Addr::new(34, 121, 29, 210);
                                            mut_pack.set_source(source);
                                            mut_pack.set_checksum(pnet::packet::ipv4::checksum(&mut_pack.to_immutable()));
    
                                            let packet = mut_pack.packet();
    
                                            println!();
                                            println!("Raw Packet going to tun {:?}", packet);
                                            println!();
    
                                            // Write to TUN
                                            if let Err(e) = tun.write().await.write_all(packet).await {
                                                eprintln!("Failed to write data to tun interface: {}", e);
                                            }
                                            println!("Packet from client - tun finished");
                                        }
                                    }
                                    6 => {
                                        println!("IP 6 version from client");
                                        if let Some(mut_pack) = MutableIpv6Packet::new(&mut packet_from_client) {
                                            println!(
                                                "TCP IPV6 Source IP: {:?}",
                                                mut_pack.get_source().to_string()
                                            );
                                            println!(
                                                "TCP IPV6 Destination IP: {:?}",
                                                mut_pack.get_destination().to_string()
                                            );
                                            // Handle IPv6 packet as needed
                                        }
                                    }
                                    _ => println!("Unknown IP version from client"),
                                }
                                packet_from_client.clear();
                            }
                        }
                        
                    },
                    Err(e) => {
                        eprintln!("Failed to read data from client: {}", e);
                        break;
                    }
                }
            }

            // Handling incoming data from the TUN interface
            result = read_from_tun => {
                match result {
                    Ok(n) => {
                        if n > 0 {}
                        packet_from_tun.extend_from_slice(&buffer_2[..n]);
                        if n < BUFFER_SIZE {
                            // If less than buffer size is read, assume end of message
                            println!();
                            println!("Raw packet from tun: {:?}", packet_from_tun);
                            println!();

                            let ip_start = if buffer_2[0] == 0 && buffer_2[1] == 0 {
                                2 // Skip the first 2 bytes (padding or extra data)
                            } else {
                                0 // IP packet starts at the first byte
                            };

                            match packet_from_tun[ip_start] >> 4 {
                                4 => {
                                    if let Some(mut mut_pack) = MutableIpv4Packet::new(&mut buffer_2) {
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

                                        // Write to TCP stream
                                        if let Err(e) = stream_w.write_all(&mut_pack.packet()).await {
                                            eprintln!("Failed to write data to TCP client: {}", e);
                                        }
                                        println!("Packet from tun - client finished");
                                    }
                                }
                                6 => {
                                    println!("IP 6 version from tun");
                                    if let Some(mut_pack) = MutableIpv6Packet::new(&mut packet_from_tun) {
                                        println!(
                                            "TCP IPV6 Source IP: {:?}",
                                            mut_pack.get_source().to_string()
                                        );
                                        println!(
                                            "TCP IPV6 Destination IP: {:?}",
                                            mut_pack.get_destination().to_string()
                                        );
                                        // Handle IPv6 packet as needed
                                    }
                                }
                                _ => println!("Unknown IP version from tun"),
                            }
                            packet_from_tun.clear();
                        }
                    }
                    Ok(0) => {
                        // TUN interface disconnected
                        println!("TUN interface disconnected:");
                        break;
                    }
                    Err(e) => {
                        eprintln!("Failed to read data from TUN interface: {}", e);
                        break;
                    }
                }
            }
        }
    }
} */