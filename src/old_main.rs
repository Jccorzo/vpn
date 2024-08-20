use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:7878")
        .await
        .expect("Error starting server");
    println!("Server is running on port 7878");

    loop {
        let (stream, _) = listener.accept().await?;
        println!("Connection established!");
        tokio::spawn(async {
            handle_connection(stream).await;
        });
    }
}

async fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    loop {
        let mut data = Vec::new();
        loop {
            let n = match stream.read(&mut buffer).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Failed to read data: {}", e);
                    return;
                }
            };
            if n == 0 {
                println!("Client disconnected:");
                return;
            }
            data.extend_from_slice(&buffer[..n]);
            if n < 512 {  // If less than buffer size is read, assume end of message
                break;
            }
        }

        //println!("Received from {}", data);
        if let Err(e) = stream.write_all(&data).await {
            eprintln!("Failed to send data: {}", e);
            break;
        } else {
            println!("data sent");
            print!("address: {:?} data: {}s ", stream.peer_addr(), String::from_utf8_lossy(&data));
        }

        /* match stream.read(&mut buffer).await {
            Ok(0) => {
                println!("Cliente desconectado");
                return;
            }
            Ok(n) => {
                if let Err(e) = stream.write_all(&buffer[0..n]).await {
                    println!("Failed to send data");
                }
            }
            Err(e) => {
                println!("Failed to read dataaaa");
                println!("Failed to read data from socket {}", e);
            }
        } */
    }
}


async fn handle_connection(
    mut stream: TcpStream,
    address: SocketAddr,
    tun: Arc<RwLock<AsyncDevice>>,
) {
    let mut buffer = [0; BUFFER_SIZE];

    /* match stream.read(&mut buffer).await {
        Ok(n) => {
            if n == 0 {
                println!("Client disconnected.");
                return;
            }

            let received_password = String::from_utf8((&buffer[..n]).to_vec());

            match received_password {
                Ok(received_password) => {
                    // validate password against backend here
                    if received_password == "PASSWORD" {
                        println!("Successssssssss");
                        return ;
                    } else {
                        eprintln!("Authentication Failed");
                        return;
                    }
                }
                Err(_) => {
                    eprintln!("Authentication Failed: Error parsing password");
                    return;
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read data: {}", e);
            return;
        }
    }; */

    loop {
        let mut packet = Vec::new();

        loop {
            let n = match stream.read(&mut buffer).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Failed to read data: {}", e);
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

        // This Data is coming from tun interface, so packets are either ipv4 or ipv6
        match packet[0] >> 4 {
            4 => {
                println!("IP 4 version");
                if let Some(mut mut_pack) = MutableIpv4Packet::new(&mut packet) {
                    println!(
                        "MUT IPV4 Source IP: {:?}",
                        mut_pack.get_source().to_string()
                    );
                    println!(
                        "MUTCK IPV4 Destination IP: {:?}",
                        mut_pack.get_destination().to_string()
                    );

                    let source = Ipv4Addr::new(10, 0, 0, 5);
                    mut_pack.set_source(source);
                    mut_pack.set_checksum(pnet::packet::ipv4::checksum(&mut_pack.to_immutable()));

                    // write to tun

                    match tun.write().await.write_all(&mut_pack.packet()).await {
                        Ok(_n) => {
                            println!("Data written to tun interface");
                        }
                        Err(err) => {
                            eprintln!("Failed to write data to tun interface: {}", err);
                            return;
                        }
                    }

                    let mut buffer = [0; BUFFER_SIZE];

                    let mut packet = Vec::new();

                    loop {
                        {
                            let n = match tun.write().await.read(&mut buffer).await {
                                Ok(n) => n,
                                Err(e) => {
                                    eprintln!("Failed to read data: {}", e);
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

                    // read from tun
                    if let Some(mut mut_pack) = MutableIpv4Packet::new(&mut packet) {
                        println!(
                            "MUT IPV4 Source IP: {:?}",
                            mut_pack.get_source().to_string()
                        );
                        println!(
                            "MUTCK IPV4 Destination IP: {:?}",
                            mut_pack.get_destination().to_string()
                        );

                        let source = Ipv4Addr::new(10, 0, 0, 1);
                        mut_pack.set_source(source);
                        mut_pack
                            .set_checksum(pnet::packet::ipv4::checksum(&mut_pack.to_immutable()));
                    }

                    // write to stream
                    if let Err(e) = stream.write_all(mut_pack.packet()).await {
                        eprintln!("Failed to send data: {}", e);
                        break;
                    } else {
                        println!("ipv4 data sent");
                        println!();
                    }
                }
            }
            6 => {
                println!("IP 6 version");
                if let Some(mut mut_pack) = MutableIpv6Packet::new(&mut packet) {
                    println!(
                        "MUT IPV6 Source IP: {:?}",
                        mut_pack.get_source().to_string()
                    );
                    println!(
                        "MUTCK IPV6 Destination IP: {:?}",
                        mut_pack.get_destination().to_string()
                    );

                    let source = Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped();
                    mut_pack.set_source(source);

                    // write to tun
                    // read from tun
                    // write to stream

                    if let Err(e) = stream.write_all(mut_pack.packet()).await {
                        eprintln!("Failed to send data: {}", e);
                        break;
                    } else {
                        println!("ipv6 data sent");
                        println!();
                    }
                }
            }
            _ => println!("Unknown IP version"),
        }
    }

    println!("Client disconnected:");
}
