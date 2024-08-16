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
