use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Inicializar el servidor en localhost:2222
    let listener = TcpListener::bind("127.0.0.1:2222").await?;
    println!("Server listening on port 2222");

    // Generar una clave para el servidor
    let server_key = rand::thread_rng().gen::<[u8; 32]>();
    // Manejar el error explícitamente
    let cipher = Aes256Gcm::new_from_slice(&server_key)
        .map_err(|e| Box::<dyn Error>::from(format!("Cipher error: {:?}", e)))?;

    while let Ok((mut socket, addr)) = listener.accept().await {
        println!("New connection from: {}", addr);

        let cipher = cipher.clone();

        tokio::spawn(async move {
            let mut buf = [0; 1024];

            // Handshake básico
            if let Err(e) = socket.write_all(b"SSH-2.0-RustSSH_0.1\r\n").await {
                eprintln!("Failed to write handshake: {}", e);
                return;
            }

            let n = match socket.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Failed to read handshake: {}", e);
                    return;
                }
            };
            println!("Client version: {}", String::from_utf8_lossy(&buf[..n]));

            // Generar un nonce aleatorio para el cifrado
            let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
            let nonce = Nonce::from_slice(&nonce_bytes);

            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) => break, // Conexión cerrada
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Failed to read from socket: {}", e);
                        break;
                    }
                };

                // Descifrar el mensaje
                let decrypted = match cipher.decrypt(nonce, &buf[..n]) {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!("Failed to decrypt message: {:?}", e);
                        break;
                    }
                };

                // Procesar el comando
                let response = format!("Echo: {}", String::from_utf8_lossy(&decrypted));

                // Cifrar la respuesta
                let encrypted = match cipher.encrypt(nonce, response.as_bytes()) {
                    Ok(enc) => enc,
                    Err(e) => {
                        eprintln!("Failed to encrypt response: {:?}", e);
                        break;
                    }
                };

                if let Err(e) = socket.write_all(&encrypted).await {
                    eprintln!("Failed to write to socket: {}", e);
                    break;
                }
            }
        });
    }

    Ok(())
}
