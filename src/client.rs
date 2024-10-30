use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:2222").await?;
    println!("Connected to server");

    let shared_key = rand::thread_rng().gen::<[u8; 32]>();
    let cipher = Aes256Gcm::new_from_slice(&shared_key)
        .map_err(|e| Box::<dyn Error>::from(format!("Cipher error: {:?}", e)))?;

    let mut buf = [0; 1024];

    let n = stream.read(&mut buf).await?;
    println!("Server version: {}", String::from_utf8_lossy(&buf[..n]));
    stream.write_all(b"SSH-2.0-RustSSHClient_0.1\r\n").await?;

    let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Cambiamos el comando a un slice
    let command = b"hello server!" as &[u8];
    let encrypted = cipher
        .encrypt(nonce, command)
        .map_err(|e| Box::<dyn Error>::from(format!("Encryption error: {:?}", e)))?;

    stream.write_all(&encrypted).await?;

    let n = stream.read(&mut buf).await?;
    let decrypted = cipher
        .decrypt(nonce, &buf[..n])
        .map_err(|e| Box::<dyn Error>::from(format!("Decryption error: {:?}", e)))?;

    println!("Server response: {}", String::from_utf8_lossy(&decrypted));

    Ok(())
}
