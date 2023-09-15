use secp256k1::{PublicKey, SecretKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

mod ecies;
mod error;
mod handshake;
mod hash_mac;
mod messages;
mod secret;

use crate::{
    error::{Error, Result},
    handshake::Handshake,
    messages::{Disconnect, Hello},
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (node_public_key, node_address) = parse_input().unwrap();
    println!("Target adress: {node_address}");

    if let Ok(mut stream) = TcpStream::connect(node_address).await {
        println!("Connected to target adress");
        if let Err(e) = handshake(&mut stream, node_public_key).await {
            println!("{e}");
        }
    } else {
        println!("Failed to connect to the given Ethereum node.");
    }
}

async fn handshake(stream: &mut TcpStream, node_public_key: PublicKey) -> Result<()> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

    let mut handshake = Handshake::new(private_key, node_public_key);

    let auth_encrypted = handshake.auth();

    if stream.write(&auth_encrypted).await? == 0 {
        return Err(Error::TcpConnectionClosed);
    }

    println!("Auth message send to target node");

    let mut buf = [0_u8; 1024];
    let resp = stream.read(&mut buf).await?;

    if resp == 0 {
        return Err(Error::AuthResponse());
    }

    let mut bytes_used = 0u16;

    let decrypted = handshake.decrypt(&mut buf, &mut bytes_used)?;

    if bytes_used == resp as u16 {
        return Err(Error::InvalidResponse(
            "Recipient's response does not contain the Hello message".to_string(),
        ));
    }

    handshake.derive_secrets(decrypted)?;

    let hello_frame = handshake.hello_msg();
    if stream.write(&hello_frame).await? == 0 {
        return Err(Error::TcpConnectionClosed);
    }

    let frame = handshake.read_frame(&mut buf[bytes_used as usize..resp])?;
    handle_incoming_frame(frame)?;

    Ok(())
}

fn handle_incoming_frame(frame: Vec<u8>) -> Result<()> {
    let message_id: u8 = rlp::decode(&[frame[0]])?;

    if message_id == 0 {
        let hello: Hello = rlp::decode(&frame[1..])?;
        println!("Hello message from target node:\n{:?}", hello);
    }

    if message_id == 1 {
        let disc: Disconnect = rlp::decode(&frame[1..])?;
        println!("Disconnect message from target node: \n{:?}", disc);
    }

    Ok(())
}

fn parse_input() -> Result<(PublicKey, String)> {
    let mut args = std::env::args();
    let _inner = args.next();
    let id = args.next().unwrap_or_default();
    let id_decoded = hex::decode(id).unwrap();
    let public_key = public_key(&id_decoded)?;

    let ip_addr = args.next().unwrap_or_default();
    let port = args.next().unwrap_or_default();

    let addr = format!("{}:{}", ip_addr, port);

    Ok((public_key, addr))
}

fn public_key(data: &[u8]) -> Result<PublicKey> {
    let mut s = [4_u8; 65];
    s[1..].copy_from_slice(data);

    let public_key =
        PublicKey::from_slice(&s).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    Ok(public_key)
}
