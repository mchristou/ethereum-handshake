use futures::SinkExt;
use futures::StreamExt;
use secp256k1::{PublicKey, SecretKey};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

mod codec;
mod ecies;
mod error;
mod handshake;
mod hash_mac;
mod messages;
mod secret;

use crate::{
    codec::Codec,
    error::{Error, Result},
    handshake::Handshake,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (node_public_key, node_address) = parse_input().unwrap();
    println!("Target address: {node_address}");

    if let Ok(mut stream) = TcpStream::connect(node_address).await {
        println!("Connected to target address");
        if let Err(e) = handshake(&mut stream, node_public_key).await {
            println!("{e}");
        }
    } else {
        println!("Failed to connect to the given Ethereum node.");
    }
}

async fn handshake(stream: &mut TcpStream, node_public_key: PublicKey) -> Result<()> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

    let handshake = Handshake::new(private_key, node_public_key);
    let mut framed = Framed::new(stream, Codec::new(handshake));

    framed.send(messages::Message::Auth).await?;
    println!("Auth message sent to target node");

    loop {
        match framed.next().await {
            Some(Ok(frame)) => match frame {
                messages::Message::Auth => {}
                messages::Message::AuthAck => {}
                messages::Message::Hello => {
                    framed.send(messages::Message::Ping).await?;
                }
                messages::Message::Ping => {
                    framed.send(messages::Message::Pong).await?;
                }
                messages::Message::Pong => {}
                messages::Message::Disconnect(reason) => {
                    println!("Disconnecting with reason: {reason}");
                    std::process::exit(0);
                }
            },
            Some(Err(e)) => {
                println!("{e}");
            }
            None => {}
        }
    }
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
