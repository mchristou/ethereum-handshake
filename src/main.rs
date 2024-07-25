use futures::{SinkExt, StreamExt};
use log::{error, info, warn};
use secp256k1::{PublicKey, SecretKey};
use std::{env, process};
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
    messages::Message,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();

    match parse_input() {
        Ok((node_public_key, node_address)) => {
            info!("Target address: {node_address}");
            match TcpStream::connect(&node_address).await {
                Ok(mut stream) => {
                    info!("Connected to target address");
                    if let Err(e) = perform_handshake(&mut stream, node_public_key).await {
                        error!("Handshake error: {e}");
                    }
                }
                Err(e) => error!("Failed to connect to the given Ethereum node: {e}"),
            }
        }
        Err(e) => error!("Error parsing input: {e}"),
    }
}

async fn perform_handshake(stream: &mut TcpStream, node_public_key: PublicKey) -> Result<()> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let handshake = Handshake::new(private_key, node_public_key);
    let mut framed = Framed::new(stream, Codec::new(handshake));

    framed.send(Message::Auth).await?;
    info!("Auth message sent to target node");

    while let Some(message) = framed.next().await {
        match message {
            Ok(frame) => match frame {
                Message::Auth => {}
                Message::AuthAck => {
                    framed.send(Message::Hello).await?;
                }
                Message::Hello => {}
                Message::Ping => {
                    framed.send(Message::Pong).await?;
                }
                Message::Pong => {
                    framed.send(Message::Ping).await?;
                }
                Message::Disconnect(_reason) => {
                    process::exit(0);
                }
                Message::Status(msg) => {
                    framed.send(Message::Status(msg)).await?;
                }
            },
            Err(e) => {
                error!("Error receiving message: {e}");
                break;
            }
        }
    }

    warn!("Connection closed by the peer side");

    Ok(())
}

fn parse_input() -> Result<(PublicKey, String)> {
    let mut args = env::args();
    let _inner = args.next();
    let id = args
        .next()
        .ok_or_else(|| Error::InvalidInput("Missing node ID".to_string()))?;
    let id_decoded =
        hex::decode(id).map_err(|_| Error::InvalidInput("Invalid node ID".to_string()))?;
    let public_key = public_key_from_slice(&id_decoded)?;

    let ip_addr = args
        .next()
        .ok_or_else(|| Error::InvalidInput("Missing IP address".to_string()))?;
    let port = args
        .next()
        .ok_or_else(|| Error::InvalidInput("Missing port".to_string()))?;

    let addr = format!("{}:{}", ip_addr, port);
    Ok((public_key, addr))
}

fn public_key_from_slice(data: &[u8]) -> Result<PublicKey> {
    const PUBLIC_KEY_LENGTH: usize = 64;
    const PUBLIC_KEY_WITH_PREFIX_LENGTH: usize = 65;

    if data.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidInput("Invalid public key length".to_string()));
    }

    let mut s = [4_u8; PUBLIC_KEY_WITH_PREFIX_LENGTH];
    s[1..].copy_from_slice(data);

    PublicKey::from_slice(&s).map_err(|e| Error::InvalidPublicKey(e.to_string()))
}
