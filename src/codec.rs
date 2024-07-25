use alloy_rlp::Decodable;
use bytes::{Buf, BytesMut};
use log::{debug, error, info};
use snap::raw::Decoder as SnapDecoder;
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    error::{Error, Result},
    handshake::Handshake,
    messages::{Disconnect, Hello, Message, Ping, Pong, Status},
};

enum State {
    Auth,
    AuthAck,
    Frame,
}

pub struct Codec {
    handshake: Handshake,
    state: State,
}

impl Codec {
    pub fn new(handshake: Handshake) -> Self {
        Self {
            handshake,
            state: State::Auth,
        }
    }

    fn handle_incoming_frame(&mut self, frame: &[u8]) -> Result<Message> {
        let (message_id, message) = frame.split_at(1);
        let message_id = u8::decode(&mut &message_id[..])?;
        debug!("Message ID received: {}", message_id);

        match message_id {
            Hello::ID => {
                let hello = Hello::decode(&mut &message[..])?;
                info!("Hello message from target node:\n{:?}", hello);
                Ok(Message::Hello)
            }
            Disconnect::ID => {
                let disc = match Disconnect::decode(&mut &message[..]) {
                    Ok(disc) => {
                        info!("Disconnect message from target node:\n{:?}", disc);
                        disc
                    }
                    Err(_) => {
                        let idx = Self::last_nonzero_index(message);
                        let buf = Self::snappy_decompress(&message[..idx])
                            .unwrap_or_else(|_| BytesMut::from(message));
                        Disconnect::decode(&mut &buf[..])?
                    }
                };

                info!("Disconnect message from target node:\n{:?}", disc);
                Ok(Message::Disconnect(disc.reason))
            }
            Ping::ID => {
                let _ping = Ping::decode(&mut &message[..])?;
                info!("Ping message received");
                Ok(Message::Ping)
            }
            Pong::ID => {
                let _pong = Pong::decode(&mut &message[..])?;
                info!("Pong message received");
                Ok(Message::Pong)
            }
            _ => self.handle_eth_wire_messages(message_id, message),
        }
    }

    pub fn handle_eth_wire_messages(&mut self, message_id: u8, message: &[u8]) -> Result<Message> {
        match message_id {
            Status::ID => {
                let idx = Self::last_nonzero_index(message);
                let buf = Self::snappy_decompress(&message[..idx])
                    .unwrap_or_else(|_| BytesMut::from(message));
                let status = Status::decode(&mut &buf[..])?;
                info!("Status message received: {:?}", status);
                Ok(Message::Status(status))
            }
            _ => {
                error!("Unsupported message ID: {}", message_id);
                Err(Error::UnsupportedMessageId(message_id))
            }
        }
    }

    fn snappy_decompress(input: &[u8]) -> Result<BytesMut> {
        let len = snap::raw::decompress_len(input)?;
        let mut decompress = BytesMut::zeroed(len + 1);
        let mut decoder = SnapDecoder::new();
        decoder.decompress(input, &mut decompress)?;

        Ok(decompress)
    }

    fn last_nonzero_index(v: &[u8]) -> usize {
        v.iter().rposition(|&x| x != 0).map_or(0, |idx| idx + 1)
    }
}

impl Encoder<Message> for Codec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            Message::Auth => {
                self.state = State::AuthAck;
                dst.extend_from_slice(&self.handshake.auth());
            }
            Message::AuthAck => {
                // Implement AuthAck encoding here
                todo!()
            }
            Message::Hello => {
                dst.extend_from_slice(&self.handshake.hello_msg());
            }
            Message::Disconnect(reason) => {
                dst.extend_from_slice(&self.handshake.disconnect_msg(reason));
            }
            Message::Ping => {
                dst.extend_from_slice(&self.handshake.ping_msg());
            }
            Message::Pong => {
                dst.extend_from_slice(&self.handshake.pong_msg());
            }
            Message::Status(msg) => {
                dst.extend_from_slice(&self.handshake.status_msg(msg));
            }
        }
        Ok(())
    }
}

impl Decoder for Codec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        match self.state {
            State::Auth => {
                self.state = State::AuthAck;
                Ok(None)
            }
            State::AuthAck => {
                if src.len() < 2 {
                    return Ok(None);
                }

                let payload = u16::from_be_bytes([src[0], src[1]]) as usize;
                let total_size = payload + 2;

                if src.len() < total_size {
                    return Ok(None);
                }

                let mut buf = src.split_to(total_size);
                let auth_ack = self.handshake.decrypt(&mut buf)?;
                self.handshake.derive_secrets(auth_ack)?;
                self.state = State::Frame;
                Ok(Some(Message::AuthAck))
            }
            State::Frame => match self.handshake.read_frame(&mut src[..]) {
                Ok((frame, size_used)) => {
                    src.advance(size_used);
                    self.handle_incoming_frame(&frame).map(Some)
                }
                Err(e) => {
                    error!("Failed to read frame: {:?}", e);
                    Ok(None)
                }
            },
        }
    }
}
