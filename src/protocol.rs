use fxhash::FxHashSet;
use serde::{Serialize,Deserialize};

pub const MAGIC : u32 = 0x55644d6f;

pub type Nonce = [u8; 24];

#[derive(Serialize,Deserialize)]
pub struct Datagram {
    magic: u32,
    nonce: Nonce,
    data: Vec<u8>,
}

#[derive(Serialize,Deserialize)]
pub enum Message {
    Ping,
    Pong,
    StartServer{sessid: u64},
    ServerStarted{key: String},
    Failed{msg: String},
}

use bincode::Options;
use chacha20poly1305::{aead::Aead, XNonce};
fn bco() -> impl bincode::Options {
    bincode::DefaultOptions::new().with_big_endian().with_fixint_encoding()
}
pub fn encrypt(msg: &Message, crypto: &chacha20poly1305::XChaCha20Poly1305) -> anyhow::Result<Vec<u8>> {
    let buf = bco().serialize(msg)?;
    let mut nonce = [0u8; 24]; 
    getrandom::getrandom(&mut nonce[..])?;
    let data: Vec<u8> = crypto.encrypt(XNonce::from_slice(&nonce), &buf[..]).unwrap();
    let h = Datagram { magic: MAGIC, nonce, data };
    let dg = bco().serialize(&h).unwrap();
    Ok(dg)
}

pub fn decrypt(msg: &[u8], crypto: &chacha20poly1305::XChaCha20Poly1305, past_nonces: &mut FxHashSet<Nonce>) -> anyhow::Result<Message> {
    let h : Datagram = bco().with_limit(1024).deserialize(msg)?;
    if h.magic != MAGIC {
        anyhow::bail!("Invalid magic");
    }
    let buf = crypto.decrypt(XNonce::from_slice(&h.nonce),&h.data[..]).map_err(|_|anyhow::anyhow!("Decryption failed"))?;
    //eprintln!("nonce={:?}",h.nonce);
    if !past_nonces.insert(h.nonce) {
        anyhow::bail!("Replay attack");
    }
    Ok(bco().with_limit(1024).deserialize(&buf)?)
}
