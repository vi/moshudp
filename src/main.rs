use argh::FromArgs;
use chacha20poly1305::aead::NewAead;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

/// mosh-server and mosh-client interconnector based on UDP and a static key file
#[derive(FromArgs)]
struct Opts {
    #[argh(subcommand)]
    cmd: Cmd,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Cmd {
    Serve(Serve),
    Connect(Connect),
    Keygen(Keygen),
}

/// server mode
#[derive(FromArgs)]
#[argh(subcommand, name = "serve")]
struct Serve {
    /// socket address to listen
    #[argh(positional)]
    addr: String,

    /// limit hostname resolution to IPv4 addresses
    #[argh(switch, short = '4')]
    ipv4: bool,

    /// limit hostname resolution to IPv6 addresses
    #[argh(switch, short = '6')]
    ipv6: bool,

    /// 32-byte file to generate use as a key
    #[argh(positional)]
    keyfile: PathBuf,
}

/// client mode
#[derive(FromArgs)]
#[argh(subcommand, name = "connect")]
struct Connect {
    /// socket address to connect
    #[argh(positional)]
    addr: String,

    /// limit hostname resolution to IPv4 addresses
    #[argh(switch, short = '4')]
    ipv4: bool,

    /// limit hostname resolution to IPv6 addresses
    #[argh(switch, short = '6')]
    ipv6: bool,

    /// 32-byte file to generate use as a key
    #[argh(positional)]
    keyfile: PathBuf,

    /// skip most of the algorithm, just send a ping
    #[argh(switch)]
    ping: bool,
}

/// generate 32-byte random file to use as a key on client and server
#[derive(FromArgs)]
#[argh(subcommand, name = "keygen")]
struct Keygen {
    /// new file to generate the key to
    #[argh(positional)]
    file: PathBuf,
}

mod client;
mod protocol;
mod server;

fn main() -> anyhow::Result<()> {
    let opts: Opts = argh::from_env();
    match opts.cmd {
        Cmd::Serve(Serve {
            addr,
            ipv4,
            ipv6,
            keyfile,
        }) => {
            let addr = handle_addr(addr, ipv4, ipv6)?;
            let key = std::fs::read(keyfile)?;
            anyhow::ensure!(key.len() == 32);
            let crypto =
                chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
            server::Server::new(addr, crypto)?.serve();
        }
        Cmd::Connect(Connect {
            addr,
            ipv4,
            ipv6,
            keyfile,
            ping,
        }) => {
            let addr = handle_addr(addr, ipv4, ipv6)?;
            let key = std::fs::read(keyfile)?;
            anyhow::ensure!(key.len() == 32);
            let crypto =
                chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
            client::Client::new(addr, crypto, ping)?.connect()
        }
        Cmd::Keygen(Keygen { file }) => {
            let mut buf = [0u8; 32];
            getrandom::getrandom(&mut buf[..])?;
            std::fs::write(file, buf)?;
        }
    }
    Ok(())
}

fn handle_addr(addr: String, ipv4: bool, ipv6: bool) -> Result<SocketAddr, anyhow::Error> {
    let mut addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
    addrs.retain(|a| match a {
        SocketAddr::V4(_) => !ipv6,
        SocketAddr::V6(_) => !ipv4,
    });
    if addrs.len() < 1 {
        anyhow::bail!("No usable socket addresses obtained");
    }
    if addrs.len() > 1 {
        anyhow::bail!("Listening or connecting to multiple UDP socket addresses is not supported");
    }
    Ok(addrs[0])
}
