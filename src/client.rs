use std::{
    ffi::OsStr,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
    os::unix::prelude::AsRawFd,
};

use chacha20poly1305::XChaCha20Poly1305;
use fxhash::FxHashSet;
use nix::poll::{poll, PollFd, PollFlags};

use crate::protocol::{Message, Nonce};
use std::os::unix::ffi::OsStrExt;

pub struct Client {
    client_socket: UdpSocket,
    crypto: XChaCha20Poly1305,
    mosh: Option<MoshClientState>,
    past_nonces: FxHashSet<Nonce>,
    destination_address: SocketAddr,
    resend_counter: usize,
    sessid: u64,
    ping_mode: bool,
}

struct MoshClientState {
    socket: UdpSocket,
    reply_address: Option<SocketAddr>,
    //child: std::process::Child,
}

impl Client {
    pub fn new(
        dest_sa: SocketAddr,
        crypto: XChaCha20Poly1305,
        ping_mode: bool,
    ) -> anyhow::Result<Client> {
        let bind_sa = match dest_sa {
            SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        };
        let mut sessid = [0u8; 8];
        getrandom::getrandom(&mut sessid[..])?;
        Ok(Client {
            client_socket: UdpSocket::bind(bind_sa)?,
            crypto,
            mosh: None,
            past_nonces: FxHashSet::default(),
            destination_address: dest_sa,
            resend_counter: 50,
            sessid: u64::from_ne_bytes(sessid),
            ping_mode,
        })
    }

    pub fn connect(&mut self) {
        let mut buf = [0u8; 8192];
        let mut polls: Vec<PollFd> = Vec::with_capacity(2);
        polls.push(PollFd::new(
            self.client_socket.as_raw_fd(),
            PollFlags::POLLIN,
        ));
        self.send_request();
        loop {
            polls.truncate(1);
            if let Some(ref mosh) = self.mosh {
                polls.push(PollFd::new(mosh.socket.as_raw_fd(), PollFlags::POLLIN));
            }

            let timeout = if self.mosh.is_some() { -1 } else { 200 };
            match poll(&mut polls[..], timeout) {
                Err(e) => {
                    eprintln!("poll error: {}", e);
                    return;
                }
                Ok(n) => {
                    if n == 0 {
                        if self.resend_counter > 0 {
                            self.resend_counter -= 1;
                            self.send_request();
                        } else {
                            if self.mosh.is_none() {
                                eprintln!("Failed to receive usable reply from server");
                                std::process::exit(2);
                            }
                        }
                    }
                }
            }

            if matches!(polls[0].revents(), Some(x) if x.contains(PollFlags::POLLIN)) {
                let (pkt, fromaddr) = match self.client_socket.recv_from(&mut buf) {
                    Ok((sz, fromaddr)) => (&buf[..sz], fromaddr),
                    Err(_) => continue,
                };
                if fromaddr != self.destination_address {
                    continue;
                }

                let msg = match crate::protocol::decrypt(&pkt, &self.crypto, &mut self.past_nonces)
                {
                    Ok(x) => x,
                    Err(_e) => {
                        if let Some(ref mosh) = self.mosh {
                            if let Some(reply_addr) = mosh.reply_address {
                                if mosh.socket.send_to(pkt, reply_addr).is_err() {
                                    eprintln!("Mosh client socket closed");
                                    return;
                                }
                            } else {
                                eprintln!("Premature traffic to mosh-client");
                            }
                        } else {
                            eprintln!("Error: {}", _e);
                        }
                        continue;
                    }
                };

                match msg {
                    Message::Ping => {
                        eprintln!("Stray incomding message: Ping");
                    }
                    Message::Pong => {
                        if self.ping_mode {
                            println!("Received Pong reply");
                            return;
                        }
                    }
                    Message::ServerStarted { key } => {
                        if self.ping_mode {
                            eprintln!("Unexpected reply: ServerStarted");
                        } else {
                            let udp = match Client::start_mosh_client(key) {
                                Ok(x) => x,
                                Err(e) => {
                                    eprintln!("Error starting mosh-client: {}", e);
                                    std::process::exit(3)
                                }
                            };
                            self.mosh = Some(udp);
                        }
                    }
                    Message::StartServer { .. } => {
                        eprintln!("Stray incoming message: StartServer");
                    }
                    Message::Failed { msg } => {
                        eprintln!("Received error from server: {}", msg);
                        std::process::exit(1);
                    }
                };

                // end of client socket msg code
            }
            if polls.len() >= 2
                && matches!(polls[1].revents(), Some(x) if x.contains(PollFlags::POLLIN))
            {
                if let Some(ref mut mosh) = self.mosh {
                    let mut clearmosh = false;
                    let (pkt, addr) = match mosh.socket.recv_from(&mut buf) {
                        Ok((sz, addr)) => (&buf[..sz], addr),
                        Err(_) => {
                            clearmosh = true;
                            (&buf[..], self.destination_address) // dummy value
                        }
                    };
                    if clearmosh {
                        eprintln!("Cannot receive from mosh-client-facing socket");
                        std::process::exit(1);
                    } else {
                        if mosh.reply_address.is_none() {
                            mosh.reply_address = Some(addr);
                        }
                        if Some(addr) != mosh.reply_address {
                            continue;
                        }
                        let _ = self.client_socket.send_to(pkt, self.destination_address);
                    }
                } else {
                    unreachable!()
                }
            }
        }
    }

    fn send_request(&self) {
        let msg = if self.ping_mode {
            Message::Ping
        } else {
            Message::StartServer {
                sessid: self.sessid,
            }
        };
        let pkt = crate::protocol::encrypt(&msg, &self.crypto).unwrap();
        if let Err(e) = self.client_socket.send_to(&pkt, self.destination_address) {
            eprintln!("sendto: {}", e);
            std::process::exit(3);
        }
    }

    fn start_mosh_client(key: String) -> anyhow::Result<MoshClientState> {
        let udp = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
        let port = udp.local_addr()?.port();
        let mosh_client =
            std::env::var_os("MOSH_CLIENT").unwrap_or(OsStr::from_bytes(b"mosh-client").to_owned());
        let mut cmd = std::process::Command::new(mosh_client);
        cmd.arg("127.0.0.1").arg(format!("{}", port));
        cmd.env("MOSH_KEY", key);
        let mut child = cmd.spawn()?;
        std::thread::spawn(move || match child.wait() {
            Ok(c) => {
                if c.success() {
                    std::process::exit(0);
                } else {
                    eprint!("Unsuccessful exit status of mosh-client: {}", c);
                    std::process::exit(4);
                }
            }
            Err(_e) => {
                eprintln!("Failed waiting for mosh-client child process");
                std::process::exit(3);
            }
        });
        Ok(MoshClientState {
            //child,
            socket: udp,
            reply_address: None,
        })
    }
}

impl Drop for MoshClientState {
    fn drop(&mut self) {
        //let _ = self.child.wait();
    }
}
