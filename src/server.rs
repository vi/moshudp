use std::{
    ffi::{OsStr, OsString},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    os::unix::prelude::AsRawFd,
};

use chacha20poly1305::XChaCha20Poly1305;
use fxhash::FxHashSet;
use nix::poll::{poll, PollFd, PollFlags};

use crate::protocol::{Message, Nonce};
use std::os::unix::ffi::OsStrExt;

pub struct Server {
    server_socket: UdpSocket,
    crypto: XChaCha20Poly1305,
    mosh: Option<MoshState>,
    past_nonces: FxHashSet<Nonce>,
    recent_client_addr: Option<SocketAddr>,
}

struct MoshState {
    socket: UdpSocket,
    key: String,
    sessid: u64,
}

impl Server {
    pub fn new(sa: SocketAddr, crypto: XChaCha20Poly1305) -> anyhow::Result<Server> {
        Ok(Server {
            server_socket: UdpSocket::bind(sa)?,
            crypto,
            mosh: None,
            past_nonces: FxHashSet::default(),
            recent_client_addr: None,
        })
    }

    pub fn serve(&mut self) {
        let mut buf = [0u8; 8192];
        let mut polls: Vec<PollFd> = Vec::with_capacity(2);
        polls.push(PollFd::new(
            self.server_socket.as_raw_fd(),
            PollFlags::POLLIN,
        ));
        loop {
            polls.truncate(1);
            if let Some(ref mosh) = self.mosh {
                polls.push(PollFd::new(mosh.socket.as_raw_fd(), PollFlags::POLLIN));
            }

            if let Err(e) = poll(&mut polls[..], -1) {
                eprintln!("poll error: {}", e);
                return;
            }

            if matches!(polls[0].revents(), Some(x) if x.contains(PollFlags::POLLIN)) {
                let (pkt, clientaddr) = match self.server_socket.recv_from(&mut buf) {
                    Ok((sz, clientaddr)) => (&buf[..sz], clientaddr),
                    Err(_) => continue,
                };

                let msg = match crate::protocol::decrypt(&pkt, &self.crypto, &mut self.past_nonces)
                {
                    Ok(x) => x,
                    Err(_e) => {
                        //eprintln!("{}", _e);
                        let mut clearmosh = false;
                        if let Some(ref mosh) = self.mosh {
                            if mosh.socket.send(pkt).is_err() {
                                clearmosh = true;
                            }
                        }
                        if clearmosh {
                            self.mosh = None
                        }
                        continue;
                    }
                };
                if self.past_nonces.len() > 1000_000 {
                    self.past_nonces.clear();
                }


                let replymsg: Option<Message> = match msg {
                    Message::Ping => Some(Message::Pong),
                    Message::Pong => None,
                    Message::ServerStarted { .. } => None,
                    Message::StartServer { sessid } => {
                        self.recent_client_addr = Some(clientaddr);
                        let reply = if let Some(ref mosh) = self.mosh {
                            if mosh.sessid == sessid {
                                Some(Message::ServerStarted {
                                    key: mosh.key.clone(),
                                })
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        if reply.is_none() {
                            match Server::start_mosh_server(sessid) {
                                Ok(mosh) => {
                                    let key = mosh.key.clone();
                                    self.mosh = Some(mosh);
                                    Some(Message::ServerStarted { key })
                                }
                                Err(e) => {
                                    self.mosh = None;
                                    Some(Message::Failed {
                                        msg: format!("{}", e),
                                    })
                                }
                            }
                        } else {
                            reply
                        }
                    }
                    Message::Failed { .. } => None,
                };

                if let Some(replymsg) = replymsg {
                    if let Ok(pkt2) = crate::protocol::encrypt(&replymsg, &self.crypto) {
                        let _ = self.server_socket.send_to(&pkt2[..], clientaddr);
                    }
                }
                // end of server socket msg code
            }
            if polls.len() >= 2
                && matches!(polls[1].revents(), Some(x) if x.contains(PollFlags::POLLIN))
            {
                if let Some(ref mosh) = self.mosh {
                    let mut clearmosh = false;
                    let pkt = match mosh.socket.recv(&mut buf) {
                        Ok(sz) => (&buf[..sz]),
                        Err(_) => {
                            clearmosh = true;
                            &buf[..]
                        }
                    };
                    if clearmosh {
                        self.mosh = None;
                        continue;
                    } else if let Some(ca) = self.recent_client_addr {
                        let _ = self.server_socket.send_to(pkt, ca);
                    }
                } else {
                    unreachable!()
                }
            }
        }
    }

    fn start_mosh_server(sessid: u64) -> anyhow::Result<MoshState> {
        let mosh_server =
            std::env::var_os("MOSH_SERVER").unwrap_or(OsStr::from_bytes(b"mosh-server").to_owned());
        let mut cmd = std::process::Command::new(mosh_server);
        cmd.arg("new").arg("-i").arg("127.0.0.1").arg("-p").arg("0");
        let out = cmd.output()?;

        if !out.status.success() {
            anyhow::bail!("Unsuccessful exit status from mosh-server: {}", out.status);
        }

        let l = String::from_utf8_lossy(&out.stdout);
        for line in l.lines() {
            if line.starts_with("MOSH CONNECT") {
                let words: Vec<&str> = line.split_ascii_whitespace().collect();
                if words.len() < 4 {
                    anyhow::bail!("Malformed MOSH CONNECT line");
                }
                let port = words[2];
                let key = words[3].to_owned();
                let port: u16 = port.parse()?;

                let socket =
                    UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
                socket.connect(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))?;
                return Ok(MoshState{key,socket,sessid});
            }
        }
        anyhow::bail!("Failed to find MOSH CONNECT in the output")
    }
}
