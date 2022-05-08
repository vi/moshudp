# moshudp

Typically [mosh](https://mosh.org/) uses ssh to establish session. However sometimes SSH is not available due to bad network, or you could lose access to SSH (and therefore to Mosh) because of some misconfiguration.

Moshudp provides alternative, simplified UDP-based session establishment mechanism for mosh-client and mosh-server.

This allows connecting mosh-client and mosh-server using only one UDP port, without SSH or another TCP connection.
Authentication is based on one static keyfile.

# Limitations

* Only one client at a time. Connecting competing client disconnects earlier one (you can use `--ping` mode to check server nondestructively).
* Only symmetric crypto - keyfile is the same on client and server.
* No NAT traversal or ICE.
* No security audit. I tried my best to protect it from replay attacks or being a DoS amplifier, but I'm not a security specialist.
* No replies at all if key is incorrect - client would just time out.
* Security model of moshudp assumes that mosh-server is ready to accept arbitrary (i.e. malicious) datagrams from open internet.

# Installation

Use [Github Releases](https://github.com/vi/moshudp/releases/) to obtain pre-built version for your platform or install Rust toolchain and do `cargo install moshudp`.

# Help outputs

```
$ moshudp --help
Usage: moshudp <command> [<args>]

mosh-server and mosh-client interconnector based on UDP and a static key file

Options:
  --help            display usage information

Commands:
  serve             server mode
  connect           client mode
  keygen            generate 32-byte random file to use as a key on client and
                    server

$ moshudp serve  --help
Usage: moshudp serve <addr> <keyfile> [-4] [-6]

server mode

Positional Arguments:
  addr              socket address to listen
  keyfile           32-byte file to generate use as a key

Options:
  -4, --ipv4        limit hostname resolution to IPv4 addresses
  -6, --ipv6        limit hostname resolution to IPv6 addresses
  --help            display usage information

$ moshudp connect  --help
Usage: moshudp connect <addr> <keyfile> [-4] [-6] [--ping]

client mode

Positional Arguments:
  addr              socket address to connect
  keyfile           32-byte file to generate use as a key

Options:
  -4, --ipv4        limit hostname resolution to IPv4 addresses
  -6, --ipv6        limit hostname resolution to IPv6 addresses
  --ping            skip most of the algorithm, just send a ping
  --help            display usage information
```

# See also

* The project was inspred by [mosh-mallet](https://gitlab.com/Zinnia_Zirconium/mosh-mallet).
