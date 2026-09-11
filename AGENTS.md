# Project

Go library implementing the Sangfor EasyConnect VPN client protocol. This is a library package (`package easyconnect`), not a standalone binary — the full VPN client lives in a separate project called "digging". The protocol is reverse-engineered from the official Linux EasyConnect client.

The protocol spec is in [PROTOCOL.md](./PROTOCOL.md) — read it before making protocol-level changes.

# Commands

```bash
make test          # go test ./...
make lint          # golangci-lint across linux/android/windows/darwin
make fmt           # golangci-lint fmt
make lint_install  # install golangci-lint
go test -run TestFoo ./...  # run a single test
```

The Makefile sets `GOTOOLCHAIN=local` and unsets `GOROOT`.

# Architecture

The library follows a layered design that mirrors the wire protocol:

**Client lifecycle** — `Client` (client.go) is the public API. It owns data packet queues (incoming/outgoing) and delegates connection management to a supervisor goroutine. Callers read/write IPv4 datagrams through `ReadDataPacket`/`WriteDataPacket`. The client supports `Suspend`/`Resume` for mobile sleep-wake and automatic reconnection with exponential backoff bounded by `ReconnectTimeout`.

**Supervisor** (client_supervisor.go) — runs the connect-authenticate-tunnel loop. It distinguishes terminal errors (bad credentials, TLS trust, unsupported protocol features) from transient ones (network timeouts). A failed tunnel discards the web session and re-authenticates from scratch because the gateway ties the tunnel to the session.

**Web auth** (auth.go) — four sequential HTTPS requests: `login_auth.csp` → `login_psw.csp` → `conf.csp` → `rclist.csp`. The `webSession` carries a TwfID cookie, parsed tunnel parameters, and the resource list. HTTP client setup is in http_client.go; TLS configuration (custom CA, insecure mode) in tls_config.go.

**Tunnel session** (session.go) — opens four TCP connections to the gateway, each preceded by a camouflage TLS handshake (camouflage.go):
- Keepalive channel: `TIMQ`/`ACKQ` heartbeat (keepalive_channel.go)
- Command channel: `JJYY` type 0 → `AABB` with assigned address
- Upload channel: `JJYY` type 5, client-to-server `IPCP` frames
- Receive channel: `JJYY` type 6, server-to-client `IPCP` frames

**Wire protocol** (protocol.go) — encode/parse functions for the five fourcc message types. `TIMQ`/`ACKQ` are big-endian; everything else is little-endian. `IPCP` frames carry IPv4 datagrams XOR'd with 0x40 (payload_encoding.go).

**Resource filter** (resource_filter.go) — drops outbound packets not covered by the published resource list. The gateway disconnects the tunnel over unpermitted traffic.

**Data path** (data_packet_queue.go, data_packet_writer.go, packet_buffer.go) — bounded queues between the public API and the tunnel session, with a dedicated writer goroutine to batch outbound frames. The outgoing queue and its writer goroutine belong to the session, because the upload channel does: a tunnel that ends takes its backlog with it, and the client only has to look up the session that is ready. Writing is fire-and-forget: `WriteDataPacketBuffers` enqueues and returns, and a queue with no room drops the rest of the batch into `DroppedOutgoingDataPackets`. The caller is a packet forwarding loop carrying every other flow of the host, so it must never wait on one stalled socket. Incoming packets take the other rule and block the receive channel instead, which is backpressure the sender can see.

**Data channel liveness** (data_channel_keepalive.go) — the gateway watches the tunnel through the keepalive channel, which is a socket of its own, so a path that stops forwarding the upload and receive connections is invisible to both ends. `DataChannelTimeout` bounds every upload write so such a path is noticed within it. `DataChannelKeepAliveInterval` additionally sends an ICMP echo request through the tunnel while the upload channel is idle, keeping the state tables on the path from dropping the connections in the first place; it is off by default because the reference client sends nothing here. The probe destination is the first address the gateway named that the resource filter permits (conf.csp DNS, then rclist host records, then a single-address resource); a gateway that named none disables the probe rather than the tunnel. Probe replies are filtered out of the receive path, and `DataChannelKeepAliveTimeout` drops a tunnel whose receive channel answers nothing.

**Configuration** (conf.go, tunnel_config.go, resource.go) — parse `conf.csp` XML into tunnel parameters (MTU, DNS, session token from the 64-byte `sslctx` blob) and build the `TunnelConfiguration` struct that callers use to set up the TUN device. `rclist.csp` `<Dns data="id:host:ipv4">` is a static hosts table (often the only resolver: `iptunDns` / `dnsserver` may be `0.0.0.0`); those A records become `Hosts`, host routes, and resource-filter prefixes.

# Key constraints

- IPv4 only — the protocol has no IPv6 path on any layer.
- The camouflage handshake uses compiled-in byte sequences (in `camouflage/` binary files), not a real TLS stack.
- The payload XOR has two implementations selected by build tag
  (payload_encoding_xor.go / payload_encoding_xor_simd.go). Building with
  `GOEXPERIMENT=simd` on Go 1.27+ picks the vectorized one on amd64 and arm64,
  worth roughly 10x on AVX2 and 6x at 128-bit vector width. Every other
  architecture keeps the scalar loop even under that experiment, because the
  simd package emulates vectors in pure Go there and the emulation is four
  times slower than the loop. The default build needs no new toolchain and
  compiles to the same code as before the split.
- Depends on `github.com/sagernet/sing` for buffer management, exception wrapping, and network abstractions.
