# EasyConnect VPN protocol

After a login HTTPS exchange, the data plane runs over a custom fourcc
protocol (not real TLS): a canned camouflage handshake is followed by
`TIMQ`/`ACKQ` keepalive and `JJYY`/`AABB`/`IPCP` L3 framing with a
1-byte XOR on the inner IPv4 payload.

## Layers

```
browser/easyconn  --HTTPS/XML-->  /por/*.csp     (web auth + conf)
CSClient          --unix CMS--->  svpnservice    (CheckReady, TwfID, HELLO)
svpnservice       --TCP :443--->  gateway        (MakeTunnel: TCP + L3VPN)
```

CSClient contains a text protocol `C01`/`C02`/`C03`, but it is **not
sent on the network**. After `CheckReady`, CSClient talks to svpnservice
over `ECDomainFile` (`<Type>HELLO</Type>`, `ProcessTwfID`). The process
that owns `:443` is `svpnservice` `TcpSocket::MakeTunnel`.

MakeTunnel opens **four** TCP connections to `gateway:443`:

| MakeTunnel type | Channel               | Client fourcc | Server fourcc  | After handshake |
|-----------------|-----------------------|---------------|----------------|-----------------|
| (TCP module)    | TCP-proxy keepalive   | `TIMQ` 28 B   | `ACKQ` 60 B    | more TIMQ/ACKQ  |
| 0               | L3 command            | `JJYY` type 0 | `AABB` field 0 | SEND_IP         |
| 5               | L3 TX (client→server) | `JJYY` type 5 | `AABB` field 2 | `IPCP` frames   |
| 6               | L3 RX (server→client) | `JJYY` type 6 | `AABB` field 1 | `IPCP` frames   |

Logs: type 5 → `Server READ OK` (server reads the client's TX);
type 6 → `Server SEND OK` (server writes the client's RX).

Native UDP to the gateway is off (`udpport: 0`). UDP/ICMP/TCP inside the
VPN are IPv4 datagrams carried in `IPCP` on the L3 TX/RX sockets.

## 1. Web auth

All of this is HTTP/1.1 over TLS 1.2. Cookie: `TWFID=<16 hex>`.

| Step | Request                                                    | ClientHello                                      | Notes    |
|------|------------------------------------------------------------|--------------------------------------------------|----------|
| 1    | `GET /por/login_auth.csp?dev=linux&language=en_US&type=cs` | OpenSSL 1.0.2 long cipher list, SNI = hostname   | probe    |
| 2    | `POST /por/login_psw.csp?dev=linux&language=en_US&type=cs` | **one suite from `<EC>`** + SCSV, SNI = hostname | password |

Query names are `dev` (device name) and `language`:

- `login_auth`: `dev` and `language` may be empty or omitted. Returns `ErrorCode=1` + 16-hex TwfID.
  `LoginAuthMessage::parseResponse` never reads `ErrorCode`: it requires `RndImg` to parse, then takes the TwfID and the cipher suite.
- `login_psw`: `language` may be empty or omitted. `dev` must be a non-empty value (`linux` works). Empty/omitted `dev`, or `device=` instead of `dev=`, returns `ErrorCode=20113`. Omitting `type=cs` returns `ErrorCode=20026`.

The `dev` and `language` query values are compile-time constants in the
Linux client (`dev=linux`, `language=en_US`), not derived from the runtime
environment.

| Step | Request                              | ClientHello                                   | Notes         |
|------|--------------------------------------|-----------------------------------------------|---------------|
| 3    | `GET /por/conf.csp`                  | long list, **no SNI**, `Host: <gateway-ip>`   | tunnel config |
| 4    | `GET /por/rclist.csp?rnd=1234`       | same as (3)                                   | resource list |

`rnd` is not an auth parameter and not a nonce: ECAgent has the whole
`/por/rclist.csp?rnd=1234` string compiled in, and the login URLs carry no
`rnd` at all. The response field `RndImg` (0 here: no image code) is unrelated
to it.

`rclist.csp` is two tables. `<Rc host>` is hostname or IPv4 (with a port
range). Domain-only rows have no prefix until `<Dns data="id:host:ipv4;…">`
supplies the A record. `dnsserver` is the optional inner resolver; empty
or `0.0.0.0` means none (`iptunDns` on this gateway is also unspecified).
The official client DNAT UDP/53 to a local stub and answers from that
static table. Without it, prefer-by-resource-hostname still matches, but
resolution is NXDOMAIN and the mapped IPs never enter the tunnel routes.

### TLS for login

- Record version TLS 1.0, hello version TLS 1.2.
- `client_random`: 32 bytes from OpenSSL 1.0.2 `RAND_bytes` (not
  `gmt_unix_time`; `SSL_MODE_SEND_CLIENTHELLO_TIME` is off).
- Session id empty.
- Extensions: SNI, signature_algorithms, heartbeat, NPN (`0x3374`), ALPN
  `http/1.1`, sometimes padding (`0x0015`).
- After `login_auth`, the ClientHello **shrinks** to the single suite named
  in `<SSLCipherSuite><EC>…</EC></SSLCipherSuite>`. This gateway sent
  `AES128-SHA` → `TLS_RSA_WITH_AES_128_CBC_SHA` (0x002f) + SCSV (0x00ff).

### `login_auth` XML (shape)

```xml
<Auth>
  <ErrorCode>1</ErrorCode>
  <Message>login auth success</Message>
  <StartAuth>1</StartAuth>
  <TwfID>…</TwfID>                  <!-- exactly 16 hex chars -->
  <RndImg>0</RndImg>
  <DeviceType>ssl</DeviceType>
  <SSLCipherSuite>
    <EC>AES128-SHA</EC>
  </SSLCipherSuite>
  <RSA_ENCRYPT_KEY>…</RSA_ENCRYPT_KEY>
  <RSA_ENCRYPT_EXP>…</RSA_ENCRYPT_EXP>
  <VPNVERSION>M7.6.8R2</VPNVERSION>
</Auth>
```

### `login_psw`

- Body: `application/x-www-form-urlencoded` with `svpn_name` and
  `svpn_password` (plaintext on this gateway; the RSA key was not used).
- Client sends a doubled cookie prefix: `Cookie: Cookie: TWFID=…`.
- Success returns a **new** 16-hex TwfID.
- The client rejects TwfID whose length is not 16 (`invalid sess size`).
- `PSWAuthMessage` / `parseAuthResult` read the integer `Result`, not `ErrorCode`.
  A missing node fails (sentinel `-99999`); `Result=2` goes on to `NextAuth`,
  which is a further authentication factor rather than a failure. The observed
  success reply carries `Result=1`, `ErrorCode=1` and `pwpErrorCode=0`.
  `ErrorCode` as a string belongs to the CSClient `randtick.csp` path.

## 2. `conf.csp` (tunnel parameters)

Nested cipher / channel-type tags:

```xml
<EC>AES128-SHA</EC>
<TCP>RC4-SHA</TCP>
<L3VPN>RC4-SHA</L3VPN>
<TCP>TCPP</TCP>
<L3VPN>L3IP</L3VPN>
```

- `Htp port="443" mtu="1400"`
- `svpnlanaddr` — assigned virtual address (also delivered later in AABB)
- `sslctx` — 64-byte blob (hex-encoded in the XML attribute)

### `sslctx` layout (64 bytes after hex-decode)

```
[ 0:32]  ASCII hex C-string + NUL   (token)
[32:48]  16 ASCII hex chars         (= TCP-channel session prefix)
[48:64]  16 raw bytes
```

`ConfManager` logs `svpnsessionId is <sslctx[32:48] as text>`.

## 3. Camouflage TLS (not a real handshake)

Every MakeTunnel connection starts with an 82-byte TLS 1.0 ClientHello
advertising **only** `TLS_DHE_RSA_WITH_AES_256_CBC_SHA` (0x0039), no SNI,
no extensions. A real DHE/PRF/Finished handshake never runs.

|       | `client_random`              | `session_id` (32 bytes)                        |
|-------|------------------------------|------------------------------------------------|
| TCP   | last byte `0x33` (reused)    | ASCII-hex(8 bytes) + `'@'` + 15-byte suffix    |
| L3VPN | last byte `0x43` (hardcoded) | 16 raw bytes + `'@'` + **same** 15-byte suffix |

Session id layout: `16 bytes || 0x40 ('@') || 15 bytes`.
TCP session prefix = `sslctx[32:48]` / `svpnsessionId`.

### Client ssl syn (after ServerHello)

Compiled constant, identical on every connection:

```
14 03 01 00 01 01                         # CCS
16 03 01 00 20  2bd1df0e…099c5a0d         # 32-byte canned blob
```

### Server ssl ack

Same record layout as the compiled vector (ServerHello + CCS + 32-byte
blob, advertised cipher 0x0004). The real gateway rewrites
ServerHello.session_id to echo the client's 32-byte id. `RecvV` of ssl ack
does not require that echo; a locally replayed canned ack is enough to
unblock the client, but without a valid `serverMsg` MakeTunnel then fails
(`RecvV serverMsg failed` / `checkHead wrong`).

## 4. TCP channel (`TIMQ` / `ACKQ`)

Not wrapped in TLS records after the camouflage handshake.

### Client `TIMQ` — 28 bytes, big-endian

```
 0  4  magic     "TIMQ"
 4  4  uint32be  type   4 = handshake (`TimeQry::HandShakeServer`), 1 = heartbeat
 8  4  uint32be  seq    `bswap(clock_gettime(CLOCK_MONOTONIC).tv_sec)`
                       (`ECBaseUtil::getSinceStartedUpS`). The handshake and the
                       first heartbeat can share a second; later heartbeats
                       track wall seconds. The gateway echoes the value and also
                       accepts 0 / 0xffffffff / random. Send loop: type 1, then
                       `ECThread::Wait(1)` up to 5 times; one TIMQ per second.
12 16  ASCII hex session prefix (= sslctx[32:48])
```

### Server `ACKQ` — 60 bytes, big-endian

```
 0  4  magic     "ACKQ"
 4  4  uint32be  type   `TimeQry::ProcessServerMsg` jump table (types 0-5):
                       5 = handshake OK (`connect server ok`)
                       1/2 = heartbeat (extra>0 extends the session,
                             extra==0 stops it)
                       3 = timeout (`recv timeout message` → setVpnTimeout
                           + LogoutSvpn)
                       4 = ProcessNewSession
                       0 / >5 = unknown
 8  4  uint32be  seq    (echo of TIMQ seq)
12  4  uint32be  extra  0 on type 5; small integers on type 2
16 16  ASCII hex session (echo)
32 28  payload (zeros, later counters)
```

This channel is the TCP-proxy module keepalive. tun0 IPv4 does **not**
travel here.

## 5. L3 command / TX / RX (`JJYY` / `AABB`)

### Client `JJYY`

The 60-byte body sits in a TLS *application-data* record
`17 03 01 00 3c`, then an 11-byte tail **outside** that record.

```
record  17 03 01 00 3c
body (60):
   0  3  pad          00 00 00
   3  4  magic        "JJYY"
   7  4  uint32le     type   0 = command, 5 = TX, 6 = RX
  11 32  zeros
  43 16  ASCII hex session prefix
  59  1  NUL
tail (11):
   0  7  zeros
   7  4  uint32le     0xffffffff on type 0;
                      tun IPv4 in **little-endian** on type 5/6
```

### Server `AABB` — 40 bytes raw after ssl ack (not in a TLS record)

**Command (MakeTunnel type 0)** — matches
`HandCmdMsg SEND_IP tapip, lanip, enc, zip, udpport`:

```
 0  4  magic        "AABB"
 4  4  uint32le     0
 8  4  tap IPv4     network order
12  4  uint32le     enc    (this gateway: 1)
16  4  IPv4         second address (observed ≠ tapip)
20  4  uint32le     udpport (this gateway: 0)
24  4  uint32le     zip    (this gateway: 3)
28 12  remaining    (opaque / cookies)
```

**TX/RX hello**

```
 0  4  "AABB"
 4  4  uint32le     2 on type-5 TX, 1 on type-6 RX
 8 36  opaque
```

`checkHead` accepts these AABB/ACKQ magics. A fake TLS record in this slot
produces `serverMsg.checkHead wrong`.

## 6. L3 data frames (`IPCP`) — TCP and UDP on the wire

After AABB, type 5 (TX, c2s) and type 6 (RX, s2c) carry length-prefixed
`IPCP` frames. No further TLS records.

```
 0  4  magic        "IPCP"
 4  4  uint32le     total frame length (includes this 12-byte header)
 8  4  uint32le     field, observed 0
12  …  IPv4 datagram XOR 0x40
```

`len - 12` equals the IPv4 `Total Length` field. Observed inner packets:

- IPv4/TCP SYN, SYN-ACK, ACK, PSH+ACK (HTTP `GET /` and `HTTP/1.1 400 …`)
- source = tun address from SEND_IP, destination = routed resource

UDP and ICMP use the same framing with the appropriate IP protocol number.

The SEND_IP knobs `enc: 1` / `zip: 3` correspond to this XOR-0x40 payload.
`svpnservice` also contains `enRc4Key` / `deRc4Key` for a different
encoding path.

## 7. CSClient C01 (compiled in, not on the wire)

Exact format strings in `CSClient`:

```
C01 HELLO\r\nCLIENT: %s/%s\r\n\r\n
C02 AUTH SESSION\r\nID: %s\r\n\r\n
C03 CONNECT RESOURCE\r\nVER: 4\r\nDST: %s %d\r\nTYPE: %s\r\n\r\n
```

`CLIENT` arguments include `MOBILE`. These bytes are not sent over the
network. CSClient's on-wire control is the unix CMS XML (`<BsClient><Type>HELLO</Type>…`,
`TWFID`, `SERVADDR`, conf/rclist blobs).

## 8. Fingerprint table

|             | login probe                        | login POST                      | data plane                                                 |
|-------------|------------------------------------|---------------------------------|------------------------------------------------------------|
| version     | TLS 1.2 (record 1.0)               | TLS 1.2                         | TLS 1.0 **camouflage only**                                |
| suites      | OpenSSL default list               | single suite from `<EC>` + SCSV | advertised **0x0039**; ack vector uses 0x0004              |
| random      | 32B RAND                           | 32B RAND                        | **hardcoded, 2 values**                                    |
| session id  | empty                              | empty                           | **32B, `16 + '@' + 15`** (server echoes it)                |
| SNI         | hostname                           | hostname                        | **none**                                                   |
| extensions  | SNI, sigalgs, heartbeat, NPN, ALPN | same                            | **none**                                                   |
| after hello | HTTP                               | HTTP                            | canned CCS+32B, then `TIMQ`/`ACKQ` or `JJYY`/`AABB`/`IPCP` |

For login HTTPS: replay the cipher list and `client_random` from the probe
ClientHello. For the data plane: splice raw bytes to the gateway (or replay
a valid `serverMsg` AABB/ACKQ). Do not run a real TLS stack.

## 9. IPv6

**The protocol as implemented is IPv4-only**.
