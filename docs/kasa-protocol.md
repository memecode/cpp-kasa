# Kasa and Tapo Local Wire Protocols

This is an implementation-oriented reference for the local protocols implemented
by this checkout of python-kasa. It is not a vendor specification. Device family,
hardware revision, and firmware determine which combinations work; the Kasa or
Tapo brand alone does not select a protocol. Cloud APIs, video streaming, and
device provisioning are outside its scope.

There are two separate choices: the application protocol (the JSON commands)
and the transport (framing, authentication, and encryption). In particular,
KLAP does not imply SMART commands: some devices use IOT commands over KLAP.

## Ports and Protocol Selection

All ports below are destination ports on the device, not required client source
ports. Discovery replies return to the sending UDP socket. Use an ephemeral
client port and keep that socket open while collecting replies.

| Purpose / transport | Carrier | Default device port | Endpoint / framing |
| --- | --- | --- | --- |
| Legacy discovery | UDP | 9999 | XOR JSON, no length prefix |
| Modern discovery | UDP | 20002 and 20004 | 16-byte TDP header + JSON |
| Legacy XOR control | TCP | 9999 | 4-byte length + XOR JSON |
| AES control | HTTP over TCP | 80 | POST `/app` |
| KLAP v1 or v2 control | HTTP over TCP | 80 | POST `/app/handshake1`, `/app/handshake2`, `/app/request` |
| HTTPS KLAP control | HTTPS over TCP | 4433 | Same KLAP endpoints |
| Camera / hub SSL-AES | HTTPS over TCP | 443 | POST `/`, then `/stok=<token>/ds` |
| Older robovac SSL | HTTPS over TCP | 4433 | POST `/app`, then `/app?token=<token>` |
| Legacy Kasa camera LINKIE2 | HTTPS over TCP | 10443 | POST `/data/LINKIE2.json` |

Advertised `mgt_encrypt_schm.http_port` overrides the HTTP-family default in these
transports. An explicit application port override takes precedence. Do not use
the UDP discovery port as the control port for modern devices.

[device_factory.py](kasa/device_factory.py) selects these principal combinations:

| Discovered family / encryption | Application protocol | Transport |
| --- | --- | --- |
| IOT / XOR, except IP cameras | IOT | XOR |
| IOT / KLAP | IOT | KLAP v1; v2 when login version is at least 2 |
| SMART / AES, without HTTPS | SMART | AES |
| SMART / KLAP, with or without HTTPS | SMART | KLAP v2 |
| SMART camera families; SMART / AES with HTTPS | SMART camera | SSL-AES |
| IOT.IPCAMERA | IOT camera commands | LINKIE2 |
| SMART.TAPOROBOVAC / AES, older firmware | SMART | SSL without inner AES |

These are supported combinations, not an instruction to blindly try every
transport against every device. Prefer discovery and handle unknown combinations
explicitly. Firmware updates can change the transport.

## Encoding Conventions

JSON is UTF-8. Examples use compact JSON; do not send Markdown fences. `||` means
byte concatenation. Unless explicitly called hexadecimal, a hash means the raw
digest bytes. `B64` is standard Base64, not URL-safe Base64. AES below means
AES-128-CBC with PKCS#7 padding to a 16-byte block boundary, including a full
padding block when the plaintext is already block-aligned.

Use standard HTTP framing for HTTP-family transports: a correct `Content-Length`
for request bytes, and normal HTTP response framing and decompression. Do not
prepend the XOR TCP length field to HTTP bodies. Preserve cookies and tokens
for the session as described below. HTTP status 200 alone does not mean the
command succeeded: also check JSON error codes after each decoding layer.

## Legacy XOR Transport

The reference implementation is [xortransport.py](kasa/transports/xortransport.py).
Control uses TCP port **9999** by default. Discovery uses UDP port **9999**.
No login, session key, integrity tag, or TLS is involved. XOR is obfuscation,
not secure encryption; use only on a trusted network.

### TCP Frame

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 4 bytes | Unsigned big-endian length N of the encrypted JSON body |
| 4 | N bytes | XOR-encrypted UTF-8 JSON |

The length excludes the four-byte header. Requests and responses use the same
format. TCP is a byte stream: read exactly four bytes, decode N, then read
exactly N bytes. Do not assume one socket read equals one message. Apply a
reasonable maximum length before allocating a buffer. Connections can be reused;
serialize requests and match each to its response.

### XOR Algorithm

Start each message with an unsigned eight-bit state of `0xAB`. For each plaintext
byte, emit `cipher = plaintext XOR state`, then set `state = cipher`. To decrypt,
emit `plaintext = cipher XOR state`, then set `state = cipher` using the original
ciphertext byte. Reset state for each message, not for each TCP read.

The four-byte length is not encrypted. There is no padding, NUL terminator, or
newline. Lengths count UTF-8 bytes, not characters.

For plaintext `{}`, the encrypted body is `D0 AD`, and the complete TCP frame is:

```text
00 00 00 02 D0 AD
```

### UDP Discovery

Send the XOR-encrypted UTF-8 JSON below to the broadcast address or a specific
device at UDP port 9999. **Omit the four-byte TCP length header.** Decrypt the
entire response datagram with the same initial state of `0xAB` and parse JSON.

```json
{"system":{"get_sysinfo":{}}}
```

The response contains `system.get_sysinfo`, with model, device identity, and
capability information. The JSON whitespace used by an encoder is not part of
the protocol. Broadcast requires the socket's broadcast option and a reachable
local broadcast domain.

## Modern UDP Discovery

The implementation is in [discover.py](kasa/discover.py), primarily
`_AesDiscoveryQuery.generate_query` and `Discover._get_discovery_json`.
The older overview in [topics.md](docs/source/topics.md) mentions two discovery
ports; this checkout actually probes **9999, 20002, and 20004**.

Send the same modern probe to UDP ports 20002 and 20004, either broadcast or
unicast. The library sends three rounds by default over a five-second window;
these are retry policy, not wire requirements. Discovery does not require an
account login. Deduplicate replies and retain the actual source IP address.

### Probe Header

The datagram is a 16-byte header followed by plaintext UTF-8 JSON. All multibyte
integers in the header are big-endian. This is the request layout; do not assume
responses repeat the request's opcode or flags.

| Offset | Size | Request field | Value |
| --- | --- | --- | --- |
| 0 | 1 | Version | 2 |
| 1 | 1 | Message type | 0 |
| 2 | 2 | Operation code | 1 (probe) |
| 4 | 2 | JSON body length | N, excluding header |
| 6 | 1 | Flags | 17 (`0x11`) |
| 7 | 1 | Padding | 0 |
| 8 | 4 | Device serial / request identifier | Random 4 bytes |
| 12 | 4 | CRC-32 | See calculation below |
| 16 | N | JSON body | RSA public-key payload |

Generate an RSA-2048 key pair with public exponent 65537. Encode the public key
as PEM SubjectPublicKeyInfo (`BEGIN PUBLIC KEY`), including PEM newlines as
escaped newlines inside the JSON string:

```json
{"params":{"rsa_key":"-----BEGIN PUBLIC KEY-----\n<base64 DER key>\n-----END PUBLIC KEY-----\n"}}
```

To compute the checksum, first write `5A 6B 7C 8D` into bytes 12..15. Calculate
standard IEEE CRC-32 over the **entire header and JSON body**, with the usual
zlib/binascii CRC-32 convention (not CRC-32C). Replace bytes 12..15 with that
checksum in big-endian order. When validating a packet checksum, restore that
placeholder in a temporary copy before recomputing. The checksum field is not
zeroed for this calculation.

### Reply and Encryption Negotiation

Replies also have a 16-byte prefix followed by JSON. The current Python reader
simply parses `datagram[16:]`; it does not verify response header fields or CRC.
A defensive implementation should at least enforce size limits and valid JSON;
strict header validation needs captures from the target firmware.

A representative, abbreviated reply is:

```json
{"error_code":0,"result":{"device_type":"SMART.TAPOPLUG","device_model":"P100","device_id":"...","ip":"192.0.2.10","mac":"00-11-22-33-44-55","mgt_encrypt_schm":{"is_support_https":false,"encrypt_type":"KLAP","http_port":80,"lv":2}}}
```

Use `result.device_type` plus `result.mgt_encrypt_schm` to select application
protocol, encryption, HTTPS, port, and login version. `lv` is the login version,
not a general command-set version. If `encrypt_type` is absent from
`mgt_encrypt_schm`, the implementation falls back to `result.encrypt_info.sym_schm`.
If `lv` is missing/falsy, it uses the maximum integer in the top-level
`result.encrypt_type` list, when present. An HTTPS camera advertising version 3
without an explicit encryption name is treated as AES. Preserve unknown fields.

Some replies contain `result.encrypt_info` with `sym_schm: "AES"`, `key`, and
`data`. These protect additional discovery metadata, not the whole reply:

1. Base64-decode `key` and RSA-decrypt with the probe's private key using
	**OAEP with SHA-1 and MGF1-SHA-1, empty label**.
2. Split the decrypted 32 bytes into a 16-byte AES key and 16-byte IV.
3. Base64-decode `data`, AES-CBC-decrypt, remove PKCS#7 padding, then parse JSON.

The discovery RSA key is 2048 bits and uses OAEP; the HTTP AES handshake below
uses a different key size and RSA padding. Do not mix them up. Basic metadata
can still be usable if optional encrypted metadata cannot be decrypted.

## HTTP AES Transport

Reference: [aestransport.py](kasa/transports/aestransport.py). This is the
non-HTTPS `/app` transport, not the camera SSL-AES transport. Its state machine
is handshake, encrypted login, then encrypted application requests.

### RSA Handshake

Generate an RSA-1024 key pair with exponent 65537. POST to `http://DEVICE:80/app`
(or the selected port), using these headers:

```text
Content-Type: application/json
Accept: application/json
requestByApp: true
Content-Length: <actual body byte count>
```

The request body is:

```json
{"method":"handshake","params":{"key":"-----BEGIN PUBLIC KEY-----\n<single-line base64 SubjectPublicKeyInfo DER>\n-----END PUBLIC KEY-----\n"}}
```

The implementation's compact JSON with this key layout is 314 bytes and sends
that explicit length; devices may reject chunked handshakes. Do not hard-code
314 if your serialization differs: send the actual length and preserve the
shown key layout for compatibility.

A successful response has `error_code: 0` and `result.key`. Base64-decode this
key and RSA-decrypt it with **PKCS#1 v1.5 encryption padding**, not OAEP. The
32-byte plaintext is `AES_key[16] || IV[16]`. Retain the session cookie
`TP_SESSIONID`; if the response uses `SESSIONID`, the Python implementation
re-sends its value under the name `TP_SESSIONID`.

### Secure Passthrough Envelope

Encrypt the inner JSON bytes using the negotiated key and IV, then Base64-encode
the ciphertext. POST this outer JSON to `/app` before login, or
`/app?token=<token>` after login, with the session cookie:

```json
{"method":"securePassthrough","params":{"request":"<base64 AES ciphertext>"}}
```

The reply normally looks like:

```json
{"error_code":0,"result":{"response":"<base64 AES ciphertext>"}}
```

Check the outer error, decrypt `result.response` using the same AES key and IV,
unpad, and parse the inner JSON; then check its error code. Each encryption starts
a fresh CBC operation with the session IV; there is no per-request IV prefix or
MAC in this transport. Some firmware returns a JSON string without inner
encryption in `result.response`, which the library also accepts.

### Encrypted Login

The inner login JSON is:

```json
{"method":"login_device","params":{"username":"<encoded username>","password":"<encoded password>"},"request_time_milis":1700000000000}
```

`request_time_milis` is the literal field spelling and is Unix time in
milliseconds. Credential transformations are:

| Field | Login version 1 / unspecified | Login version 2 |
| --- | --- | --- |
| `username` | B64(ASCII(lowercase hex SHA1(UTF8(username)))) | Same |
| Password field | `password` | `password2` |
| Password value | B64(UTF8(password)) | B64(ASCII(lowercase hex SHA1(UTF8(password)))) |

The hash is hexadecimal text **before** Base64, not the 20 raw digest bytes.
The successful decrypted reply supplies `result.token`. Keep both token and
cookie for later application requests. A `TIMEOUT` cookie supplies the session
lifetime in seconds; absent that, Python assumes 86400 seconds and renews
20 minutes early. Do not echo the `TIMEOUT` cookie. Re-handshake after an
authentication failure rather than repeatedly attempting login on stale keys.

## KLAP v1 and v2

Reference: [klaptransport.py](kasa/transports/klaptransport.py). Both versions
use the same binary request encryption but different authentication hashes.
They normally use HTTP port 80; HTTPS KLAP defaults to port 4433.
Credential strings are case-sensitive UTF-8; do not lowercase the email address.

### Authentication Hashes

Let `U` and `P` be username and password bytes, `L` a fresh 16-byte client seed,
and `R` a 16-byte server seed. Hash outputs in this section are **raw bytes**.

| Value | KLAP v1 | KLAP v2 |
| --- | --- | --- |
| Auth hash A | MD5(MD5(U) \|\| MD5(P)) | SHA256(SHA1(U) \|\| SHA1(P)) |
| Server proof | SHA256(L \|\| A) | SHA256(L \|\| R \|\| A) |
| Client proof | SHA256(R \|\| A) | SHA256(R \|\| L \|\| A) |

The MD5 digests in v1 are 16-byte binary values, not 32-character hex strings.
The SHA1 digests in v2 are 20-byte binary values. A is 16 bytes for v1 and
32 bytes for v2.

### Two HTTP Handshakes

1. POST the raw 16 bytes `L` to `/app/handshake1`. The successful HTTP 200 body
	is exactly `R[16] || server_proof[32]`, totaling 48 bytes. Verify the proof
	against A before continuing. Save the `TP_SESSIONID` response cookie.
2. POST the raw 32-byte client proof to `/app/handshake2`, sending
	`Cookie: TP_SESSIONID=<value>`. HTTP 200 completes the handshake; no JSON
	login or additional token is used.

Bodies are binary, not JSON, hexadecimal, or Base64. The implementation first
checks supplied credentials, then known factory credentials, then empty strings
where applicable. Some unbound devices accept empty credentials. See
[credentials.py](kasa/credentials.py) for the compatibility credential values;
they are not substitutes for the owner's account on an already bound device.
Use only credentials authorized for the device.

`TIMEOUT` is a lifetime hint in seconds, not a cookie to send back. The Python
client defaults to a day and renews 20 minutes early, as for HTTP AES.

### Key and Sequence Derivation

Let `S = L || R || A`. The quoted prefixes below are literal lowercase ASCII:

```text
key         = SHA256("lsk" || S)[0:16]
iv_hash     = SHA256("iv"  || S)
iv_prefix   = iv_hash[0:12]
initial_seq = signed_big_endian_int32(iv_hash[28:32])
sig_prefix  = SHA256("ldk" || S)[0:28]
```

The initial sequence uses the **last four bytes of the full 32-byte digest**,
not bytes 12..15. Before encrypting each request, increment the sequence by one.
Encode that value as four-byte big-endian two's-complement for cryptographic
inputs, and as a signed decimal string for the URL query parameter. Python
does not implement overflow wrapping; establish a fresh session before signed
32-bit overflow. Avoid signed-overflow undefined behavior in C++.

### Request and Response Bodies

For the current incremented sequence `seq`:

```text
seq_bytes  = BE32(seq)
iv         = iv_prefix || seq_bytes
ciphertext = AES_CBC_ENCRYPT(key, iv, PKCS7(UTF8(application_json)))
signature  = SHA256(sig_prefix || seq_bytes || ciphertext)
body       = signature[32] || ciphertext
```

POST to `/app/request?seq=<signed-decimal-seq>` with the session cookie. The
32-byte signature is a keyed-prefix SHA-256 construction, **not HMAC-SHA256**.
HTTP provides the body length; there is no additional binary length field.

A successful HTTP 200 response is also a 32-byte prefix followed by AES
ciphertext. The current reader skips the prefix, decrypts with the **same IV
and sequence as the request**, unpads, then parses JSON. It does not authenticate
the response prefix; this document does not claim a verified response-tag
validation algorithm. Do not increment seq again for response decryption.
Keep only one request in flight per session so the reply uses the correct IV.
On HTTP 403, discard the session and perform a new handshake before retrying.

## Application JSON Commands

These JSON objects are the plaintext passed into the selected transport. They
are not the HTTP AES outer `securePassthrough` envelope. Features vary by model;
query identity and capabilities first rather than probing arbitrary commands.
The examples are wire JSON, not the dictionaries returned by Python's public API,
which sometimes unwraps or normalizes responses.

### IOT Command Format

References: [iotprotocol.py](kasa/protocols/iotprotocol.py),
[iotdevice.py](kasa/iot/iotdevice.py), [iotplug.py](kasa/iot/iotplug.py),
and [iotbulb.py](kasa/iot/iotbulb.py).

IOT requests have the shape `{"<module>":{"<command>":{<arguments>}}}`.
Start with a system information request:

```json
{"system":{"get_sysinfo":{}}}
```

A plug's relay can be switched on with:

```json
{"system":{"set_relay_state":{"state":1}}}
```

Use integer `0` for off, not the SMART `device_on` field. A typical acknowledgement
is:

```json
{"system":{"set_relay_state":{"err_code":0}}}
```

Replies mirror module and command nesting. Check each command's `err_code`;
nonzero is failure, and `err_msg` can provide detail. Do not confuse IOT
`err_code` with SMART `error_code`. Multiple modules/commands can share an
object, subject to firmware limits; a module can also report its own error.

For energy-capable legacy plugs, a common read is:

```json
{"emeter":{"get_realtime":{}}}
```

Some bulb families use `smartlife.iot.common.emeter` instead of `emeter`.
Energy values differ by firmware: fields such as `power` and `power_mw` do
not share units. Inspect actual response keys before converting.

For a legacy bulb, the module and state fields differ from a relay:

```json
{"smartlife.iot.smartbulb.lightingservice":{"transition_light_state":{"on_off":1,"brightness":50,"transition_period":0}}}
```

Capability-dependent light fields include `hue`, `saturation`, and `color_temp`.
Do not assume all bulbs support them.

IOT strip outlets are addressed through the parent's transport using a top-level
context, with the exact child identifier returned by the device:

```json
{"context":{"child_ids":["<child-id>"]},"system":{"set_relay_state":{"state":1}}}
```

### SMART Command Format

Reference: [smartprotocol.py](kasa/protocols/smartprotocol.py).
SMART uses `method` plus optional `params`. The library adds a Unix millisecond
timestamp and a client identifier. To match its behavior, generate one
`terminal_uuid` per client protocol instance as Base64 of the raw 16-byte MD5
digest of a random UUID's 16 bytes; keep it stable for that instance. The value
is not an authentication token.

```json
{"method":"get_device_info","request_time_milis":1700000000000,"terminal_uuid":"<client-id>"}
```

This returns `{"error_code":0,"result":{...}}`. On a switchable device:

```json
{"method":"set_device_info","params":{"device_on":true},"request_time_milis":1700000000000,"terminal_uuid":"<client-id>"}
```

Use JSON boolean `false` for off. A setter may reply with only `{"error_code":0}`
and no `result`. Device strings such as `nickname` and `ssid` may themselves be
Base64-encoded UTF-8; transport decryption does not decode those fields.

The initial SMART capability query is `component_nego`; component versions
determine supported modules and request details. Other common reads include
`get_energy_usage`, `get_child_device_list`, and `get_child_device_component_list`,
but only on devices supporting those components.

Batching uses `multipleRequest` with a capital R:

```json
{"method":"multipleRequest","params":{"requests":[{"method":"get_device_info"},{"method":"get_energy_usage"}]},"request_time_milis":1700000000000,"terminal_uuid":"<client-id>"}
```

Results are in `result.responses`, usually with `method`, `error_code`, and
`result` per entry. Check outer and per-entry errors and match by method, not
just position. Python defaults to five requests per batch, falls back to singles
for some failures, and re-queries missing methods. Five is not a universal device
limit. Single queries are the simplest initial C++ implementation.

List responses may contain `start_index`, `sum`, and a list. Continue requesting
with `params.start_index` until all entries are retrieved; stop on an empty page
to avoid an infinite loop. This is application-level pagination, not network
packet fragmentation.

### SMART Child Routing

Use a parent's authenticated connection and wrap the child's command as follows:

```json
{"method":"control_child","params":{"device_id":"<child-id>","requestData":{"method":"set_device_info","params":{"device_on":true}}},"request_time_milis":1700000000000,"terminal_uuid":"<client-id>"}
```

The outer result contains `responseData`, which has its own `error_code` and
optional `result`. Discover child IDs rather than deriving them from MAC
addresses or socket numbers. `requestData`/`responseData` are case-sensitive.

## Camera and Other HTTPS Variants

These transports are included because the library supports more than legacy
Kasa plugs. They are not needed for an XOR-only implementation, and their
command sets must not be substituted for ordinary SMART plug commands.

### Camera / Hub SSL-AES Login

Reference: [sslaestransport.py](kasa/transports/sslaestransport.py). Default
endpoint is `https://DEVICE:443/`. Unlike HTTP AES, this does not use RSA or
`login_device`. Headers used by the library include:

```text
Content-Type: application/json; charset=UTF-8
requestByApp: true
Accept: application/json
Accept-Encoding: gzip, deflate
User-Agent: Tapo CameraClient Android
Host: DEVICE:443
Referer: https://DEVICE:443
```

Let `HEX256(x)` and `HEXMD5(x)` mean uppercase hexadecimal hash text, and
`ASCII(x)` its text bytes. In the formulas below all nonces and hashes are text
unless a raw SHA256 digest is explicitly requested. Generate the client nonce
`C` as uppercase hex of eight random bytes (16 characters).

POST a first login request to `/`:

```json
{"method":"login","params":{"cnonce":"<C>","encrypt_type":"3","username":"<username>"}}
```

The expected challenge is HTTP 200 with `error_code: -40413` (`INVALID_NONCE`),
and `result.data.nonce` (server nonce `N`) plus `result.data.device_confirm`.
This particular nonzero code is an expected handshake step, not a completed
login failure. Try `H = HEX256(UTF8(password))`, then
`H = HEXMD5(UTF8(password))` if the first confirmation does not match:

```text
Q                = HEX256(ASCII(C || H || N))
expected_confirm = Q || N || C
digest_passwd    = HEX256(ASCII(H || C || N)) || C || N
```

Verify `device_confirm == expected_confirm`, then POST to `/`:

```json
{"method":"login","params":{"cnonce":"<C>","encrypt_type":"3","digest_passwd":"<digest_passwd>","username":"<username>"}}
```

The successful result supplies `stok` and `start_seq`. Derive key and IV as
**raw** digest slices:

```text
key = SHA256(ASCII("lsk" || C || N || Q))[0:16]
iv  = SHA256(ASCII("ivb" || C || N || Q))[0:16]
```

Send later requests to `/stok=<stok>/ds`, not `/app?token=...`. Encrypt inner
JSON with the key and IV, then use the same Base64 `securePassthrough` envelope
shape as HTTP AES. Unlike KLAP, the IV does not incorporate the sequence.
Serialize the envelope once as bytes B and send **those exact JSON bytes** with:

```text
Seq: <current sequence as decimal>
Tapo_tag: <tag>

T   = HEX256(ASCII(H || C))
tag = HEX256(ASCII(T) || B || ASCII(decimal(sequence)))
```

Use `start_seq` for the first request, then increment after constructing each
request. Changing JSON whitespace, order, or escaping after computing the tag
will invalidate it. Both tag hashes are uppercase hex text, not raw digest bytes.
This tag is not HMAC. Responses may contain encrypted `result.response`, a
plaintext JSON string there, or direct unencrypted JSON. Here "unencrypted"
means without inner AES; HTTPS still protects the connection. HTTP 401 can
indicate an expired session. Another session from the same host may invalidate
keys and cause HTTP 500 or decryption errors.

Some firmware advertises an older login instead of type 3. The implemented
fallback posts `{"method":"login","params":{"hashed":true,"password":"<uppercase MD5 password hex>","username":"<username>"}}`
to `/`, then sends plain JSON over HTTPS to `/stok=<stok>/ds` using the returned
`stok`, without inner AES or sequence/tag headers. Username and default-credential
selection differ by camera login version; see the transport and
[credentials.py](kasa/credentials.py). Do not repeatedly guess credentials:
devices can return a blocked interval in `data.sec_left`.

### Camera Application JSON

Reference: [smartcamprotocol.py](kasa/protocols/smartcamprotocol.py).
Single camera operations often use `get`, `set`, or `do` and a named module
directly at the top level, rather than the ordinary SMART `params` layout:

```json
{"method":"get","device_info":{"name":["basic_info","info"]}}
```

Some firmware omits `error_code` in single responses; returned module data can
be at the root. Batched camera methods instead use named requests, for example:

```json
{"method":"multipleRequest","params":{"requests":[{"method":"getDeviceInfo","params":{"device_info":{"name":["basic_info","info"]}}}]}}
```

Camera/hub child routing differs again: `controlChild`, `childControl`, and
`request_data`, not ordinary SMART `control_child` and `requestData`:

```json
{"method":"multipleRequest","params":{"requests":[{"method":"controlChild","params":{"childControl":{"device_id":"<child-id>","request_data":{"method":"get_device_info","params":null}}}}]}}
```

The corresponding inner reply is in each batch entry's
`result.response_data`; check its error code as well. Child command families
depend on the hub-attached device.

### Older Robovac SSL Transport

Reference: [ssltransport.py](kasa/transports/ssltransport.py).
POST `{"method":"login","params":{"username":"<literal username>","password":"<uppercase MD5 password hex>"}}`
to `https://DEVICE:4433/app`. On success take `result.token` and POST ordinary
SMART JSON to `/app?token=<token>`. There is **no inner AES or securePassthrough**
in this transport; TLS provides encryption. Later firmware can use KLAP instead.

### Legacy Kasa Camera LINKIE2

Reference: [linkietransport.py](kasa/transports/linkietransport.py).
POST to `https://DEVICE:10443/data/LINKIE2.json` with HTTP Basic authentication
using the `KASACAMERA` compatibility credentials in
[credentials.py](kasa/credentials.py). This implementation uses that fixed
credential pair rather than the configured cloud account.

Set `Content-Type: application/x-www-form-urlencoded`. The body is
`content=<percent-encoded Base64 of XOR-encrypted JSON>`. XOR uses initial state
`0xAB` and **no four-byte length prefix**. Percent-encode Base64 characters such
as `+`, `/`, and `=` so form decoding does not change them. A normal response
body is raw Base64 text; Base64-decode, XOR-decrypt, then parse JSON. Errors may
instead be returned as plaintext JSON. Although this transport exists, automatic
legacy camera device-class selection is disabled in
[device_factory.py](kasa/device_factory.py); do not infer complete camera support
from transport support alone.

## Implementation Notes for C++

1. Start with discovery and the port/transport selection table. For a known
	legacy plug, implement XOR plus `get_sysinfo` first. For modern devices,
	implement the advertised transport before adding more commands.
2. Keep application commands separate from transport sessions. Use explicit
	byte buffers for digests and ciphertext; never treat them as NUL-terminated
	strings. JSON strings and hash hex text are a different type of data.
3. Use a maintained HTTP/TLS implementation such as libcurl, a JSON library,
	and OpenSSL EVP or an equivalent cryptographic library. Select RSA padding,
	CBC padding, hash output encoding, and byte order explicitly. Use a
	cryptographic RNG for seeds, nonces, and RSA keys.
4. Serialize operations per device/session. Read whole TCP frames or HTTP
	bodies, validate lengths and padding, and set connection/read timeouts.
	Reconnect or reauthenticate after session loss; do not reuse an uncertain
	KLAP sequence/IV state.
5. Distinguish connection failure, HTTP failure, outer envelope failure, and
	inner command failure. SMART success is `error_code == 0`; IOT success is
	per-command `err_code == 0`. Preserve unknown codes and error details.
	Common SMART codes include `-1501` (login error), `-40401` (session expired),
	`-1003` (JSON decode failure), and `-40210` (protocol format error). See
	[exceptions.py](kasa/exceptions.py) for the complete implemented mapping.
6. Retry reads conservatively. A timed-out write may already have executed;
	avoid automatic retries of non-idempotent operations such as toggles or
	relative adjustments. Prefer setting an explicit state and reading it back.
7. Discover capability/version information before choosing modules. Fixtures
	show model-specific fields and units; they are not a guarantee for every
	firmware. Some devices crash on unexpected module queries.
8. Treat local credentials, cookies, and tokens as secrets. The current Python
	HTTPS context disables hostname and certificate verification for local
	devices and adds legacy TLS cipher suites for compatibility; see
	[sslcontext.py](kasa/transports/sslcontext.py). A C++ client should make that
	trust decision explicit, preferably with device pinning where feasible.
	Do not assume these local protocols are safe to expose to the Internet.

## Sources and Conformance Checks

The existing [protocol overview](docs/source/topics.md) explains the historical
IOT/SMART and transport split. Where its older port summary differs, the current
implementation is the authority used here. Additional implementation references:

- [discovery tests](tests/test_discovery.py) and
	[discovery fixture helpers](tests/discovery_fixtures.py) for negotiation and metadata.
- [IOT protocol tests](tests/protocols/test_iotprotocol.py) and
  [SMART protocol tests](tests/protocols/test_smartprotocol.py) for command envelopes.
- [AES tests](tests/transports/test_aestransport.py),
  [KLAP tests](tests/transports/test_klaptransport.py), and
  [SSL-AES tests](tests/transports/test_sslaestransport.py) for handshakes,
  credentials, session behavior, and encryption round trips.
- [Device fixtures](tests/fixtures) for model-specific captured/normalized JSON.
  These are not raw packet captures; placeholders and redacted identities must
  not be copied as actual device IDs or credentials.

Earlier research linked by the implementation is useful background, not a
replacement for the current code:

- [Legacy HS110 reverse engineering](https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/).
- [Original KLAP notes](https://gist.github.com/chriswheeldon/3b17d974db3817613c69191c0480fe55)
  and [python-kasa KLAP integration](https://github.com/python-kasa/python-kasa/pull/117).
- [plugp100](https://github.com/petretiandrea/plugp100), credited by the HTTP AES implementation.
- [TDP research](https://labs.withsecure.com/advisories/tp-link-ac1750-pwn2own-2019),
  linked by discovery's header construction.

For a C++ port, compare against the XOR `{}` vector above, construct a discovery
datagram with a fixed serial and verify its CRC, then use fixed KLAP seeds and
credentials to compare proof bytes, derived key/IV/sequence, and the complete
encrypted request against Python. Finally capture traffic to an owned device
to verify firmware-specific behavior. This document was derived from code and
fixtures, not a fresh live-device capture; notably, discovery response header
validation and KLAP response-signature verification are not established here.

