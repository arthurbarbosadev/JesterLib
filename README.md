# Jester

A TypeScript implementation of the WhatsApp Web (multi-device) protocol, written
from scratch.

This is not a wrapper around an existing client. The transport, the Noise
handshake, the binary XML, the protobuf runtime and the Curve25519 signatures
are all implemented here — and every layer is documented and tested in
isolation, so you can read it to understand how WhatsApp Web actually works.

```
WebSocket  →  3-byte frames  →  Noise XX  →  WABinary nodes  →  your code
```

> **Status: not usable end to end yet.** Everything up to and including QR
> pairing works and is tested. The Signal layer (message encryption) is not
> implemented, so you cannot send or receive messages yet. See
> [Roadmap](#roadmap).

---

## Contents

- [Why this exists](#why-this-exists)
- [Install](#install)
- [One required setup step](#one-required-setup-step)
- [Quick start](#quick-start)
- [Persisting credentials](#persisting-credentials)
- [Reconnecting](#reconnecting)
- [Sending and receiving raw nodes](#sending-and-receiving-raw-nodes)
- [How the protocol works](#how-the-protocol-works)
- [API reference](#api-reference)
- [Project layout](#project-layout)
- [Design decisions](#design-decisions)
- [Testing](#testing)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [Legal and safety](#legal-and-safety)

---

## Why this exists

WhatsApp has no public API for personal accounts. Every unofficial client works
by impersonating a **companion device** — the same role WhatsApp Web plays when
you scan that QR code from your phone.

Existing implementations work, but they are large and hard to learn from. Jester
has two goals:

1. **Be readable.** Each layer is a small module with a doc comment explaining
   not just *what* it does but *which mistakes* break it. The protocol has a lot
   of failure modes that surface only as "the server closed the connection", and
   those are called out in the code.
2. **Keep all state serializable.** No key material hidden in closures, no
   memory-only session state. The process holding the socket should be
   disposable: kill it, start another one, resume without a new QR scan.

## Install

```bash
npm install jesterlib
```

Requires **Node 22+** (for native X25519 and Ed25519 in `node:crypto`).

Runtime dependencies are just `ws` and `@noble/curves`.

## One required setup step

WABinary — WhatsApp's binary XML — replaces frequent strings (`message`, `from`,
`s.whatsapp.net`…) with 1- or 2-byte indexes into a dictionary. That dictionary
is **data, not logic**: it lives in the WhatsApp Web bundle and changes between
versions.

Jester deliberately does not ship a hand-written copy. A single token out of
order shifts every token after it, and the stream breaks *silently* — the server
just closes the connection with no readable error. Instead you generate it:

```bash
npm i -D baileys       # reference package, MIT licensed
npm run vendor:tokens  # writes src/binary/tokens.generated.ts
```

You can remove the reference package afterwards — only the data stays. If you
skip this step, the first encode throws `MissingTokenDictionaryError` with these
instructions.

The entire codec is independent of this table and is tested against a synthetic
dictionary, so correctness of the codec does not depend on getting the vendoring
right.

## Quick start

```ts
import { initAuthCreds, makeInMemoryKeyStore, JesterSocket } from 'jesterlib'

const socket = new JesterSocket({
  auth: {
    creds: initAuthCreds(),
    keys: makeInMemoryKeyStore(),
  },
})

socket.on('connection.update', ({ connection, qr, lastDisconnect }) => {
  if (qr) {
    // Render this string as a QR code and scan it from
    // WhatsApp → Linked devices → Link a device
    console.log(qr)
  }

  if (connection === 'open') {
    console.log('connected as', socket.auth.creds.me?.id)
  }

  if (connection === 'close') {
    console.log('closed:', lastDisconnect?.error?.message)
  }
})

socket.on('creds.update', creds => {
  // persist these — see below
})

await socket.connect()
```

To turn the `qr` string into something scannable, use any QR library, for
example:

```ts
import qrcode from 'qrcode-terminal'

if (qr) qrcode.generate(qr, { small: true })
```

## Persisting credentials

**This is the part that matters.** Without persistence you get a new QR code on
every restart.

The credentials object is plain serializable data, but it contains `Buffer`
fields that do not survive a naive `JSON.stringify`. Jester ships a replacer and
reviver that handle it:

```ts
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { initAuthCreds, serializeCreds, deserializeCreds, makeInMemoryKeyStore } from 'jesterlib'

const FILE = './auth.json'

const creds = existsSync(FILE)
  ? deserializeCreds(readFileSync(FILE, 'utf-8'))
  : initAuthCreds()

const socket = new JesterSocket({ auth: { creds, keys: makeInMemoryKeyStore() } })

socket.on('creds.update', updated => {
  writeFileSync(FILE, serializeCreds(updated))
})
```

For anything beyond a single local process, implement the `SignalKeyStore`
interface against your own storage. It is deliberately narrow — batched `get`
and batched `set` — so a Postgres, Redis or Supabase adapter can implement it
without a round-trip per key:

```ts
interface SignalKeyStore {
  get<T extends keyof SignalDataTypeMap>(
    type: T,
    ids: string[],
  ): Promise<{ [id: string]: SignalDataTypeMap[T] }>

  set(data: SignalDataSet): Promise<void>   // a null value deletes the key
  clear?(): Promise<void>
}
```

> **Note:** the credentials contain your device's private keys. Treat
> `auth.json` like a password file — anyone who copies it can impersonate your
> linked device. Do not commit it.

## Reconnecting

Two things surprise people here, and both are normal protocol behaviour:

**After a successful pairing, the server closes the connection** with
`stream:error code="515"` (`restartRequired`). Your credentials are already
saved at that point. Just reconnect — the second connection uses the login
payload instead of asking for a QR.

**A `JesterSocket` is single-use.** Reconnecting means creating a new instance
with the same credentials.

```ts
import { JesterSocket, ConnectionError, DisconnectReason } from 'jesterlib'

function start(creds) {
  const socket = new JesterSocket({ auth: { creds, keys } })

  socket.on('connection.update', ({ connection, lastDisconnect }) => {
    if (connection !== 'close') return

    const code = (lastDisconnect?.error as ConnectionError)?.code

    // Only a logout is final; everything else is worth retrying.
    if (code !== DisconnectReason.loggedOut) {
      setTimeout(() => start(creds), 3000)
    }
  })

  socket.connect()
  return socket
}
```

| `DisconnectReason` | Meaning | Reconnect? |
|---|---|---|
| `restartRequired` (515) | Normal right after pairing | yes, immediately |
| `connectionClosed` (428) | Socket dropped | yes |
| `connectionLost` / `timedOut` (408) | Network problem | yes, with backoff |
| `connectionReplaced` (440) | Another session took over | no, unless you meant to |
| `loggedOut` (401) | Device unlinked from the phone | no — discard credentials |

## Sending and receiving raw nodes

Once connected, all traffic is a tree of `BinaryNode`s — the binary equivalent
of an XMPP stanza:

```ts
type BinaryNode = {
  tag: string
  attrs: Record<string, string>
  content?: BinaryNode[] | string | Buffer
}
```

`query()` sends a node and waits for the reply carrying the same `id`,
generating one if you do not supply it:

```ts
const result = await socket.query({
  tag: 'iq',
  attrs: { to: 's.whatsapp.net', type: 'get', xmlns: 'w:p' },
  content: [{ tag: 'ping', attrs: {} }],
})
```

If the server replies with `type="error"`, `query()` throws a `ConnectionError`
whose `code` is the server's error code. For fire-and-forget, use `sendNode()`.

To observe everything arriving:

```ts
import { nodeToString } from 'jesterlib'

socket.on('node', node => console.log(nodeToString(node)))
```

> Length-delimited content always comes back as a `Buffer`, never a string. The
> wire format does not distinguish text from binary, and guessing UTF-8 would
> corrupt binary payloads that happen to be valid UTF-8. Use
> `getBinaryNodeChildString()` when you know a field is text.

## How the protocol works

Useful whether or not you use this library.

**1. Transport.** A WebSocket to `wss://web.whatsapp.com/ws/chat`. Every message
is preceded by a 3-byte big-endian length. One WebSocket message may contain
several frames, or half of one, so framing must be streaming.

**2. Noise handshake.** `Noise_XX_25519_AESGCM_SHA256`. Three messages —
ClientHello, ServerHello, ClientFinish — after which the channel is symmetric
with one key per direction. Two things bite here: during the handshake both
directions share the *same* nonce counter, and every ciphertext exchanged feeds
into the transcript hash.

**3. WABinary.** WhatsApp speaks neither JSON nor XML but a binary XML of its
own: token dictionaries, JIDs packed into a few bytes, phone numbers
nibble-packed two digits per byte, lists sized with 8 or 16 bits.

**4. Protobuf.** `ClientPayload`, `WebMessageInfo`, the ADV family and others.
The field numbers are the part that cannot be guessed.

**5. Pairing.** The QR string is literally `ref,noiseKey,identityKey,advSecret`
joined by commas, where `ref` rotates every ~20 seconds. When the phone scans
it, three signatures are checked in sequence — see
[src/auth/pairing.ts](src/auth/pairing.ts), which documents each one.

**6. Signal Protocol.** Every message is end-to-end encrypted: X3DH to establish
sessions, Double Ratchet to maintain them, sender keys for groups. *Not yet
implemented here.*

## API reference

### `JesterSocket`

```ts
new JesterSocket(options: JesterSocketOptions)
```

| Option | Default | Description |
|---|---|---|
| `auth` | *required* | `{ creds, keys }` |
| `version` | `[2, 3000, 1015901307]` | WhatsApp Web version; too old and the server refuses |
| `browser` | `['Jester', 'Chrome', '120.0.0']` | Shown in the phone's linked-devices list |
| `url` | `wss://web.whatsapp.com/ws/chat` | WebSocket endpoint |
| `transport` | a real WebSocket | Inject your own (used by the tests) |
| `logger` | silent | `{ debug, info, warn, error }` |
| `connectTimeoutMs` | `20000` | |
| `keepAliveIntervalMs` | `30000` | Ping interval |
| `defaultQueryTimeoutMs` | `60000` | |
| `qrTimeoutMs` | `60000` | Lifetime of the first QR |
| `qrRefreshMs` | `20000` | Lifetime of subsequent QRs |

**Methods**

- `connect(): Promise<void>` — connects and runs the handshake
- `sendNode(node): void` — fire and forget
- `query(node, timeoutMs?): Promise<BinaryNode>` — send and await the reply
- `end(error?): void` — close
- `generateMessageTag(): string`
- `connectionState` — current `ConnectionState`
- `auth` — the live `AuthenticationState`

**Events**

| Event | Payload | When |
|---|---|---|
| `connection.update` | `Partial<ConnectionState>` | state changed, or a new QR |
| `creds.update` | `AuthenticationCreds` | credentials changed — persist them |
| `node` | `BinaryNode` | any node received |

### Other exports

Credentials: `initAuthCreds`, `serializeCreds`, `deserializeCreds`,
`makeSignedKeyPair`, `generateRegistrationId`

Pairing: `buildQrString`, `extractPairingRefs`, `configureSuccessfulPairing`

Nodes: `getBinaryNodeChild`, `getBinaryNodeChildren`,
`getBinaryNodeChildString`, `getBinaryNodeChildBuffer`,
`getBinaryNodeChildUInt`, `nodeToString`, `encodeBinaryNode`,
`decodeBinaryNode`

JIDs: `jidEncode`, `jidDecode`, `jidNormalizedUser`, `areJidsSameUser`,
`isJidUser`, `isJidGroup`, `isJidBroadcast`, `isJidNewsletter`

Crypto: `Curve`, `xeddsaSign`, `xeddsaVerify`, `hkdf`, `sha256`, `hmacSha256`,
`aesEncryptGCM`, `aesDecryptGCM`

## Project layout

```
src/
  crypto/    X25519 via node:crypto + XEdDSA on top of @noble/curves
  proto/     a small protobuf runtime and the WAProto schemas
  binary/    WhatsApp's binary XML: tokens, JIDs, nibble/hex packing
  noise/     Noise_XX_25519_AESGCM_SHA256 handshake and framing
  socket/    connection, ClientPayload, transport abstraction
  auth/      serializable credentials, key store, QR pairing
test/
  helpers/   a simulated WhatsApp server and a simulated phone
```

The bottom three layers have no network dependency and are testable offline —
that is why they were built first.

## Design decisions

**Almost no dependencies.** X25519, AES, HKDF and Ed25519 verification all come
from Node's native crypto. The protobuf runtime is ~220 lines of our own code.
Only `ws` and `@noble/curves` remain at runtime, the latter purely for the
Edwards-curve point arithmetic Node does not expose.

**Declarative protobuf schemas.** Instead of code generation from `.proto`
files, messages are plain objects and the TypeScript type is inferred from them
([src/proto/wa.ts](src/proto/wa.ts)). The schema doubles as protocol
documentation:

```ts
export const ClientPayload = defineMessage('ClientPayload', {
  username: f(1, 'uint64'),
  passive: f(3, 'bool'),
  userAgent: f(5, UserAgent),
  devicePairingData: f(19, DevicePairingRegistrationData),
})
```

**Simulated servers instead of mocks.** The handshake and the whole connection
are tested against a real Noise responder and a real pairing counterparty,
speaking over a pair of in-memory transports. That catches DH ordering, nonce
counter sharing and signature-prefix mistakes — the failures that otherwise only
show up in production as a silently closed socket.

**Independent verification paths.** XEdDSA signatures are produced with
`@noble/curves` and verified with Node's OpenSSL binding — two codebases that
share nothing. A bug would have to exist in both at once.

## Testing

```bash
npm test         # 83 tests, no network needed
npm run typecheck
npm run build
```

Tests run on Node's built-in runner with native TypeScript stripping, so there
is no build step and no test framework dependency.

Coverage worth knowing about:

- X25519 and HKDF are checked against the official **RFC 7748** and **RFC 5869**
  vectors, not just self-consistency
- protobuf encoding is checked against the canonical examples from the protobuf
  documentation
- the Noise handshake is driven against a responder implementation, and both
  sides' derived keys are compared
- pairing is driven against a simulated phone that signs as the account would
  and then verifies the client's counter-signature

## Contributing

Issues and pull requests are welcome. A few conventions:

- Comments explain *why*, and especially *what breaks if you get it wrong* —
  that is the useful information in protocol code
- New protocol behaviour needs a test against the simulated server or phone, not
  a mock
- Run `npm test && npm run typecheck` before opening a PR
- Never commit a real `auth.json`, token dictionary dump or phone number

## Roadmap

- [x] Crypto primitives, XEdDSA signatures
- [x] Protobuf runtime and WAProto schemas
- [x] WABinary encoder and decoder
- [x] Noise XX handshake and framing
- [x] Connection, queries, node routing
- [x] QR pairing
- [ ] Pre-key upload (`<iq xmlns="encrypt">`)
- [ ] Signal Protocol: sessions, receiving and sending text
- [ ] Group messaging (sender keys)
- [ ] Media upload and download
- [ ] App state sync (contacts, chats)

## Legal and safety

This client presents itself as a WhatsApp Web companion device. It is protocol
reverse engineering and falls outside WhatsApp's Terms of Service. **Accounts
using unofficial clients can be banned**, particularly when the usage pattern
looks like bulk messaging. Use a number you can afford to lose.

If you need something supported and reliable for business messaging, the
official **WhatsApp Cloud API** exists and is webhook based — much less work
than this.

Server certificate validation currently checks only the issuer serial, not the
cryptographic signature against WhatsApp's root key. On a hostile network that
leaves room for a MITM. It is isolated in `validateServerCertificate` so it can
be hardened.

## License

MIT
