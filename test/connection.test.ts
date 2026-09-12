import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { before, test } from 'node:test'
import { initAuthCreds, deserializeCreds, serializeCreds } from '../src/auth/creds.ts'
import { makeInMemoryKeyStore, type AuthenticationState } from '../src/auth/state.ts'
import { setTokenDictionary } from '../src/binary/tokens.ts'
import { DeviceProps, Platform, WebSubPlatform } from '../src/proto/wa.ts'
import {
	ConnectionError,
	DisconnectReason,
	JesterSocket,
	type JesterSocketOptions,
} from '../src/socket/connection.ts'
import { createLinkedTransports } from '../src/socket/transport.ts'
import { attachFakeServer } from './helpers/fake-server.ts'

/** Minimal dictionary holding just the tokens this test uses. */
before(() => {
	setTokenDictionary({
		single: [
			null,
			'iq',
			'to',
			'from',
			'type',
			'get',
			'set',
			'result',
			'error',
			'id',
			'xmlns',
			'success',
			'failure',
			'stream:error',
			'ib',
			'ping',
			'w:p',
			's.whatsapp.net',
			'edge_routing',
			'routing_info',
			'code',
			'reason',
			'lid',
			'platform',
		],
		double: [],
	})
})

function makeAuth(): AuthenticationState {
	return { creds: initAuthCreds(), keys: makeInMemoryKeyStore() }
}

type ExtraOptions = Partial<Omit<JesterSocketOptions, 'auth' | 'transport'>>

async function connectPair(options: ExtraOptions = {}) {
	const [clientTransport, serverTransport] = createLinkedTransports()
	const server = attachFakeServer(serverTransport)
	const auth = makeAuth()

	const socket = new JesterSocket({ auth, transport: clientTransport, ...options })
	await socket.connect()
	await server.ready()

	return { socket, server, auth }
}

function waitForOpen(socket: JesterSocket, timeoutMs = 2000): Promise<void> {
	// The <success> may already have arrived before this listener is attached.
	if (socket.connectionState.connection === 'open') {
		return Promise.resolve()
	}

	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error('timed out waiting for connection=open')), timeoutMs)

		socket.on('connection.update', update => {
			if (update.connection === 'open') {
				clearTimeout(timer)
				resolve()
			}

			if (update.connection === 'close') {
				clearTimeout(timer)
				reject(update.lastDisconnect?.error ?? new Error('closed'))
			}
		})
	})
}

test('a full handshake brings the connection to connection=open', async () => {
	const { socket, server } = await connectPair()
	const opened = waitForOpen(socket)

	await opened

	assert.equal(socket.connectionState.connection, 'open')
	assert.ok(server.clientPayload(), 'server never received a ClientPayload')

	socket.end()
})

test('the registration ClientPayload arrives intact on the other side', async () => {
	const { socket, server, auth } = await connectPair()
	await waitForOpen(socket)

	const payload = server.clientPayload()
	assert.ok(payload)

	// No account yet: it has to be the registration payload.
	assert.equal(payload.passive, false)
	assert.equal(payload.username, undefined)
	assert.ok(payload.devicePairingData, 'devicePairingData is missing')

	const pairing = payload.devicePairingData!
	assert.deepEqual(pairing.eIdent, auth.creds.signedIdentityKey.public)
	assert.deepEqual(pairing.eSkeyVal, auth.creds.signedPreKey.keyPair.public)
	assert.deepEqual(pairing.eSkeySig, auth.creds.signedPreKey.signature)
	assert.deepEqual(pairing.eKeytype, Buffer.from([5]))

	// registrationId as a 4-byte big-endian value
	assert.equal(pairing.eRegid?.readUInt32BE(0), auth.creds.registrationId)
	// prekey keyId as a 3-byte big-endian value
	assert.equal(pairing.eSkeyId?.length, 3)

	assert.equal(payload.userAgent?.platform, Platform.WEB)
	assert.equal(payload.webInfo?.webSubPlatform, WebSubPlatform.WEB_BROWSER)

	socket.end()
})

test('buildHash is the md5 of the WhatsApp version, not of the browser', async () => {
	// Regression. This was md5(browser.join(' ')), which connects and produces a
	// perfectly good QR — and then the phone refuses the pairing with a generic
	// "cannot connect". The server cross-checks it against userAgent.appVersion.
	const version: [number, number, number] = [2, 3000, 1043857760]

	const [clientTransport, serverTransport] = createLinkedTransports()
	const server = attachFakeServer(serverTransport)
	const socket = new JesterSocket({ auth: makeAuth(), transport: clientTransport, version })

	await socket.connect()
	await server.ready()
	await waitForOpen(socket)

	const pairing = server.clientPayload()?.devicePairingData
	assert.ok(pairing)

	assert.deepEqual(
		pairing.buildHash,
		createHash('md5').update(version.join('.')).digest(),
		'buildHash must hash the dotted version string',
	)

	socket.end()
})

test('the registration payload sets pull to false', async () => {
	const { socket, server } = await connectPair()
	await waitForOpen(socket)

	assert.equal(server.clientPayload()?.pull, false)

	socket.end()
})

test('DeviceProps reports the companion version, not the browser version', async () => {
	const { socket, server } = await connectPair({ browser: ['Jester', 'Chrome', '999.888.777'] })
	await waitForOpen(socket)

	const props = DeviceProps.decode(server.clientPayload()!.devicePairingData!.deviceProps!)

	// Deriving this from the browser string is what made the phone reject it.
	assert.equal(props.version?.primary, 10)
	assert.equal(props.version?.secondary, 15)
	assert.equal(props.version?.tertiary, 7)
	assert.equal(props.os, 'Jester')

	socket.end()
})

test('query matches the reply by id and returns the node', async () => {
	const { socket, server } = await connectPair()
	await waitForOpen(socket)

	server.autoRespond(node => {
		if (node.tag === 'iq' && node.attrs.type === 'get') {
			return {
				tag: 'iq',
				attrs: { id: node.attrs.id!, type: 'result', from: 's.whatsapp.net' },
				content: [{ tag: 'ping', attrs: {} }],
			}
		}

		return undefined
	})

	const result = await socket.query({
		tag: 'iq',
		attrs: { to: 's.whatsapp.net', type: 'get', xmlns: 'w:p' },
		content: [{ tag: 'ping', attrs: {} }],
	})

	assert.equal(result.tag, 'iq')
	assert.equal(result.attrs.type, 'result')

	// the server received exactly what was asked for
	const sent = server.received().find(n => n.tag === 'iq')
	assert.ok(sent)
	assert.equal(sent.attrs.xmlns, 'w:p')
	assert.ok(sent.attrs.id, 'query must generate an id')

	socket.end()
})

test('a type=error reply becomes a ConnectionError carrying the server code', async () => {
	const { socket, server } = await connectPair()
	await waitForOpen(socket)

	server.autoRespond(node =>
		node.tag === 'iq'
			? {
					tag: 'iq',
					attrs: { id: node.attrs.id!, type: 'error' },
					content: [{ tag: 'error', attrs: { code: '404', text: 'not found' } }],
				}
			: undefined,
	)

	await assert.rejects(
		() => socket.query({ tag: 'iq', attrs: { to: 's.whatsapp.net', type: 'get' } }),
		(err: ConnectionError) => {
			assert.equal(err.name, 'ConnectionError')
			assert.equal(err.code, 404)
			assert.equal(err.message, 'not found')

			return true
		},
	)

	socket.end()
})

test('an unanswered query times out', async () => {
	const { socket } = await connectPair({ defaultQueryTimeoutMs: 150 })
	await waitForOpen(socket)

	await assert.rejects(
		() => socket.query({ tag: 'iq', attrs: { to: 's.whatsapp.net', type: 'get' } }),
		(err: ConnectionError) => err.code === DisconnectReason.timedOut,
	)

	socket.end()
})

test('<failure> closes the connection with the server reason', async () => {
	const { socket, server } = await connectPair()
	await waitForOpen(socket)

	const closed = new Promise<ConnectionError>(resolve => {
		socket.on('connection.update', update => {
			if (update.connection === 'close') {
				resolve(update.lastDisconnect?.error as ConnectionError)
			}
		})
	})

	server.send({ tag: 'failure', attrs: { reason: '401', text: 'logged out' } })

	const error = await closed
	assert.equal(error.code, DisconnectReason.loggedOut)
	assert.equal(socket.connectionState.connection, 'close')
})

test('<stream:error> closes the connection', async () => {
	const { socket, server } = await connectPair()
	await waitForOpen(socket)

	const closed = new Promise<ConnectionError>(resolve => {
		socket.on('connection.update', u => {
			if (u.connection === 'close') {
				resolve(u.lastDisconnect?.error as ConnectionError)
			}
		})
	})

	server.send({ tag: 'stream:error', attrs: { code: '515' }, content: [{ tag: 'conflict', attrs: {} }] })

	const error = await closed
	assert.equal(error.code, DisconnectReason.restartRequired)
	assert.match(error.message, /conflict/)
})

test('routing info from <ib> is stored in the credentials', async () => {
	const { socket, server, auth } = await connectPair()
	await waitForOpen(socket)

	const routing = Buffer.from([0x01, 0x02, 0x03])
	const updated = new Promise<void>(resolve => socket.on('creds.update', () => resolve()))

	server.send({
		tag: 'ib',
		attrs: {},
		content: [
			{
				tag: 'edge_routing',
				attrs: {},
				content: [{ tag: 'routing_info', attrs: {}, content: routing }],
			},
		],
	})

	await updated
	assert.deepEqual(auth.creds.routingInfo, routing)

	socket.end()
})

test('<success> records lid and platform in the credentials', async () => {
	const [clientTransport, serverTransport] = createLinkedTransports()
	const server = attachFakeServer(serverTransport, { sendSuccessOnConnect: false })
	const auth = makeAuth()

	auth.creds.me = { id: '5511999999999:1@s.whatsapp.net' }

	const socket = new JesterSocket({ auth, transport: clientTransport })
	await socket.connect()
	await server.ready()

	server.send({ tag: 'success', attrs: { lid: '888777:1@lid', platform: 'smba' } })
	await waitForOpen(socket)

	assert.equal(auth.creds.me?.lid, '888777:1@lid')
	assert.equal(auth.creds.platform, 'smba')

	socket.end()
})

test('an already-paired connection sends the login payload, not the registration one', async () => {
	const [clientTransport, serverTransport] = createLinkedTransports()
	const server = attachFakeServer(serverTransport)
	const auth = makeAuth()

	auth.creds.registered = true
	auth.creds.me = { id: '5511987654321:7@s.whatsapp.net' }

	const socket = new JesterSocket({ auth, transport: clientTransport })
	await socket.connect()
	await server.ready()
	await waitForOpen(socket)

	const payload = server.clientPayload()
	assert.ok(payload)
	assert.equal(payload.username, 5511987654321n)
	assert.equal(payload.device, 7)
	assert.equal(payload.passive, true)
	assert.equal(payload.devicePairingData, undefined, 'login must not carry pairing data')

	socket.end()
})

test('a dropped transport rejects pending queries', async () => {
	const { socket } = await connectPair({ defaultQueryTimeoutMs: 5000 })
	await waitForOpen(socket)

	const pending = socket.query({ tag: 'iq', attrs: { to: 's.whatsapp.net', type: 'get' } })

	socket.end(new ConnectionError('dropped', DisconnectReason.connectionLost))

	await assert.rejects(pending, (err: ConnectionError) => err.code === DisconnectReason.connectionLost)
})

test('sending a node before the handshake is an explicit error', () => {
	const [clientTransport] = createLinkedTransports()
	const socket = new JesterSocket({ auth: makeAuth(), transport: clientTransport })

	assert.throws(() => socket.sendNode({ tag: 'iq', attrs: {} }), /handshake has not finished yet/)
})

test('credentials survive JSON serialization', () => {
	const creds = initAuthCreds()
	creds.me = { id: '5511999999999:1@s.whatsapp.net', name: 'Test' }
	creds.routingInfo = Buffer.from([1, 2, 3])

	const restored = deserializeCreds(serializeCreds(creds))

	assert.deepEqual(restored.noiseKey.private, creds.noiseKey.private)
	assert.deepEqual(restored.signedIdentityKey.public, creds.signedIdentityKey.public)
	assert.deepEqual(restored.signedPreKey.signature, creds.signedPreKey.signature)
	assert.deepEqual(restored.identityId, creds.identityId)
	assert.deepEqual(restored.routingInfo, creds.routingInfo)
	assert.equal(restored.registrationId, creds.registrationId)
	assert.equal(restored.advSecretKey, creds.advSecretKey)
	assert.deepEqual(restored.me, creds.me)
	assert.ok(Buffer.isBuffer(restored.noiseKey.private), 'a Buffer turned into something else on the way back')
})
