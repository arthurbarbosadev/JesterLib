import assert from 'node:assert/strict'
import { before, test } from 'node:test'
import { initAuthCreds, deserializeCreds, serializeCreds } from '../src/auth/creds.ts'
import { makeInMemoryKeyStore, type AuthenticationState } from '../src/auth/state.ts'
import { setTokenDictionary } from '../src/binary/tokens.ts'
import type { BinaryNode } from '../src/binary/node.ts'
import { Platform, WebSubPlatform } from '../src/proto/wa.ts'
import {
	ConnectionError,
	DisconnectReason,
	JesterSocket,
	type JesterSocketOptions,
} from '../src/socket/connection.ts'
import { createLinkedTransports } from '../src/socket/transport.ts'
import { attachFakeServer } from './helpers/fake-server.ts'

/** Dicionário mínimo com os tokens que este teste usa. */
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
	// O <success> pode já ter chegado antes deste listener ser anexado.
	if (socket.connectionState.connection === 'open') {
		return Promise.resolve()
	}

	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error('timeout esperando connection=open')), timeoutMs)

		socket.on('connection.update', update => {
			if (update.connection === 'open') {
				clearTimeout(timer)
				resolve()
			}

			if (update.connection === 'close') {
				clearTimeout(timer)
				reject(update.lastDisconnect?.error ?? new Error('fechou'))
			}
		})
	})
}

test('handshake completo leva a conexão até connection=open', async () => {
	const { socket, server } = await connectPair()
	const opened = waitForOpen(socket)

	await opened

	assert.equal(socket.connectionState.connection, 'open')
	assert.ok(server.clientPayload(), 'servidor não recebeu ClientPayload')

	socket.end()
})

test('o ClientPayload de registro chega íntegro do outro lado', async () => {
	const { socket, server, auth } = await connectPair()
	await waitForOpen(socket)

	const payload = server.clientPayload()
	assert.ok(payload)

	// Sem conta ainda: tem que ser o payload de registro.
	assert.equal(payload.passive, false)
	assert.equal(payload.username, undefined)
	assert.ok(payload.devicePairingData, 'faltou devicePairingData')

	const pairing = payload.devicePairingData!
	assert.deepEqual(pairing.eIdent, auth.creds.signedIdentityKey.public)
	assert.deepEqual(pairing.eSkeyVal, auth.creds.signedPreKey.keyPair.public)
	assert.deepEqual(pairing.eSkeySig, auth.creds.signedPreKey.signature)
	assert.deepEqual(pairing.eKeytype, Buffer.from([5]))

	// registrationId em big-endian de 4 bytes
	assert.equal(pairing.eRegid?.readUInt32BE(0), auth.creds.registrationId)
	// keyId da prekey em big-endian de 3 bytes
	assert.equal(pairing.eSkeyId?.length, 3)

	assert.equal(payload.userAgent?.platform, Platform.WEB)
	assert.equal(payload.webInfo?.webSubPlatform, WebSubPlatform.WEB_BROWSER)

	socket.end()
})

test('query casa a resposta pelo id e devolve o nó', async () => {
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

	// o servidor recebeu exatamente o que foi pedido
	const sent = server.received().find(n => n.tag === 'iq')
	assert.ok(sent)
	assert.equal(sent.attrs.xmlns, 'w:p')
	assert.ok(sent.attrs.id, 'query precisa gerar um id')

	socket.end()
})

test('query com type=error vira ConnectionError com o código do servidor', async () => {
	const { socket, server } = await connectPair()
	await waitForOpen(socket)

	server.autoRespond(node =>
		node.tag === 'iq'
			? {
					tag: 'iq',
					attrs: { id: node.attrs.id!, type: 'error' },
					content: [{ tag: 'error', attrs: { code: '404', text: 'não encontrado' } }],
				}
			: undefined,
	)

	await assert.rejects(
		() => socket.query({ tag: 'iq', attrs: { to: 's.whatsapp.net', type: 'get' } }),
		(err: ConnectionError) => {
			assert.equal(err.name, 'ConnectionError')
			assert.equal(err.code, 404)
			assert.equal(err.message, 'não encontrado')

			return true
		},
	)

	socket.end()
})

test('query sem resposta estoura no timeout', async () => {
	const { socket } = await connectPair({ defaultQueryTimeoutMs: 150 })
	await waitForOpen(socket)

	await assert.rejects(
		() => socket.query({ tag: 'iq', attrs: { to: 's.whatsapp.net', type: 'get' } }),
		(err: ConnectionError) => err.code === DisconnectReason.timedOut,
	)

	socket.end()
})

test('<failure> fecha a conexão com o motivo do servidor', async () => {
	const { socket, server } = await connectPair()
	await waitForOpen(socket)

	const closed = new Promise<ConnectionError>(resolve => {
		socket.on('connection.update', update => {
			if (update.connection === 'close') {
				resolve(update.lastDisconnect?.error as ConnectionError)
			}
		})
	})

	server.send({ tag: 'failure', attrs: { reason: '401', text: 'deslogado' } })

	const error = await closed
	assert.equal(error.code, DisconnectReason.loggedOut)
	assert.equal(socket.connectionState.connection, 'close')
})

test('<stream:error> fecha a conexão', async () => {
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

test('routing info de <ib> é guardada nas credenciais', async () => {
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

test('<success> grava lid e platform nas credenciais', async () => {
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

test('conexão já pareada envia payload de login, não de registro', async () => {
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
	assert.equal(payload.devicePairingData, undefined, 'login não deve carregar dados de pareamento')

	socket.end()
})

test('queda do transporte rejeita as queries pendentes', async () => {
	const { socket } = await connectPair({ defaultQueryTimeoutMs: 5000 })
	await waitForOpen(socket)

	const pending = socket.query({ tag: 'iq', attrs: { to: 's.whatsapp.net', type: 'get' } })

	socket.end(new ConnectionError('caiu', DisconnectReason.connectionLost))

	await assert.rejects(pending, (err: ConnectionError) => err.code === DisconnectReason.connectionLost)
})

test('enviar nó antes do handshake é erro explícito', () => {
	const [clientTransport] = createLinkedTransports()
	const socket = new JesterSocket({ auth: makeAuth(), transport: clientTransport })

	assert.throws(() => socket.sendNode({ tag: 'iq', attrs: {} }), /handshake ainda não terminou/)
})

test('credenciais sobrevivem a serialização em JSON', () => {
	const creds = initAuthCreds()
	creds.me = { id: '5511999999999:1@s.whatsapp.net', name: 'Teste' }
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
	assert.ok(Buffer.isBuffer(restored.noiseKey.private), 'Buffer virou outra coisa na volta')
})
