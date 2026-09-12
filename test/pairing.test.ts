import assert from 'node:assert/strict'
import { before, test } from 'node:test'
import { initAuthCreds } from '../src/auth/creds.ts'
import { PairingError, buildQrString, configureSuccessfulPairing, extractPairingRefs } from '../src/auth/pairing.ts'
import { makeInMemoryKeyStore, type AuthenticationState } from '../src/auth/state.ts'
import { setTokenDictionary } from '../src/binary/tokens.ts'
import type { BinaryNode } from '../src/binary/node.ts'
import { ADVSignedDeviceIdentity } from '../src/proto/wa.ts'
import { JesterSocket, type ConnectionState } from '../src/socket/connection.ts'
import { createLinkedTransports } from '../src/socket/transport.ts'
import { makeFakePhone } from './helpers/fake-phone.ts'
import { attachFakeServer } from './helpers/fake-server.ts'

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
			'id',
			'success',
			'pair-device',
			'pair-success',
			'pair-device-sign',
			'device-identity',
			'device',
			'platform',
			'biz',
			'ref',
			'jid',
			'lid',
			'name',
			'key-index',
			's.whatsapp.net',
		],
		double: [],
	})
})

function makeAuth(): AuthenticationState {
	return { creds: initAuthCreds(), keys: makeInMemoryKeyStore() }
}

function pairDeviceNode(id: string, refs: string[]): BinaryNode {
	return {
		tag: 'iq',
		attrs: { id, type: 'set', from: 's.whatsapp.net' },
		content: [
			{
				tag: 'pair-device',
				attrs: {},
				content: refs.map(ref => ({ tag: 'ref', attrs: {}, content: Buffer.from(ref) })),
			},
		],
	}
}

// ---------------------------------------------------------------------------
// Unidade
// ---------------------------------------------------------------------------

test('QR carrega ref e as três chaves, separados por vírgula', () => {
	const creds = initAuthCreds()
	const parts = buildQrString('REF123', creds).split(',')

	assert.equal(parts.length, 4)
	assert.equal(parts[0], 'REF123')
	assert.deepEqual(Buffer.from(parts[1]!, 'base64'), creds.noiseKey.public)
	assert.deepEqual(Buffer.from(parts[2]!, 'base64'), creds.signedIdentityKey.public)
	assert.equal(parts[3], creds.advSecretKey)
})

test('extractPairingRefs preserva a ordem dos refs', () => {
	assert.deepEqual(extractPairingRefs(pairDeviceNode('1', ['a', 'b', 'c'])), ['a', 'b', 'c'])
	assert.throws(() => extractPairingRefs({ tag: 'iq', attrs: {} }), PairingError)
})

test('pareamento válido produz resposta e atualização de credenciais', () => {
	const creds = initAuthCreds()
	const phone = makeFakePhone()

	const stanza = phone.buildPairSuccess({
		stanzaId: 'abc',
		clientIdentityPublic: creds.signedIdentityKey.public,
		advSecretKey: creds.advSecretKey,
		keyIndex: 3,
	})

	const { reply, update } = configureSuccessfulPairing(stanza, creds)

	// a contra-assinatura tem que convencer o celular
	assert.equal(
		phone.verifyDeviceSignature(reply, creds.signedIdentityKey.public),
		true,
		'assinatura do dispositivo não validou no celular',
	)

	assert.equal(reply.tag, 'iq')
	assert.equal(reply.attrs.type, 'result')
	assert.equal(reply.attrs.id, 'abc')

	const sign = (reply.content as BinaryNode[])[0]!
	assert.equal(sign.tag, 'pair-device-sign')

	const identity = (sign.content as BinaryNode[])[0]!
	assert.equal(identity.attrs['key-index'], '3')

	// a chave da conta NÃO volta para o servidor
	const sent = ADVSignedDeviceIdentity.decode(identity.content as Buffer)
	assert.equal(sent.accountSignatureKey, undefined, 'accountSignatureKey não deveria ser reenviada')
	assert.ok(sent.deviceSignature)

	assert.equal(update.me?.id, phone.jid)
	assert.equal(update.me?.lid, '998877:12@lid')
	assert.equal(update.me?.name, 'Loja do Arthur')
	assert.equal(update.platform, 'android')
	assert.equal(update.registered, true)
	assert.equal(update.signalIdentities?.length, 1)
	assert.equal(update.signalIdentities?.[0]?.identifier.name, phone.jid)
	assert.equal(update.signalIdentities?.[0]?.identifierKey.length, 33, 'identifierKey precisa do byte 0x05')

	// as credenciais guardam a identidade COM a chave da conta
	const stored = ADVSignedDeviceIdentity.decode(update.account!)
	assert.deepEqual(stored.accountSignatureKey, phone.accountKey.public)
})

test('HMAC errado é rejeitado (QR de outro dispositivo)', () => {
	const creds = initAuthCreds()
	const outro = initAuthCreds()
	const phone = makeFakePhone()

	// o celular usou o segredo de OUTRO dispositivo
	const stanza = phone.buildPairSuccess({
		stanzaId: 'abc',
		clientIdentityPublic: creds.signedIdentityKey.public,
		advSecretKey: outro.advSecretKey,
	})

	assert.throws(() => configureSuccessfulPairing(stanza, creds), /HMAC da identidade não confere/)
})

test('assinatura da conta sobre outra identidade é rejeitada', () => {
	const creds = initAuthCreds()
	const impostor = initAuthCreds()
	const phone = makeFakePhone()

	// A conta autorizou o dispositivo do impostor, mas o HMAC é do nosso —
	// simula alguém tentando reaproveitar uma autorização alheia.
	const stanza = phone.buildPairSuccess({
		stanzaId: 'abc',
		clientIdentityPublic: impostor.signedIdentityKey.public,
		advSecretKey: creds.advSecretKey,
	})

	assert.throws(() => configureSuccessfulPairing(stanza, creds), /assinatura da conta inválida/)
})

test('pair-success malformado falha com PairingError', () => {
	const creds = initAuthCreds()

	assert.throws(
		() => configureSuccessfulPairing({ tag: 'iq', attrs: { id: 'x' }, content: [] }, creds),
		PairingError,
	)

	assert.throws(
		() =>
			configureSuccessfulPairing(
				{ tag: 'iq', attrs: {}, content: [{ tag: 'pair-success', attrs: {} }] },
				creds,
			),
		/sem id/,
	)
})

// ---------------------------------------------------------------------------
// Fluxo completo sobre a conexão
// ---------------------------------------------------------------------------

test('fluxo ponta a ponta: QR emitido, celular pareia, cliente contra-assina', async () => {
	const [clientTransport, serverTransport] = createLinkedTransports()
	const server = attachFakeServer(serverTransport, { sendSuccessOnConnect: false })
	const auth = makeAuth()
	const phone = makeFakePhone()

	const socket = new JesterSocket({ auth, transport: clientTransport })
	const updates: Partial<ConnectionState>[] = []
	socket.on('connection.update', u => updates.push(u))

	const credsUpdated = new Promise<void>(resolve => socket.once('creds.update', () => resolve()))

	await socket.connect()
	await server.ready()

	// O servidor manda os refs; o cliente deve ACKar e publicar o primeiro QR.
	const qrEmitted = new Promise<string>(resolve => {
		socket.on('connection.update', u => {
			if (u.qr) {
				resolve(u.qr)
			}
		})
	})

	server.send(pairDeviceNode('pair-1', ['REF-A', 'REF-B', 'REF-C']))

	const qr = await qrEmitted
	const [ref, , identityB64, advSecret] = qr.split(',')

	assert.equal(ref, 'REF-A')
	assert.deepEqual(Buffer.from(identityB64!, 'base64'), auth.creds.signedIdentityKey.public)

	// o ACK precisa ter chegado, senão o servidor real não continuaria
	await new Promise(resolve => setTimeout(resolve, 10))
	const ack = server.received().find(n => n.tag === 'iq' && n.attrs.id === 'pair-1')
	assert.ok(ack, 'cliente não ACKou o <pair-device>')
	assert.equal(ack.attrs.type, 'result')

	// O celular lê o QR e devolve a identidade assinada.
	server.send(
		phone.buildPairSuccess({
			stanzaId: 'pair-2',
			clientIdentityPublic: Buffer.from(identityB64!, 'base64'),
			advSecretKey: advSecret!,
		}),
	)

	await credsUpdated
	await new Promise(resolve => setTimeout(resolve, 10))

	const reply = server.received().find(n => n.attrs.id === 'pair-2')
	assert.ok(reply, 'cliente não respondeu ao <pair-success>')
	assert.equal(
		phone.verifyDeviceSignature(reply, auth.creds.signedIdentityKey.public),
		true,
		'contra-assinatura inválida no fluxo completo',
	)

	assert.equal(auth.creds.me?.id, phone.jid)
	assert.equal(auth.creds.registered, true)
	assert.ok(updates.some(u => u.isNewLogin), 'não sinalizou isNewLogin')

	socket.end()
})

test('QR rotaciona pelos refs conforme expiram', async () => {
	const [clientTransport, serverTransport] = createLinkedTransports()
	const server = attachFakeServer(serverTransport, { sendSuccessOnConnect: false })

	const socket = new JesterSocket({
		auth: makeAuth(),
		transport: clientTransport,
		qrTimeoutMs: 20,
		qrRefreshMs: 20,
	})

	const qrs: string[] = []
	socket.on('connection.update', u => {
		if (u.qr) {
			qrs.push(u.qr.split(',')[0]!)
		}
	})

	await socket.connect()
	await server.ready()

	server.send(pairDeviceNode('pair-1', ['REF-A', 'REF-B', 'REF-C']))

	await new Promise(resolve => setTimeout(resolve, 120))

	assert.deepEqual(qrs, ['REF-A', 'REF-B', 'REF-C'])
	socket.end()
})

test('refs esgotados fecham a conexão em vez de travar', async () => {
	const [clientTransport, serverTransport] = createLinkedTransports()
	const server = attachFakeServer(serverTransport, { sendSuccessOnConnect: false })

	const socket = new JesterSocket({
		auth: makeAuth(),
		transport: clientTransport,
		qrTimeoutMs: 15,
		qrRefreshMs: 15,
	})

	const closed = new Promise<Error>(resolve => {
		socket.on('connection.update', u => {
			if (u.connection === 'close' && u.lastDisconnect?.error) {
				resolve(u.lastDisconnect.error)
			}
		})
	})

	await socket.connect()
	await server.ready()

	server.send(pairDeviceNode('pair-1', ['SO-UM-REF']))

	const error = await closed
	assert.match(error.message, /refs do QR esgotados/)
})
