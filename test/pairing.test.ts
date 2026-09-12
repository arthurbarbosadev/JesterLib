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
// Unit
// ---------------------------------------------------------------------------

test('the QR carries the ref and the three keys, comma separated', () => {
	const creds = initAuthCreds()
	const parts = buildQrString('REF123', creds).split(',')

	assert.equal(parts.length, 4)
	assert.equal(parts[0], 'REF123')
	assert.deepEqual(Buffer.from(parts[1]!, 'base64'), creds.noiseKey.public)
	assert.deepEqual(Buffer.from(parts[2]!, 'base64'), creds.signedIdentityKey.public)
	assert.equal(parts[3], creds.advSecretKey)
})

test('extractPairingRefs preserves the ref order', () => {
	assert.deepEqual(extractPairingRefs(pairDeviceNode('1', ['a', 'b', 'c'])), ['a', 'b', 'c'])
	assert.throws(() => extractPairingRefs({ tag: 'iq', attrs: {} }), PairingError)
})

test('a valid pairing produces a reply and a credentials update', () => {
	const creds = initAuthCreds()
	const phone = makeFakePhone()

	const stanza = phone.buildPairSuccess({
		stanzaId: 'abc',
		clientIdentityPublic: creds.signedIdentityKey.public,
		advSecretKey: creds.advSecretKey,
		keyIndex: 3,
	})

	const { reply, update } = configureSuccessfulPairing(stanza, creds)

	// the counter-signature has to convince the phone
	assert.equal(
		phone.verifyDeviceSignature(reply, creds.signedIdentityKey.public),
		true,
		'the device signature did not validate on the phone',
	)

	assert.equal(reply.tag, 'iq')
	assert.equal(reply.attrs.type, 'result')
	assert.equal(reply.attrs.id, 'abc')

	const sign = (reply.content as BinaryNode[])[0]!
	assert.equal(sign.tag, 'pair-device-sign')

	const identity = (sign.content as BinaryNode[])[0]!
	assert.equal(identity.attrs['key-index'], '3')

	// the account key must NOT go back to the server
	const sent = ADVSignedDeviceIdentity.decode(identity.content as Buffer)
	assert.equal(sent.accountSignatureKey, undefined, 'accountSignatureKey should not be sent back')
	assert.ok(sent.deviceSignature)

	assert.equal(update.me?.id, phone.jid)
	assert.equal(update.me?.lid, '998877:12@lid')
	assert.equal(update.me?.name, 'Arthur Store')
	assert.equal(update.platform, 'android')
	assert.equal(update.registered, true)
	assert.equal(update.signalIdentities?.length, 1)
	assert.equal(update.signalIdentities?.[0]?.identifier.name, phone.jid)
	assert.equal(update.signalIdentities?.[0]?.identifierKey.length, 33, 'identifierKey needs the 0x05 byte')

	// the credentials keep the identity WITH the account key
	const stored = ADVSignedDeviceIdentity.decode(update.account!)
	assert.deepEqual(stored.accountSignatureKey, phone.accountKey.public)
})

test('a wrong HMAC is rejected (QR from another device)', () => {
	const creds = initAuthCreds()
	const other = initAuthCreds()
	const phone = makeFakePhone()

	// the phone used ANOTHER device's secret
	const stanza = phone.buildPairSuccess({
		stanzaId: 'abc',
		clientIdentityPublic: creds.signedIdentityKey.public,
		advSecretKey: other.advSecretKey,
	})

	assert.throws(() => configureSuccessfulPairing(stanza, creds), /identity HMAC mismatch/)
})

test('an account signature over a different identity is rejected', () => {
	const creds = initAuthCreds()
	const impostor = initAuthCreds()
	const phone = makeFakePhone()

	// The account authorized the impostor's device but the HMAC is ours —
	// simulates someone trying to reuse somebody else's authorization.
	const stanza = phone.buildPairSuccess({
		stanzaId: 'abc',
		clientIdentityPublic: impostor.signedIdentityKey.public,
		advSecretKey: creds.advSecretKey,
	})

	assert.throws(() => configureSuccessfulPairing(stanza, creds), /invalid account signature/)
})

test('a malformed pair-success fails with a PairingError', () => {
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
		/has no id/,
	)
})

// ---------------------------------------------------------------------------
// Full flow over the connection
// ---------------------------------------------------------------------------

test('end to end: QR emitted, phone pairs, client counter-signs', async () => {
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

	// The server sends the refs; the client must ACK and publish the first QR.
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

	// the ACK must have arrived, otherwise a real server would not continue
	await new Promise(resolve => setTimeout(resolve, 10))
	const ack = server.received().find(n => n.tag === 'iq' && n.attrs.id === 'pair-1')
	assert.ok(ack, 'the client did not ACK the <pair-device>')
	assert.equal(ack.attrs.type, 'result')

	// The phone scans the QR and returns the signed identity.
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
	assert.ok(reply, 'the client did not reply to the <pair-success>')
	assert.equal(
		phone.verifyDeviceSignature(reply, auth.creds.signedIdentityKey.public),
		true,
		'invalid counter-signature in the full flow',
	)

	assert.equal(auth.creds.me?.id, phone.jid)
	assert.equal(auth.creds.registered, true)
	assert.ok(updates.some(u => u.isNewLogin), 'isNewLogin was never signalled')

	socket.end()
})

test('the QR rotates through the refs as they expire', async () => {
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

test('running out of refs closes the connection instead of hanging', async () => {
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

	server.send(pairDeviceNode('pair-1', ['ONLY-ONE-REF']))

	const error = await closed
	assert.match(error.message, /ran out of QR refs/)
})
