import assert from 'node:assert/strict'
import { before, test } from 'node:test'
import { setTokenDictionary } from '../src/binary/tokens.ts'
import type { BinaryNode } from '../src/binary/node.ts'
import { padMessage, unpadMessage } from '../src/message/padding.ts'
import { Message, extractText, unwrapMessage } from '../src/message/proto.ts'
import {
	MessageNodeError,
	buildDeviceQuery,
	buildMessageAck,
	buildOutgoingMessage,
	buildReadReceipt,
	generateMessageId,
	parseDeviceQuery,
	parseIncomingMessage,
} from '../src/message/node.ts'
import {
	PRE_KEYS_PER_UPLOAD,
	buildPreKeyUploadNode,
	generatePreKeys,
	parsePreKeyBundles,
	parsePreKeyCount,
	verifyPreKeyBundle,
} from '../src/auth/prekeys.ts'
import { initAuthCreds } from '../src/auth/creds.ts'
import { getBinaryNodeChild, getBinaryNodeChildren } from '../src/binary/node.ts'
import { addKeyType, xeddsaVerify } from '../src/crypto/index.ts'

before(() => {
	setTokenDictionary({ single: [null, 'message', 'enc', 'iq'], double: [] })
})

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

test('padding round-trips for every length', () => {
	for (const size of [0, 1, 15, 16, 17, 255, 1000]) {
		const payload = Buffer.alloc(size, 0x41)
		const padded = padMessage(payload)

		assert.ok(padded.length > payload.length, 'padding must add at least one byte')
		assert.ok(padded.length <= payload.length + 16, 'padding must add at most 16')
		assert.deepEqual(unpadMessage(padded), payload, `falhou em ${size} bytes`)
	}
})

test('padding is randomized, so length leaks less', () => {
	const payload = Buffer.from('mesma mensagem')
	const sizes = new Set(Array.from({ length: 60 }, () => padMessage(payload).length))

	assert.ok(sizes.size > 1, 'padding always produced the same length')
})

test('the pad byte is never zero', () => {
	// A zero would be read as "strip nothing" and leave the padding in the
	// plaintext.
	for (let i = 0; i < 200; i++) {
		const padded = padMessage(Buffer.from('x'))
		assert.notEqual(padded[padded.length - 1], 0)
	}
})

test('invalid padding is rejected instead of corrupting the plaintext', () => {
	assert.throws(() => unpadMessage(Buffer.alloc(0)), /empty/)
	// Claims 99 bytes of padding in a 3-byte buffer.
	assert.throws(() => unpadMessage(Buffer.from([1, 2, 99])), /invalid padding/)
	assert.throws(() => unpadMessage(Buffer.from([1, 2, 0])), /invalid padding/)
})

// ---------------------------------------------------------------------------
// Message content
// ---------------------------------------------------------------------------

test('plain text round-trips through the protobuf', () => {
	const encoded = Message.encode({ conversation: 'oi, quanto custa?' })

	assert.equal(extractText(Message.decode(encoded)), 'oi, quanto custa?')
})

test('extended text is found too', () => {
	const encoded = Message.encode({ extendedTextMessage: { text: 'olha esse link' } })

	assert.equal(extractText(Message.decode(encoded)), 'olha esse link')
})

test('text inside a deviceSentMessage is unwrapped', () => {
	// This is how our own outgoing messages come back from the phone. Without
	// unwrapping, a bot never sees them — or worse, replies to itself.
	const encoded = Message.encode({
		deviceSentMessage: {
			destinationJid: '5511999999999@s.whatsapp.net',
			message: { conversation: 'enviada do celular' },
		},
	})

	assert.equal(extractText(Message.decode(encoded)), 'enviada do celular')
})

test('nested future-proof wrappers are unwrapped', () => {
	const encoded = Message.encode({
		ephemeralMessage: { message: { viewOnceMessage: { message: { conversation: 'no fundo' } } } },
	})

	assert.equal(extractText(Message.decode(encoded)), 'no fundo')
	assert.equal(unwrapMessage(Message.decode(encoded))?.conversation, 'no fundo')
})

test('a message with no text returns undefined rather than throwing', () => {
	assert.equal(extractText(Message.decode(Message.encode({}))), undefined)
	assert.equal(extractText(undefined), undefined)
})

// ---------------------------------------------------------------------------
// Message nodes
// ---------------------------------------------------------------------------

function incoming(attrs: Record<string, string>, encs: BinaryNode[]): BinaryNode {
	return { tag: 'message', attrs, content: encs }
}

test('an incoming direct message is parsed', () => {
	const node = incoming(
		{ id: 'ABC123', from: '5511988887777@s.whatsapp.net', t: '1757000000', notify: 'Fulano', type: 'text' },
		[{ tag: 'enc', attrs: { v: '2', type: 'pkmsg' }, content: Buffer.from('cifrado') }],
	)

	const parsed = parseIncomingMessage(node)

	assert.equal(parsed.id, 'ABC123')
	assert.equal(parsed.pushName, 'Fulano')
	assert.equal(parsed.timestamp, 1757000000)
	assert.equal(parsed.encs.length, 1)
	assert.equal(parsed.encs[0]?.type, 'pkmsg')
	assert.equal(parsed.senderJid, '5511988887777@s.whatsapp.net')
})

test('in a group, the sender is the participant and not the group', () => {
	// Decrypting against the group JID silently finds no session.
	const node = incoming(
		{
			id: 'G1',
			from: '120363001234567890@g.us',
			participant: '5511988887777@s.whatsapp.net',
			t: '1757000000',
		},
		[{ tag: 'enc', attrs: { v: '2', type: 'msg' }, content: Buffer.from('x') }],
	)

	const parsed = parseIncomingMessage(node)

	assert.equal(parsed.from, '120363001234567890@g.us')
	assert.equal(parsed.senderJid, '5511988887777@s.whatsapp.net')
})

test('a message without id or from is rejected', () => {
	assert.throws(() => parseIncomingMessage({ tag: 'message', attrs: {} }), MessageNodeError)
})

test('a single recipient puts the enc directly under message', () => {
	const node = buildOutgoingMessage({
		id: 'M1',
		to: '5511988887777@s.whatsapp.net',
		recipients: [
			{
				jid: '5511988887777@s.whatsapp.net',
				encrypted: { type: 'msg', ciphertext: Buffer.from('c') },
			},
		],
	})

	const children = node.content as BinaryNode[]
	assert.equal(children[0]?.tag, 'enc')
	assert.equal(children[0]?.attrs.type, 'msg')
	assert.equal(node.attrs.type, 'text')
})

test('several devices go under participants, one to per device', () => {
	const node = buildOutgoingMessage({
		id: 'M2',
		to: '5511988887777@s.whatsapp.net',
		recipients: [
			{ jid: '5511988887777:0@s.whatsapp.net', encrypted: { type: 'msg', ciphertext: Buffer.from('a') } },
			{ jid: '5511988887777:3@s.whatsapp.net', encrypted: { type: 'pkmsg', ciphertext: Buffer.from('b') } },
			{ jid: '5511900000000:1@s.whatsapp.net', encrypted: { type: 'msg', ciphertext: Buffer.from('c') } },
		],
	})

	const participants = (node.content as BinaryNode[])[0]!
	assert.equal(participants.tag, 'participants')

	const tos = participants.content as BinaryNode[]
	assert.equal(tos.length, 3)
	assert.equal(tos[1]?.attrs.jid, '5511988887777:3@s.whatsapp.net')
	assert.equal((tos[1]?.content as BinaryNode[])[0]?.attrs.type, 'pkmsg')
})

test('building with no recipients is an explicit error', () => {
	assert.throws(
		() => buildOutgoingMessage({ id: 'M3', to: 'x@s.whatsapp.net', recipients: [] }),
		MessageNodeError,
	)
})

test('the ack echoes the id, or the server redelivers forever', () => {
	const message = parseIncomingMessage(
		incoming({ id: 'ACK1', from: '5511988887777@s.whatsapp.net', t: '1' }, []),
	)

	const ack = buildMessageAck(message)

	assert.equal(ack.tag, 'ack')
	assert.equal(ack.attrs.id, 'ACK1')
	assert.equal(ack.attrs.class, 'receipt')
	assert.equal(ack.attrs.to, '5511988887777@s.whatsapp.net')
})

test('the group ack carries the participant', () => {
	const message = parseIncomingMessage(
		incoming(
			{ id: 'G2', from: '120363001234567890@g.us', participant: '5511988887777@s.whatsapp.net', t: '1' },
			[],
		),
	)

	assert.equal(buildMessageAck(message).attrs.participant, '5511988887777@s.whatsapp.net')
})

test('a read receipt for several ids puts the rest in a list', () => {
	const receipt = buildReadReceipt({ jid: '5511988887777@s.whatsapp.net', ids: ['A', 'B', 'C'] })

	assert.equal(receipt.attrs.id, 'A')
	assert.equal(receipt.attrs.type, 'read')

	const items = getBinaryNodeChildren(getBinaryNodeChild(receipt, 'list'), 'item')
	assert.deepEqual(items.map(i => i.attrs.id), ['B', 'C'])
})

test('message ids are uppercase hex and unique', () => {
	const ids = new Set(Array.from({ length: 500 }, () => generateMessageId()))

	assert.equal(ids.size, 500)
	assert.match([...ids][0]!, /^[0-9A-F]+$/)
})

test('the device query round-trips', () => {
	const query = buildDeviceQuery(['5511988887777@s.whatsapp.net'])
	assert.equal(query.attrs.xmlns, 'usync')

	const result: BinaryNode = {
		tag: 'iq',
		attrs: { type: 'result' },
		content: [
			{
				tag: 'usync',
				attrs: {},
				content: [
					{
						tag: 'list',
						attrs: {},
						content: [
							{
								tag: 'user',
								attrs: { jid: '5511988887777@s.whatsapp.net' },
								content: [
									{
										tag: 'devices',
										attrs: {},
										content: [
											{
												tag: 'device-list',
												attrs: {},
												content: [
													{ tag: 'device', attrs: { id: '0' } },
													{ tag: 'device', attrs: { id: '3' } },
												],
											},
										],
									},
								],
							},
						],
					},
				],
			},
		],
	}

	assert.deepEqual(parseDeviceQuery(result), [
		'5511988887777:0@s.whatsapp.net',
		'5511988887777:3@s.whatsapp.net',
	])
})

// ---------------------------------------------------------------------------
// Pre-keys
// ---------------------------------------------------------------------------

test('pre-keys are generated with sequential ids and distinct keys', () => {
	const keys = generatePreKeys(100, 10)

	assert.equal(keys.length, 10)
	assert.deepEqual(keys.map(k => k.keyId), Array.from({ length: 10 }, (_, i) => 100 + i))

	const publics = new Set(keys.map(k => k.keyPair.public.toString('hex')))
	assert.equal(publics.size, 10)
})

test('the upload node carries ids in 3 bytes and the registration in 4', () => {
	const creds = initAuthCreds()
	const preKeys = generatePreKeys(1, 3)
	const node = buildPreKeyUploadNode(creds, preKeys)

	assert.equal(node.attrs.xmlns, 'encrypt')
	assert.equal(node.attrs.type, 'set')

	const registration = getBinaryNodeChild(node, 'registration')?.content as Buffer
	assert.equal(registration.length, 4)
	assert.equal(registration.readUInt32BE(0), creds.registrationId)

	const keys = getBinaryNodeChildren(getBinaryNodeChild(node, 'list'), 'key')
	assert.equal(keys.length, 3)

	const firstId = getBinaryNodeChild(keys[0], 'id')?.content as Buffer
	assert.equal(firstId.length, 3, 'key ids are 3 bytes, not 4')

	const skey = getBinaryNodeChild(node, 'skey')
	assert.equal((getBinaryNodeChild(skey, 'signature')?.content as Buffer).length, 64)
})

test('a fetched bundle parses and its signature verifies', () => {
	const peer = initAuthCreds()

	const result: BinaryNode = {
		tag: 'iq',
		attrs: { type: 'result' },
		content: [
			{
				tag: 'list',
				attrs: {},
				content: [
					{
						tag: 'user',
						attrs: { jid: '5511988887777@s.whatsapp.net' },
						content: [
							{ tag: 'registration', attrs: {}, content: Buffer.from([0, 0, 0x10, 0x20]) },
							{ tag: 'identity', attrs: {}, content: peer.signedIdentityKey.public },
							{
								tag: 'skey',
								attrs: {},
								content: [
									{ tag: 'id', attrs: {}, content: Buffer.from([0, 0, 1]) },
									{ tag: 'value', attrs: {}, content: peer.signedPreKey.keyPair.public },
									{ tag: 'signature', attrs: {}, content: peer.signedPreKey.signature },
								],
							},
							{
								tag: 'key',
								attrs: {},
								content: [
									{ tag: 'id', attrs: {}, content: Buffer.from([0, 0, 7]) },
									{ tag: 'value', attrs: {}, content: Buffer.alloc(32, 9) },
								],
							},
						],
					},
				],
			},
		],
	}

	const bundle = parsePreKeyBundles(result).get('5511988887777@s.whatsapp.net')
	assert.ok(bundle)

	assert.equal(bundle.registrationId, 0x1020)
	assert.equal(bundle.signedPreKeyId, 1)
	assert.equal(bundle.preKeyId, 7)

	// The signature is what separates end-to-end encryption from
	// encryption-to-whoever-the-server-says.
	assert.equal(verifyPreKeyBundle(bundle, xeddsaVerify), true)
})

test('a bundle with a forged signed pre-key fails verification', () => {
	const peer = initAuthCreds()
	const attacker = initAuthCreds()

	const bundle = {
		registrationId: 1,
		identityKeyPublic: peer.signedIdentityKey.public,
		signedPreKeyId: 1,
		// The attacker swapped in their own pre-key but cannot sign it as the peer.
		signedPreKeyPublic: attacker.signedPreKey.keyPair.public,
		signedPreKeySignature: peer.signedPreKey.signature,
	}

	assert.equal(verifyPreKeyBundle(bundle, xeddsaVerify), false)
})

test('a bundle without a one-time pre-key is valid, not an error', () => {
	const peer = initAuthCreds()

	const result: BinaryNode = {
		tag: 'iq',
		attrs: {},
		content: [
			{
				tag: 'list',
				attrs: {},
				content: [
					{
						tag: 'user',
						attrs: { jid: 'x@s.whatsapp.net' },
						content: [
							{ tag: 'registration', attrs: {}, content: Buffer.from([0, 0, 0, 1]) },
							{ tag: 'identity', attrs: {}, content: peer.signedIdentityKey.public },
							{
								tag: 'skey',
								attrs: {},
								content: [
									{ tag: 'id', attrs: {}, content: Buffer.from([0, 0, 1]) },
									{ tag: 'value', attrs: {}, content: peer.signedPreKey.keyPair.public },
									{ tag: 'signature', attrs: {}, content: peer.signedPreKey.signature },
								],
							},
						],
					},
				],
			},
		],
	}

	const bundle = parsePreKeyBundles(result).get('x@s.whatsapp.net')

	assert.ok(bundle)
	assert.equal(bundle.preKeyId, undefined)
	assert.equal(bundle.preKeyPublic, undefined)
})

test('the remaining pre-key count is read from the attribute', () => {
	assert.equal(
		parsePreKeyCount({ tag: 'iq', attrs: {}, content: [{ tag: 'count', attrs: { value: '12' } }] }),
		12,
	)
})

test('identity keys go up without the type byte', () => {
	const creds = initAuthCreds()
	const node = buildPreKeyUploadNode(creds, generatePreKeys(1, 1))
	const identity = getBinaryNodeChild(node, 'identity')?.content as Buffer

	assert.equal(identity.length, 32, 'the wire carries the raw key here, not the 33-byte form')
	assert.equal(addKeyType(identity).length, 33)
	assert.equal(PRE_KEYS_PER_UPLOAD, 30)
})
