import assert from 'node:assert/strict'
import { test } from 'node:test'
import { Curve, addKeyType, xeddsaSign, xeddsaVerify, type KeyPair } from '../src/crypto/index.ts'
import {
	createOutgoingSession,
	decryptPreKeyMessage,
	decryptSignalMessage,
	encrypt,
	type IncomingPreKeyContext,
	type PreKeyBundle,
} from '../src/signal/cipher.ts'
import { SignalMessageError } from '../src/signal/message.ts'
import {
	MAX_SKIPPED_MESSAGE_KEYS,
	SessionError,
	createSessionRecord,
	deserializeSessionRecord,
	messageKeysForCounter,
	serializeSessionRecord,
	type SessionRecord,
} from '../src/signal/session.ts'

/**
 * A device with the keys a real one would publish.
 *
 * Both parties are driven for real through the whole protocol. Nothing is
 * asserted against a constant I wrote down: if the two sides disagree anywhere
 * — DH ordering, ratchet direction, MAC input — the exchange simply stops
 * working, which is exactly how it would fail in production.
 */
function makeDevice(registrationId: number) {
	const identityKey = Curve.generateKeyPair()
	const signedPreKey = Curve.generateKeyPair()
	const preKey = Curve.generateKeyPair()

	return {
		registrationId,
		identityKey,
		signedPreKey,
		signedPreKeyId: 1,
		preKey,
		preKeyId: 7,
		record: createSessionRecord(),

		bundle(withOneTimePreKey = true): PreKeyBundle {
			return {
				registrationId,
				identityKeyPublic: identityKey.public,
				signedPreKeyId: 1,
				signedPreKeyPublic: signedPreKey.public,
				signedPreKeySignature: xeddsaSign(identityKey.private, addKeyType(signedPreKey.public)),
				preKeyId: withOneTimePreKey ? 7 : undefined,
				preKeyPublic: withOneTimePreKey ? preKey.public : undefined,
			}
		},

		resolver(): (signedPreKeyId: number, preKeyId?: number) => IncomingPreKeyContext {
			return (_signedPreKeyId, preKeyId) => ({
				local: { identityKey, registrationId },
				signedPreKey,
				preKey: preKeyId === 7 ? preKey : undefined,
			})
		},

		local() {
			return { identityKey, registrationId }
		},
	}
}

type Device = ReturnType<typeof makeDevice>

/** Alice opens a session with Bob and sends the first message. */
function openSession(alice: Device, bob: Device, first = 'oi', withOneTimePreKey = true) {
	createOutgoingSession(alice.local(), bob.bundle(withOneTimePreKey), alice.record)

	const sent = encrypt(alice.record, Buffer.from(first))
	assert.equal(sent.type, 'pkmsg', 'the first message must be a pkmsg')

	const received = decryptPreKeyMessage(bob.record, sent.ciphertext, bob.resolver())
	assert.equal(received.plaintext.toString(), first)

	return received
}

function send(from: Device, to: Device, text: string): string {
	const sent = encrypt(from.record, Buffer.from(text))

	if (sent.type === 'pkmsg') {
		return decryptPreKeyMessage(to.record, sent.ciphertext, to.resolver()).plaintext.toString()
	}

	return decryptSignalMessage(to.record, sent.ciphertext).toString()
}

// ---------------------------------------------------------------------------
// Session establishment
// ---------------------------------------------------------------------------

test('the signed pre-key signature verifies against the identity key', () => {
	const bob = makeDevice(200)
	const bundle = bob.bundle()

	assert.equal(
		xeddsaVerify(bundle.identityKeyPublic, addKeyType(bundle.signedPreKeyPublic), bundle.signedPreKeySignature),
		true,
	)
})

test('a full session opens and the first message decrypts', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	const result = openSession(alice, bob, 'primeira mensagem')

	assert.equal(result.usedPreKeyId, 7, 'should report which one-time pre-key was consumed')
})

test('a session opens without a one-time pre-key', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	const result = openSession(alice, bob, 'sem prekey', false)

	assert.equal(result.usedPreKeyId, undefined)
})

test('messages flow in both directions', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)

	assert.equal(send(bob, alice, 'oi Alice'), 'oi Alice')
	assert.equal(send(alice, bob, 'tudo bem?'), 'tudo bem?')
	assert.equal(send(bob, alice, 'tudo'), 'tudo')
})

test('once the peer replies, messages stop being pkmsg', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)

	// Bob has not answered yet, so Alice must keep advertising the bundle:
	// Bob may not have processed the first message.
	assert.equal(encrypt(alice.record, Buffer.from('ainda pkmsg')).type, 'pkmsg')

	send(bob, alice, 'respondi')

	assert.equal(encrypt(alice.record, Buffer.from('agora msg')).type, 'msg')
})

test('a long back-and-forth keeps working', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)

	for (let i = 0; i < 25; i++) {
		assert.equal(send(alice, bob, `a${i}`), `a${i}`)
		assert.equal(send(bob, alice, `b${i}`), `b${i}`)
	}
})

test('many messages in a row from one side (no ratchet turn)', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)
	send(bob, alice, 'ok')

	for (let i = 0; i < 30; i++) {
		assert.equal(send(alice, bob, `seguida ${i}`), `seguida ${i}`)
	}
})

// ---------------------------------------------------------------------------
// Out of order delivery
// ---------------------------------------------------------------------------

test('messages that arrive out of order still decrypt', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)
	send(bob, alice, 'ok')

	// Alice sends five, the network scrambles them.
	const sent = Array.from({ length: 5 }, (_, i) => encrypt(alice.record, Buffer.from(`msg ${i}`)))
	const order = [3, 0, 4, 1, 2]

	for (const i of order) {
		const decrypted = decryptSignalMessage(bob.record, sent[i]!.ciphertext)
		assert.equal(decrypted.toString(), `msg ${i}`)
	}
})

test('a message delayed across a ratchet turn still decrypts', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)
	send(bob, alice, 'ok')

	// Alice sends one that gets stuck in the network.
	const delayed = encrypt(alice.record, Buffer.from('atrasada'))

	// Meanwhile the conversation moves on and the ratchet turns several times.
	for (let i = 0; i < 3; i++) {
		send(bob, alice, `b${i}`)
		send(alice, bob, `a${i}`)
	}

	assert.equal(decryptSignalMessage(bob.record, delayed.ciphertext).toString(), 'atrasada')
})

test('a replayed message is rejected', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)
	send(bob, alice, 'ok')

	const sent = encrypt(alice.record, Buffer.from('unica'))
	assert.equal(decryptSignalMessage(bob.record, sent.ciphertext).toString(), 'unica')

	// Each message key is used exactly once and then destroyed.
	assert.throws(() => decryptSignalMessage(bob.record, sent.ciphertext), SessionError)
})

test('a huge counter gap is refused instead of hanging', () => {
	// Driven directly against the chain rather than by poking bytes in a
	// ciphertext: a peer can claim any counter it likes, and without the cap the
	// receiver would derive that many keys and stall the process.
	const chain = {
		ratchetKey: Buffer.alloc(32, 1),
		chainKey: { key: Buffer.alloc(32, 2), index: 0 },
		messageKeys: new Map(),
	}

	assert.throws(
		() => messageKeysForCounter(chain, MAX_SKIPPED_MESSAGE_KEYS + 1),
		(err: Error) => {
			assert.match(err.message, /exceeds the limit/)
			return true
		},
	)

	// Just under the cap is still allowed.
	assert.ok(messageKeysForCounter(chain, 10).cipherKey)
})

test('a counter below the chain index is rejected as a duplicate', () => {
	const chain = {
		ratchetKey: Buffer.alloc(32, 1),
		chainKey: { key: Buffer.alloc(32, 2), index: 0 },
		messageKeys: new Map(),
	}

	messageKeysForCounter(chain, 5)

	// Index has moved past 3 and no key was banked for it under this path.
	assert.throws(() => messageKeysForCounter(chain, 5), SessionError)
})

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

test('a tampered ciphertext fails the MAC', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)
	send(bob, alice, 'ok')

	const sent = encrypt(alice.record, Buffer.from('mensagem intacta'))
	const tampered = Buffer.from(sent.ciphertext)
	const middle = Math.floor(tampered.length / 2)
	tampered.writeUInt8(tampered.readUInt8(middle) ^ 0x01, middle)

	assert.throws(() => decryptSignalMessage(bob.record, tampered))
})

test('a message from a third party is rejected', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	const mallory = makeDevice(300)

	openSession(alice, bob)
	send(bob, alice, 'ok')

	// Mallory opens her own session with Bob, then tries to pass a message off
	// into Alice's session.
	createOutgoingSession(mallory.local(), bob.bundle(false), mallory.record)
	const fromMallory = encrypt(mallory.record, Buffer.from('sou a Alice'))

	const alicesRecord: SessionRecord = alice.record
	assert.throws(() => decryptSignalMessage(alicesRecord, fromMallory.ciphertext))
})

test('a truncated message is rejected', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)
	send(bob, alice, 'ok')

	const sent = encrypt(alice.record, Buffer.from('completa'))

	assert.throws(
		() => decryptSignalMessage(bob.record, sent.ciphertext.subarray(0, 4)),
		SignalMessageError,
	)
})

// ---------------------------------------------------------------------------
// Persistence — the point of the whole design
// ---------------------------------------------------------------------------

test('a session survives being serialized and reloaded', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)
	send(bob, alice, 'ok')
	send(alice, bob, 'continua')

	// Both sides are written out and read back, as the worker would do.
	alice.record = deserializeSessionRecord(serializeSessionRecord(alice.record))
	bob.record = deserializeSessionRecord(serializeSessionRecord(bob.record))

	assert.equal(send(alice, bob, 'depois do reload'), 'depois do reload')
	assert.equal(send(bob, alice, 'funcionou'), 'funcionou')
})

test('skipped message keys survive serialization', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)
	send(bob, alice, 'ok')

	const sent = Array.from({ length: 4 }, (_, i) => encrypt(alice.record, Buffer.from(`m${i}`)))

	// Bob receives the last one, banking keys for the three it skipped.
	assert.equal(decryptSignalMessage(bob.record, sent[3]!.ciphertext).toString(), 'm3')

	// The process restarts before the stragglers arrive.
	bob.record = deserializeSessionRecord(serializeSessionRecord(bob.record))

	for (const i of [0, 1, 2]) {
		assert.equal(decryptSignalMessage(bob.record, sent[i]!.ciphertext).toString(), `m${i}`)
	}
})

test('a reloaded session before any reply still sends a pkmsg', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)

	createOutgoingSession(alice.local(), bob.bundle(), alice.record)
	alice.record = deserializeSessionRecord(serializeSessionRecord(alice.record))

	const sent = encrypt(alice.record, Buffer.from('depois do reload'))
	assert.equal(sent.type, 'pkmsg', 'pendingPreKey must survive serialization')

	assert.equal(
		decryptPreKeyMessage(bob.record, sent.ciphertext, bob.resolver()).plaintext.toString(),
		'depois do reload',
	)
})

test('a retried pkmsg does not rebuild the session', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	createOutgoingSession(alice.local(), bob.bundle(), alice.record)

	const first = encrypt(alice.record, Buffer.from('um'))
	const second = encrypt(alice.record, Buffer.from('dois'))

	assert.equal(decryptPreKeyMessage(bob.record, first.ciphertext, bob.resolver()).plaintext.toString(), 'um')

	// The second pkmsg carries the same base key. Rebuilding the session here
	// would throw away the ratchet state built by the first.
	assert.equal(decryptPreKeyMessage(bob.record, second.ciphertext, bob.resolver()).plaintext.toString(), 'dois')

	assert.equal(send(bob, alice, 'ainda funciona'), 'ainda funciona')
})

test('binary payloads round-trip unchanged', () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	openSession(alice, bob)
	send(bob, alice, 'ok')

	for (const size of [0, 1, 15, 16, 17, 1000]) {
		const payload = Buffer.alloc(size, 0xab)
		const sent = encrypt(alice.record, payload)

		assert.deepEqual(decryptSignalMessage(bob.record, sent.ciphertext), payload, `falhou em ${size} bytes`)
	}
})

test('encrypting without a session is an explicit error', () => {
	const record = createSessionRecord()

	assert.throws(() => encrypt(record, Buffer.from('x')), SessionError)
})
