import assert from 'node:assert/strict'
import { test } from 'node:test'
import { initAuthCreds } from '../src/auth/creds.ts'
import { generatePreKeys } from '../src/auth/prekeys.ts'
import { makeInMemoryKeyStore, type AuthenticationState } from '../src/auth/state.ts'
import { addKeyType, xeddsaSign } from '../src/crypto/index.ts'
import type { PreKeyBundle } from '../src/signal/cipher.ts'
import {
	SignalRepositoryError,
	makeSignalRepository,
	sessionAddress,
} from '../src/signal/repository.ts'

/**
 * A device whose entire Signal state lives in a key store.
 *
 * This mirrors how the worker runs: nothing is held in memory between calls, so
 * every message load and save goes through the store. If serialization dropped
 * anything, the second message would fail.
 */
function makeDevice(registrationId: number) {
	const creds = initAuthCreds()
	creds.registrationId = registrationId

	const auth: AuthenticationState = { creds, keys: makeInMemoryKeyStore() }
	const repo = makeSignalRepository(auth)
	const preKeys = generatePreKeys(1, 5)

	return {
		auth,
		creds,
		repo,
		preKeys,
		jid: `${5511900000000 + registrationId}@s.whatsapp.net`,

		async publish() {
			await repo.storePreKeys(preKeys)
		},

		bundle(withOneTime = true): PreKeyBundle {
			return {
				registrationId,
				identityKeyPublic: creds.signedIdentityKey.public,
				signedPreKeyId: creds.signedPreKey.keyId,
				signedPreKeyPublic: creds.signedPreKey.keyPair.public,
				signedPreKeySignature: creds.signedPreKey.signature,
				preKeyId: withOneTime ? preKeys[0]!.keyId : undefined,
				preKeyPublic: withOneTime ? preKeys[0]!.keyPair.public : undefined,
			}
		},
	}
}

test('session addresses keep devices apart', () => {
	// Collapsing these would decrypt one device's messages with another's keys.
	assert.equal(sessionAddress('5511999999999@s.whatsapp.net'), '5511999999999.0')
	assert.equal(sessionAddress('5511999999999:3@s.whatsapp.net'), '5511999999999.3')
	assert.notEqual(
		sessionAddress('5511999999999@s.whatsapp.net'),
		sessionAddress('5511999999999:3@s.whatsapp.net'),
	)

	assert.throws(() => sessionAddress('sem-arroba'), SignalRepositoryError)
})

test('two devices talk through the key store alone', async () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	await bob.publish()

	await alice.repo.openSession(bob.jid, bob.bundle())

	const first = await alice.repo.encrypt(bob.jid, Buffer.from('oi Bob'))
	assert.equal(first.type, 'pkmsg')

	assert.equal(
		(await bob.repo.decrypt(alice.jid, 'pkmsg', first.ciphertext)).toString(),
		'oi Bob',
	)

	// Bob replies; from here on everything runs off stored sessions.
	const reply = await bob.repo.encrypt(alice.jid, Buffer.from('oi Alice'))
	assert.equal((await alice.repo.decrypt(bob.jid, 'msg', reply.ciphertext)).toString(), 'oi Alice')

	for (let i = 0; i < 10; i++) {
		const out = await alice.repo.encrypt(bob.jid, Buffer.from(`a${i}`))
		assert.equal((await bob.repo.decrypt(alice.jid, out.type, out.ciphertext)).toString(), `a${i}`)

		const back = await bob.repo.encrypt(alice.jid, Buffer.from(`b${i}`))
		assert.equal((await alice.repo.decrypt(bob.jid, back.type, back.ciphertext)).toString(), `b${i}`)
	}
})

test('a consumed one-time pre-key is deleted from the store', async () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	await bob.publish()

	const preKeyId = String(bob.preKeys[0]!.keyId)
	assert.ok((await bob.auth.keys.get('pre-key', [preKeyId]))[preKeyId], 'should start present')

	await alice.repo.openSession(bob.jid, bob.bundle())
	const sent = await alice.repo.encrypt(bob.jid, Buffer.from('x'))
	await bob.repo.decrypt(alice.jid, 'pkmsg', sent.ciphertext)

	// Leaving it would let a replay re-establish the same session.
	assert.equal(
		(await bob.auth.keys.get('pre-key', [preKeyId]))[preKeyId],
		undefined,
		'the one-time pre-key must be gone after use',
	)
})

test('a bundle with a forged signature is refused', async () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	const attacker = makeDevice(300)

	// The attacker swaps in their own signed pre-key but cannot sign it as Bob.
	const forged: PreKeyBundle = {
		...bob.bundle(false),
		signedPreKeyPublic: attacker.creds.signedPreKey.keyPair.public,
	}

	await assert.rejects(
		() => alice.repo.openSession(bob.jid, forged),
		(err: Error) => {
			assert.match(err.message, /failed signature verification/)
			return true
		},
	)

	assert.equal(await alice.repo.hasSession(bob.jid), false, 'no session may be created')
})

test('a correctly signed bundle from a rotated key is accepted', async () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)

	// Bob rotates his signed pre-key and signs the new one properly.
	const rotated = makeDevice(999).creds.signedPreKey.keyPair
	const bundle: PreKeyBundle = {
		...bob.bundle(false),
		signedPreKeyPublic: rotated.public,
		signedPreKeySignature: xeddsaSign(
			bob.creds.signedIdentityKey.private,
			addKeyType(rotated.public),
		),
	}

	await alice.repo.openSession(bob.jid, bundle)
	assert.equal(await alice.repo.hasSession(bob.jid), true)
})

test('encrypting without a session says what to do about it', async () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)

	await assert.rejects(
		() => alice.repo.encrypt(bob.jid, Buffer.from('x')),
		(err: Error) => {
			assert.match(err.message, /fetch a pre-key bundle/)
			return true
		},
	)
})

test('a pkmsg for an unknown pre-key fails with a clear reason', async () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)

	// Bob never stored his pre-keys, so he cannot complete the handshake.
	await alice.repo.openSession(bob.jid, bob.bundle())
	const sent = await alice.repo.encrypt(bob.jid, Buffer.from('x'))

	await assert.rejects(
		() => bob.repo.decrypt(alice.jid, 'pkmsg', sent.ciphertext),
		(err: Error) => {
			assert.match(err.message, /already consumed|is gone/)
			return true
		},
	)
})

test('sessions with different devices of the same number stay separate', async () => {
	const alice = makeDevice(100)
	const phone = makeDevice(200)
	const laptop = makeDevice(201)

	await phone.publish()
	await laptop.publish()

	const base = '5511988887777'
	const phoneJid = `${base}:0@s.whatsapp.net`
	const laptopJid = `${base}:3@s.whatsapp.net`

	await alice.repo.openSession(phoneJid, phone.bundle())
	await alice.repo.openSession(laptopJid, laptop.bundle())

	const toPhone = await alice.repo.encrypt(phoneJid, Buffer.from('pro celular'))
	const toLaptop = await alice.repo.encrypt(laptopJid, Buffer.from('pro laptop'))

	assert.equal((await phone.repo.decrypt(alice.jid, 'pkmsg', toPhone.ciphertext)).toString(), 'pro celular')
	assert.equal((await laptop.repo.decrypt(alice.jid, 'pkmsg', toLaptop.ciphertext)).toString(), 'pro laptop')

	// The laptop must not be able to read what was meant for the phone.
	await assert.rejects(() => laptop.repo.decrypt(alice.jid, 'pkmsg', toPhone.ciphertext))
})

test('the store holds everything needed to resume', async () => {
	const alice = makeDevice(100)
	const bob = makeDevice(200)
	await bob.publish()

	await alice.repo.openSession(bob.jid, bob.bundle())
	const sent = await alice.repo.encrypt(bob.jid, Buffer.from('antes'))
	await bob.repo.decrypt(alice.jid, 'pkmsg', sent.ciphertext)

	// A fresh repository over the same store — what a restarted worker sees.
	const resumed = makeSignalRepository(bob.auth)
	const reply = await resumed.encrypt(alice.jid, Buffer.from('depois do restart'))

	assert.equal(
		(await alice.repo.decrypt(bob.jid, reply.type, reply.ciphertext)).toString(),
		'depois do restart',
	)
})
