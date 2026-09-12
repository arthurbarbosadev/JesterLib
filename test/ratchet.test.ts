import assert from 'node:assert/strict'
import { test } from 'node:test'
import { Curve } from '../src/crypto/index.ts'
import {
	calculateInitiatorSecret,
	calculateReceiverSecret,
	deriveInitialKeys,
	deriveMessageKeys,
	deriveRootKey,
	nextChainKey,
	type ChainKey,
} from '../src/signal/ratchet.ts'

/**
 * Both sides of X3DH, run for real.
 *
 * This is the test that matters for the ratchet: if the order of the DH outputs
 * is wrong on either side, each party still computes a perfectly well-formed
 * secret — they just differ. In production that surfaces only as "cannot
 * decrypt", with nothing pointing at the cause.
 */
function runX3DH(opts: { withOneTimePreKey: boolean }) {
	const alice = { identity: Curve.generateKeyPair(), base: Curve.generateKeyPair() }
	const bob = {
		identity: Curve.generateKeyPair(),
		signedPreKey: Curve.generateKeyPair(),
		oneTimePreKey: Curve.generateKeyPair(),
	}

	const initiator = calculateInitiatorSecret({
		identityKey: alice.identity,
		baseKey: alice.base,
		theirIdentityPublic: bob.identity.public,
		theirSignedPreKeyPublic: bob.signedPreKey.public,
		theirOneTimePreKeyPublic: opts.withOneTimePreKey ? bob.oneTimePreKey.public : undefined,
	})

	const receiver = calculateReceiverSecret({
		identityKey: bob.identity,
		signedPreKey: bob.signedPreKey,
		theirIdentityPublic: alice.identity.public,
		theirBaseKeyPublic: alice.base.public,
		oneTimePreKey: opts.withOneTimePreKey ? bob.oneTimePreKey : undefined,
	})

	return { initiator, receiver, alice, bob }
}

test('X3DH: both sides derive the same master secret', () => {
	const { initiator, receiver } = runX3DH({ withOneTimePreKey: true })

	assert.deepEqual(initiator, receiver)
	// 32 discontinuity bytes + 4 DH outputs of 32
	assert.equal(initiator.length, 32 + 4 * 32)
})

test('X3DH works without a one-time pre-key', () => {
	const { initiator, receiver } = runX3DH({ withOneTimePreKey: false })

	assert.deepEqual(initiator, receiver)
	assert.equal(initiator.length, 32 + 3 * 32)
})

test('X3DH starts with the 32 discontinuity bytes', () => {
	const { initiator } = runX3DH({ withOneTimePreKey: true })

	assert.deepEqual(initiator.subarray(0, 32), Buffer.alloc(32, 0xff))
})

test('a mismatched one-time pre-key breaks the secret', () => {
	const { alice, bob } = runX3DH({ withOneTimePreKey: true })
	const wrongPreKey = Curve.generateKeyPair()

	const initiator = calculateInitiatorSecret({
		identityKey: alice.identity,
		baseKey: alice.base,
		theirIdentityPublic: bob.identity.public,
		theirSignedPreKeyPublic: bob.signedPreKey.public,
		theirOneTimePreKeyPublic: wrongPreKey.public,
	})

	const receiver = calculateReceiverSecret({
		identityKey: bob.identity,
		signedPreKey: bob.signedPreKey,
		theirIdentityPublic: alice.identity.public,
		theirBaseKeyPublic: alice.base.public,
		oneTimePreKey: bob.oneTimePreKey,
	})

	assert.notDeepEqual(initiator, receiver)
})

test('the same X3DH secret yields the same root and chain keys', () => {
	const { initiator, receiver } = runX3DH({ withOneTimePreKey: true })

	const a = deriveInitialKeys(initiator)
	const b = deriveInitialKeys(receiver)

	assert.deepEqual(a.rootKey, b.rootKey)
	assert.deepEqual(a.chainKey, b.chainKey)
	assert.equal(a.rootKey.length, 32)
	assert.equal(a.chainKey.length, 32)
	assert.notDeepEqual(a.rootKey, a.chainKey)
})

// ---------------------------------------------------------------------------
// Chain and message keys
// ---------------------------------------------------------------------------

test('the chain key advances deterministically and never repeats', () => {
	let chain: ChainKey = { key: Buffer.alloc(32, 1), index: 0 }
	const seen = new Set<string>()

	for (let i = 0; i < 50; i++) {
		assert.equal(chain.index, i)
		assert.ok(!seen.has(chain.key.toString('hex')), `chain key repeated at index ${i}`)
		seen.add(chain.key.toString('hex'))
		chain = nextChainKey(chain)
	}

	// Deterministic: the same starting point produces the same sequence.
	let again: ChainKey = { key: Buffer.alloc(32, 1), index: 0 }
	for (let i = 0; i < 50; i++) {
		again = nextChainKey(again)
	}

	assert.deepEqual(again, chain)
})

test('message keys are distinct from the chain key and from each other', () => {
	const chain: ChainKey = { key: Buffer.alloc(32, 7), index: 3 }
	const keys = deriveMessageKeys(chain)

	assert.equal(keys.cipherKey.length, 32)
	assert.equal(keys.macKey.length, 32)
	assert.equal(keys.iv.length, 16)
	assert.equal(keys.index, 3)

	// The three parts come from one 80-byte block but must not overlap.
	assert.notDeepEqual(keys.cipherKey, keys.macKey)
	assert.notDeepEqual(keys.cipherKey, chain.key)
	assert.notDeepEqual(keys.macKey, chain.key)

	// A different chain key gives entirely different message keys.
	const other = deriveMessageKeys({ key: Buffer.alloc(32, 8), index: 3 })
	assert.notDeepEqual(other.cipherKey, keys.cipherKey)
})

test('the message key cannot be used to recompute the chain key', () => {
	// Not a proof, just a guard: the two HMAC seeds must differ, or the message
	// key would reveal the next chain key and forward secrecy would be gone.
	const chain: ChainKey = { key: Buffer.alloc(32, 5), index: 0 }
	const message = deriveMessageKeys(chain)
	const next = nextChainKey(chain)

	assert.notDeepEqual(message.cipherKey, next.key)
	assert.notDeepEqual(message.macKey, next.key)
})

// ---------------------------------------------------------------------------
// Root chain
// ---------------------------------------------------------------------------

test('the root chain turns identically on both sides', () => {
	const rootKey = Buffer.alloc(32, 9)
	const alice = Curve.generateKeyPair()
	const bob = Curve.generateKeyPair()

	const fromAlice = deriveRootKey(rootKey, Curve.sharedKey(alice.private, bob.public))
	const fromBob = deriveRootKey(rootKey, Curve.sharedKey(bob.private, alice.public))

	assert.deepEqual(fromAlice.rootKey, fromBob.rootKey)
	assert.deepEqual(fromAlice.chainKey, fromBob.chainKey)
})

test('each turn of the root chain moves it forward', () => {
	let rootKey: Buffer = Buffer.alloc(32, 9)
	const seen = new Set<string>([rootKey.toString('hex')])

	for (let i = 0; i < 20; i++) {
		const a = Curve.generateKeyPair()
		const b = Curve.generateKeyPair()
		const result = deriveRootKey(rootKey, Curve.sharedKey(a.private, b.public))

		assert.ok(!seen.has(result.rootKey.toString('hex')), `root key repeated at turn ${i}`)
		assert.notDeepEqual(result.rootKey, result.chainKey)

		seen.add(result.rootKey.toString('hex'))
		rootKey = result.rootKey
	}
})
