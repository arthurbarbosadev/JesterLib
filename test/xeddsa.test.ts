import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { Curve, addKeyType } from '../src/crypto/curve.ts'
import {
	SIGNATURE_LENGTH,
	montgomeryToEdwardsPublic,
	xeddsaSign,
	xeddsaVerify,
} from '../src/crypto/xeddsa.ts'

test('signs and verifies', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const message = Buffer.from('message to sign')
	const signature = xeddsaSign(priv, message)

	assert.equal(signature.length, SIGNATURE_LENGTH)
	assert.equal(xeddsaVerify(pub, message, signature), true)
})

test('accepts a public key carrying the 0x05 type byte', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const message = Buffer.from('signed prekey')
	const signature = xeddsaSign(priv, message)

	assert.equal(xeddsaVerify(addKeyType(pub), message, signature), true)
})

test('rejects a modified message', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const signature = xeddsaSign(priv, Buffer.from('original'))

	assert.equal(xeddsaVerify(pub, Buffer.from('tampered'), signature), false)
})

test('rejects a modified signature', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const message = Buffer.from('message')
	const signature = xeddsaSign(priv, message)

	for (const index of [0, 31, 32, 63]) {
		const tampered = Buffer.from(signature)
		tampered.writeUInt8(tampered.readUInt8(index) ^ 0x01, index)

		assert.equal(xeddsaVerify(pub, message, tampered), false, `byte ${index} went undetected`)
	}
})

test('rejects a signature from a different key', () => {
	const a = Curve.generateKeyPair()
	const b = Curve.generateKeyPair()
	const message = Buffer.from('message')

	assert.equal(xeddsaVerify(b.public, message, xeddsaSign(a.private, message)), false)
})

test('rejects a signature of the wrong length', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const message = Buffer.from('m')
	const signature = xeddsaSign(priv, message)

	assert.equal(xeddsaVerify(pub, message, signature.subarray(0, 63)), false)
	assert.equal(xeddsaVerify(pub, message, Buffer.concat([signature, Buffer.alloc(1)])), false)
})

test('is deterministic with a fixed nonce and randomized without one', () => {
	const { private: priv } = Curve.generateKeyPair()
	const message = Buffer.from('message')
	const nonce = Buffer.alloc(64, 7)

	assert.deepEqual(xeddsaSign(priv, message, nonce), xeddsaSign(priv, message, nonce))
	assert.notDeepEqual(xeddsaSign(priv, message), xeddsaSign(priv, message))
})

/**
 * An independent verification path: the same computation done by @noble rather
 * than OpenSSL. If both agree, a bug would have to exist in both at once — and
 * they share no code.
 */
test('the signature also verifies under @noble Ed25519', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const message = Buffer.from('cross-check')
	const signature = xeddsaSign(priv, message)
	const edwards = montgomeryToEdwardsPublic(pub)

	assert.equal(ed25519.verify(signature, message, edwards), true)
})

/**
 * Closes the Montgomery -> Edwards -> Montgomery loop using @noble conversion
 * on the way back. Validates the birational map in both directions.
 */
test('Montgomery <-> Edwards conversion is consistent', () => {
	for (let i = 0; i < 20; i++) {
		const { public: montgomery } = Curve.generateKeyPair()
		const edwards = montgomeryToEdwardsPublic(montgomery)

		assert.deepEqual(Buffer.from(ed25519.utils.toMontgomery(edwards)), montgomery)
	}
})

/**
 * The Edwards key sign bit is 1 for roughly half of all keys. If the scalar
 * negation is missing, half the cases fail — this loop makes sure both branches
 * are exercised.
 */
test('works for both values of the sign bit', () => {
	let withSignBit = 0
	let withoutSignBit = 0

	for (let i = 0; i < 40; i++) {
		const { private: priv, public: pub } = Curve.generateKeyPair()
		const message = randomBytes(32)

		assert.equal(xeddsaVerify(pub, message, xeddsaSign(priv, message)), true)

		// rebuild the un-normalized Edwards point to see which branch was taken
		const scalar = Buffer.from(priv)
		scalar[0]! &= 248
		scalar[31]! &= 127
		scalar[31]! |= 64

		let k = 0n
		for (let j = 31; j >= 0; j--) {
			k = (k << 8n) | BigInt(scalar[j]!)
		}

		const encoded = ed25519.Point.BASE.multiply(k % ed25519.Point.CURVE().n).toBytes()

		if ((encoded[31]! >> 7) & 1) {
			withSignBit++
		} else {
			withoutSignBit++
		}
	}

	assert.ok(withSignBit > 0, 'no key with sign bit 1 was tested')
	assert.ok(withoutSignBit > 0, 'no key with sign bit 0 was tested')
})

test('empty message and long message', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()

	for (const message of [Buffer.alloc(0), randomBytes(100_000)]) {
		assert.equal(xeddsaVerify(pub, message, xeddsaSign(priv, message)), true)
	}
})
