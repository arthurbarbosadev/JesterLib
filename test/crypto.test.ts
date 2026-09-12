import assert from 'node:assert/strict'
import { test } from 'node:test'
import { Curve, aesDecryptGCM, aesEncryptGCM, addKeyType, hkdf, hmacSha256, sha256, stripKeyType } from '../src/crypto/index.ts'

// RFC 7748, secao 6.1 — vetor de teste oficial do X25519 (Diffie-Hellman)
const ALICE_PRIV = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex')
const ALICE_PUB = Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex')
const BOB_PRIV = Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex')
const BOB_PUB = Buffer.from('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex')
const SHARED = Buffer.from('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742', 'hex')

test('X25519 bate com o vetor do RFC 7748', () => {
	assert.deepEqual(Curve.publicFromPrivate(ALICE_PRIV), ALICE_PUB)
	assert.deepEqual(Curve.publicFromPrivate(BOB_PRIV), BOB_PUB)
	assert.deepEqual(Curve.sharedKey(ALICE_PRIV, BOB_PUB), SHARED)
	assert.deepEqual(Curve.sharedKey(BOB_PRIV, ALICE_PUB), SHARED)
})

test('ECDH funciona com chave pública prefixada com 0x05', () => {
	assert.deepEqual(Curve.sharedKey(ALICE_PRIV, addKeyType(BOB_PUB)), SHARED)
})

test('generateKeyPair produz par coerente', () => {
	const a = Curve.generateKeyPair()
	const b = Curve.generateKeyPair()

	assert.equal(a.private.length, 32)
	assert.equal(a.public.length, 32)
	assert.deepEqual(Curve.publicFromPrivate(a.private), a.public)
	assert.deepEqual(Curve.sharedKey(a.private, b.public), Curve.sharedKey(b.private, a.public))
})

test('stripKeyType / addKeyType são inversos', () => {
	assert.equal(addKeyType(ALICE_PUB).length, 33)
	assert.equal(addKeyType(ALICE_PUB)[0], 0x05)
	assert.deepEqual(stripKeyType(addKeyType(ALICE_PUB)), ALICE_PUB)
	assert.deepEqual(addKeyType(addKeyType(ALICE_PUB)).length, 33)
	assert.throws(() => stripKeyType(Buffer.alloc(10)))
})

// RFC 5869, caso de teste 1 (SHA-256)
test('HKDF bate com o vetor do RFC 5869', () => {
	const out = hkdf(Buffer.from('0b'.repeat(22), 'hex'), 42, {
		salt: Buffer.from('000102030405060708090a0b0c', 'hex'),
		info: Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'),
	})

	assert.equal(
		out.toString('hex'),
		'3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
	)
})

test('SHA-256 e HMAC-SHA256 conhecidos', () => {
	assert.equal(sha256(Buffer.from('abc')).toString('hex'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
	assert.equal(
		hmacSha256(Buffer.from('Hi There'), Buffer.from('0b'.repeat(20), 'hex')).toString('hex'),
		'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
	)
})

test('AES-256-GCM faz round-trip e detecta AAD errada', () => {
	const key = Buffer.alloc(32, 7)
	const iv = Buffer.alloc(12, 3)
	const aad = Buffer.from('cabecalho')
	const msg = Buffer.from('oi jester')

	const enc = aesEncryptGCM(msg, key, iv, aad)
	assert.deepEqual(aesDecryptGCM(enc, key, iv, aad), msg)
	assert.throws(() => aesDecryptGCM(enc, key, iv, Buffer.from('outra')))
})
