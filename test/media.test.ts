import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { test } from 'node:test'
import {
	MediaError,
	decryptMedia,
	encryptMedia,
	expandMediaKey,
	type MediaType,
} from '../src/media/crypto.ts'

const TYPES: MediaType[] = ['image', 'video', 'audio', 'document']

test('media round-trips for every type and size', () => {
	for (const type of TYPES) {
		for (const size of [1, 15, 16, 17, 5000]) {
			const payload = randomBytes(size)
			const encrypted = encryptMedia(payload, type)

			assert.deepEqual(
				decryptMedia(encrypted.body, encrypted.mediaKey, type),
				payload,
				`falhou em ${type} de ${size} bytes`,
			)
		}
	}
})

test('the key expands into four distinct keys', () => {
	const keys = expandMediaKey(Buffer.alloc(32, 7), 'image')

	assert.equal(keys.iv.length, 16)
	assert.equal(keys.cipherKey.length, 32)
	assert.equal(keys.macKey.length, 32)
	assert.equal(keys.refKey.length, 32)

	// All four come from one 112-byte block and must not overlap.
	const seen = new Set([keys.iv, keys.cipherKey, keys.macKey, keys.refKey].map(b => b.toString('hex')))
	assert.equal(seen.size, 4)
})

test('each media type derives different keys', () => {
	// The info string is per type and part of the protocol. Encrypting an image
	// with the video string produces a file the recipient cannot open, with no
	// error anywhere to explain why.
	const mediaKey = Buffer.alloc(32, 3)
	const derived = TYPES.map(type => expandMediaKey(mediaKey, type).cipherKey.toString('hex'))

	assert.equal(new Set(derived).size, TYPES.length)
})

test('decrypting with the wrong type fails instead of returning garbage', () => {
	const payload = randomBytes(200)
	const encrypted = encryptMedia(payload, 'image')

	assert.throws(() => decryptMedia(encrypted.body, encrypted.mediaKey, 'video'), MediaError)
})

test('a tampered download is rejected before decryption', () => {
	const encrypted = encryptMedia(randomBytes(500), 'image')

	for (const index of [0, 100, encrypted.body.length - 1]) {
		const tampered = Buffer.from(encrypted.body)
		tampered.writeUInt8(tampered.readUInt8(index) ^ 0x01, index)

		assert.throws(() => decryptMedia(tampered, encrypted.mediaKey, 'image'), MediaError)
	}
})

test('the wrong media key is rejected', () => {
	const encrypted = encryptMedia(randomBytes(300), 'image')

	assert.throws(() => decryptMedia(encrypted.body, randomBytes(32), 'image'), MediaError)
})

test('the hashes describe the right bytes', () => {
	// fileSha256 is of the plaintext so the recipient can verify what it got;
	// fileEncSha256 is of the uploaded bytes, which is what the server indexes.
	const payload = randomBytes(1000)
	const encrypted = encryptMedia(payload, 'document')

	assert.deepEqual(encrypted.fileSha256, createHash('sha256').update(payload).digest())
	assert.deepEqual(encrypted.fileEncSha256, createHash('sha256').update(encrypted.body).digest())
	assert.equal(encrypted.fileLength, 1000)
})

test('the MAC is 10 bytes, not 8', () => {
	// Signal messages truncate to 8; media truncates to 10. Using the wrong one
	// here fails against every real client.
	const payload = randomBytes(64)
	const encrypted = encryptMedia(payload, 'image')

	// CBC pads 64 bytes to 80, plus a 10-byte MAC.
	assert.equal(encrypted.body.length, 80 + 10)
})

test('a payload shorter than the MAC is rejected', () => {
	assert.throws(() => decryptMedia(Buffer.alloc(5), randomBytes(32), 'image'), MediaError)
})

test('reusing a supplied media key reproduces the same ciphertext', () => {
	// Needed for retries: re-uploading must not produce a different file hash.
	const payload = randomBytes(400)
	const mediaKey = randomBytes(32)

	const a = encryptMedia(payload, 'image', mediaKey)
	const b = encryptMedia(payload, 'image', mediaKey)

	assert.deepEqual(a.body, b.body)
	assert.deepEqual(a.fileEncSha256, b.fileEncSha256)
})
