import { randomBytes } from '../crypto/index.ts'

/**
 * WhatsApp's own padding, applied to the plaintext before Signal encrypts it.
 *
 * This sits on top of the PKCS7 padding AES-CBC already does — it is not a
 * replacement. Its purpose is different: PKCS7 rounds up to the block size,
 * while this adds a random 1..16 bytes so the ciphertext length leaks less
 * about the message length.
 *
 * The format is the same idea as PKCS7: every added byte holds the number of
 * bytes added, so the receiver reads the last one to know how much to strip.
 */

const MIN_PAD = 1
const MAX_PAD = 16

export function padMessage(plaintext: Buffer): Buffer {
	// 1..16; never 0, since a 0 byte would be read as "strip nothing" and leave
	// the padding in place.
	const size = (randomBytes(1)[0]! & 0x0f) + MIN_PAD

	return Buffer.concat([plaintext, Buffer.alloc(size, size)])
}

export function unpadMessage(padded: Buffer): Buffer {
	if (padded.length === 0) {
		throw new Error('cannot unpad an empty buffer')
	}

	const size = padded[padded.length - 1]!

	if (size < MIN_PAD || size > MAX_PAD || size > padded.length) {
		throw new Error(`invalid padding byte ${size} for a ${padded.length} byte message`)
	}

	return padded.subarray(0, padded.length - size)
}
