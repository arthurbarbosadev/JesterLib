import { createHash } from 'node:crypto'
import { aesDecryptCBC, aesEncryptCBC, hkdf, hmacSha256, randomBytes } from '../crypto/index.ts'

/**
 * Media encryption.
 *
 * Media does not travel through the Signal session — it is encrypted once with
 * its own key, uploaded to WhatsApp's media servers, and only the small
 * `mediaKey` rides inside the encrypted message. That is what lets a 5 MB image
 * be sent to ten devices without encrypting it ten times.
 *
 * The `info` strings below are per media type and are part of the protocol.
 * Encrypting an image with the video string produces a file the recipient
 * cannot open, with no error anywhere to explain why.
 */

export type MediaType = 'image' | 'video' | 'audio' | 'document'

const MEDIA_INFO: Record<MediaType, string> = {
	image: 'WhatsApp Image Keys',
	video: 'WhatsApp Video Keys',
	audio: 'WhatsApp Audio Keys',
	document: 'WhatsApp Document Keys',
}

/** The MAC is truncated to 10 bytes here — not 8 like Signal messages. */
const MAC_LENGTH = 10

export type MediaKeys = {
	iv: Buffer
	cipherKey: Buffer
	macKey: Buffer
	refKey: Buffer
}

/**
 * Expands a 32-byte media key into the four keys the format needs.
 *
 * 112 bytes: 16 iv, 32 cipher, 32 mac, 32 ref.
 */
export function expandMediaKey(mediaKey: Buffer, type: MediaType): MediaKeys {
	const expanded = hkdf(mediaKey, 112, { info: MEDIA_INFO[type] })

	return {
		iv: expanded.subarray(0, 16),
		cipherKey: expanded.subarray(16, 48),
		macKey: expanded.subarray(48, 80),
		refKey: expanded.subarray(80, 112),
	}
}

export type EncryptedMedia = {
	/** Ciphertext with the 10-byte MAC appended — this is what gets uploaded. */
	body: Buffer
	mediaKey: Buffer
	/** SHA-256 of the plaintext, so the recipient can verify what it decrypted. */
	fileSha256: Buffer
	/** SHA-256 of the uploaded bytes, which is what the server indexes. */
	fileEncSha256: Buffer
	fileLength: number
}

export function encryptMedia(plaintext: Buffer, type: MediaType, mediaKey?: Buffer): EncryptedMedia {
	const key = mediaKey ?? randomBytes(32)
	const keys = expandMediaKey(key, type)

	const ciphertext = aesEncryptCBC(plaintext, keys.cipherKey, keys.iv)

	// The MAC covers the IV as well as the ciphertext. Leaving the IV out
	// produces a file every real client rejects.
	const mac = hmacSha256(Buffer.concat([keys.iv, ciphertext]), keys.macKey).subarray(0, MAC_LENGTH)
	const body = Buffer.concat([ciphertext, mac])

	return {
		body,
		mediaKey: key,
		fileSha256: createHash('sha256').update(plaintext).digest(),
		fileEncSha256: createHash('sha256').update(body).digest(),
		fileLength: plaintext.length,
	}
}

export class MediaError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'MediaError'
	}
}

export function decryptMedia(downloaded: Buffer, mediaKey: Buffer, type: MediaType): Buffer {
	if (downloaded.length <= MAC_LENGTH) {
		throw new MediaError('media payload shorter than its MAC')
	}

	const keys = expandMediaKey(mediaKey, type)

	const ciphertext = downloaded.subarray(0, downloaded.length - MAC_LENGTH)
	const receivedMac = downloaded.subarray(downloaded.length - MAC_LENGTH)

	const expectedMac = hmacSha256(Buffer.concat([keys.iv, ciphertext]), keys.macKey).subarray(
		0,
		MAC_LENGTH,
	)

	// Verified before decrypting: a tampered file should never reach a decoder.
	if (!expectedMac.equals(receivedMac)) {
		throw new MediaError('media MAC mismatch — corrupted or tampered download')
	}

	return aesDecryptCBC(ciphertext, keys.cipherKey, keys.iv)
}
