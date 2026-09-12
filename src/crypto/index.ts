import {
	createCipheriv,
	createDecipheriv,
	createHash,
	createHmac,
	hkdfSync,
	randomBytes,
} from 'node:crypto'

export * from './curve.ts'
export { randomBytes }

export function sha256(data: Buffer): Buffer {
	return createHash('sha256').update(data).digest()
}

export function hmacSha256(data: Buffer, key: Buffer): Buffer {
	return createHmac('sha256', key).update(data).digest()
}

/**
 * HKDF-SHA256 (RFC 5869) — extract + expand em uma chamada.
 * O handshake Noise usa salt variável e `info` vazio; a mídia usa o contrário.
 */
export function hkdf(ikm: Buffer, length: number, opts: { salt?: Buffer; info?: string | Buffer } = {}): Buffer {
	const salt = opts.salt ?? Buffer.alloc(0)
	const info = typeof opts.info === 'string' ? Buffer.from(opts.info) : (opts.info ?? Buffer.alloc(0))

	return Buffer.from(hkdfSync('sha256', ikm, salt, info, length))
}

const GCM_TAG_LENGTH = 16

export function aesEncryptGCM(plaintext: Buffer, key: Buffer, iv: Buffer, additionalData: Buffer): Buffer {
	const cipher = createCipheriv('aes-256-gcm', key, iv)
	cipher.setAAD(additionalData)

	return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
}

export function aesDecryptGCM(ciphertext: Buffer, key: Buffer, iv: Buffer, additionalData: Buffer): Buffer {
	if (ciphertext.length < GCM_TAG_LENGTH) {
		throw new Error('ciphertext menor que o tag GCM')
	}

	const body = ciphertext.subarray(0, ciphertext.length - GCM_TAG_LENGTH)
	const tag = ciphertext.subarray(ciphertext.length - GCM_TAG_LENGTH)

	const decipher = createDecipheriv('aes-256-gcm', key, iv)
	decipher.setAAD(additionalData)
	decipher.setAuthTag(tag)

	return Buffer.concat([decipher.update(body), decipher.final()])
}

export function aesEncryptCBC(plaintext: Buffer, key: Buffer, iv: Buffer): Buffer {
	const cipher = createCipheriv('aes-256-cbc', key, iv)

	return Buffer.concat([cipher.update(plaintext), cipher.final()])
}

export function aesDecryptCBC(ciphertext: Buffer, key: Buffer, iv: Buffer): Buffer {
	const decipher = createDecipheriv('aes-256-cbc', key, iv)

	return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}
