import {
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	randomBytes,
} from 'node:crypto'

/**
 * Curve25519 (X25519) via Node's native crypto.
 *
 * Node only accepts DER-encoded keys, but the protocol carries raw 32-byte
 * keys on the wire. The prefixes below are the fixed DER envelope for X25519 —
 * since the body has a constant length, concatenating is enough.
 *
 * SPKI  (public):  SEQUENCE { SEQUENCE { OID 1.3.101.110 }, BIT STRING }
 * PKCS8 (private): SEQUENCE { 0, SEQUENCE { OID 1.3.101.110 }, OCTET STRING }
 */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex')
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')

/** libsignal's type byte (DJB_TYPE) that prefixes public keys on the wire. */
export const KEY_TYPE_DJB = 0x05

export type KeyPair = {
	private: Buffer
	public: Buffer
}

/** Strips libsignal's 0x05 byte, if present, returning the raw 32 bytes. */
export function stripKeyType(key: Buffer): Buffer {
	if (key.length === 33) {
		if (key[0] !== KEY_TYPE_DJB) {
			throw new Error(`33-byte public key has unexpected type: 0x${key[0]!.toString(16)}`)
		}

		return key.subarray(1)
	}

	if (key.length !== 32) {
		throw new Error(`public key must be 32 or 33 bytes, got ${key.length}`)
	}

	return key
}

/** Prefixes with 0x05 — the format libsignal and several protocol nodes expect. */
export function addKeyType(key: Buffer): Buffer {
	return key.length === 33 ? key : Buffer.concat([Buffer.from([KEY_TYPE_DJB]), key])
}

function toNodePublicKey(raw: Buffer) {
	return createPublicKey({
		key: Buffer.concat([X25519_SPKI_PREFIX, stripKeyType(raw)]),
		format: 'der',
		type: 'spki',
	})
}

function toNodePrivateKey(raw: Buffer) {
	if (raw.length !== 32) {
		throw new Error(`private key must be 32 bytes, got ${raw.length}`)
	}

	return createPrivateKey({
		key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
		format: 'der',
		type: 'pkcs8',
	})
}

export const Curve = {
	generateKeyPair(): KeyPair {
		const { privateKey, publicKey } = generateKeyPairSync('x25519')

		// The last 32 bytes of the DER encoding are the raw key, since the
		// prefix has a fixed length.
		const priv = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(X25519_PKCS8_PREFIX.length)
		const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(X25519_SPKI_PREFIX.length)

		return { private: Buffer.from(priv), public: Buffer.from(pub) }
	},

	/** Derives the public key from a raw 32-byte private key. */
	publicFromPrivate(priv: Buffer): Buffer {
		const der = createPublicKey(toNodePrivateKey(priv)).export({ format: 'der', type: 'spki' })

		return Buffer.from(der.subarray(X25519_SPKI_PREFIX.length))
	},

	/** X25519 ECDH. Accepts public keys with or without the type byte. */
	sharedKey(priv: Buffer, pub: Buffer): Buffer {
		return diffieHellman({
			privateKey: toNodePrivateKey(priv),
			publicKey: toNodePublicKey(pub),
		})
	},
}

export { randomBytes }
