import {
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	randomBytes,
} from 'node:crypto'

/**
 * Curve25519 (X25519) via a API nativa do Node.
 *
 * O Node só aceita chaves em DER, mas o protocolo trafega chaves cruas de 32
 * bytes. Os prefixos abaixo são o envelope DER fixo para X25519 — como o corpo
 * tem tamanho constante, basta concatenar.
 *
 * SPKI  (pública):  SEQUENCE { SEQUENCE { OID 1.3.101.110 }, BIT STRING }
 * PKCS8 (privada):  SEQUENCE { 0, SEQUENCE { OID 1.3.101.110 }, OCTET STRING }
 */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex')
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')

/** Byte de tipo do libsignal (DJB_TYPE) que prefixa chaves públicas na wire. */
export const KEY_TYPE_DJB = 0x05

export type KeyPair = {
	private: Buffer
	public: Buffer
}

/** Remove o byte 0x05 do libsignal, se presente, devolvendo os 32 bytes crus. */
export function stripKeyType(key: Buffer): Buffer {
	if (key.length === 33) {
		if (key[0] !== KEY_TYPE_DJB) {
			throw new Error(`chave pública de 33 bytes com tipo inesperado: 0x${key[0]!.toString(16)}`)
		}

		return key.subarray(1)
	}

	if (key.length !== 32) {
		throw new Error(`chave pública deve ter 32 ou 33 bytes, recebido ${key.length}`)
	}

	return key
}

/** Prefixa com 0x05 — formato esperado pelo libsignal e por vários nós do protocolo. */
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
		throw new Error(`chave privada deve ter 32 bytes, recebido ${raw.length}`)
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

		// Os últimos 32 bytes do DER são a chave crua, já que o prefixo é fixo.
		const priv = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(X25519_PKCS8_PREFIX.length)
		const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(X25519_SPKI_PREFIX.length)

		return { private: Buffer.from(priv), public: Buffer.from(pub) }
	},

	/** Deriva a chave pública a partir de uma privada crua de 32 bytes. */
	publicFromPrivate(priv: Buffer): Buffer {
		const der = createPublicKey(toNodePrivateKey(priv)).export({ format: 'der', type: 'spki' })

		return Buffer.from(der.subarray(X25519_SPKI_PREFIX.length))
	},

	/** ECDH X25519. Aceita a pública com ou sem o byte de tipo. */
	sharedKey(priv: Buffer, pub: Buffer): Buffer {
		return diffieHellman({
			privateKey: toNodePrivateKey(priv),
			publicKey: toNodePublicKey(pub),
		})
	},
}

export { randomBytes }
