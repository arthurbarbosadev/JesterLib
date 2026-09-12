import { createHash, createPublicKey, randomBytes, verify as nodeVerify } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { stripKeyType } from './curve.ts'

/**
 * XEdDSA over Curve25519 — signing with an X25519 key.
 *
 * WhatsApp uses ONE key pair for everything: the same Curve25519 key performs
 * ECDH and signs (the signed pre-key, the device identity during pairing).
 * Ed25519 and X25519 use the same curve in different forms (Edwards vs
 * Montgomery), and XEdDSA is the bridge: it converts the key to Edwards form
 * at signing time.
 *
 * Node exposes native X25519 and Ed25519, but not that bridge — its API only
 * accepts an Ed25519 *seed*, which gets hashed into a scalar. Here the
 * Montgomery scalar is used directly, so the point multiplication has to be
 * done by hand (via @noble/curves).
 *
 * Verification, however, is plain Ed25519: the equation `R == sB - hA` and the
 * hash `SHA512(R || A || M)` are identical. That is why it uses Node's native
 * verifier — a path independent from the signing code, which is what makes the
 * tests meaningful.
 *
 * Reference: Signal, "The XEdDSA and VXEdDSA Signature Schemes".
 */

const CURVE = ed25519.Point.CURVE()

/** Field prime (2^255 - 19) and group order, read from the curve itself. */
const P = CURVE.p
const Q = CURVE.n

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

/**
 * XEdDSA's hash_1: SHA-512 prefixed with (2^256 - 2) in little-endian. The
 * prefix separates this domain from the hash used to compute `h`, which has
 * no prefix.
 */
const HASH1_PREFIX = Buffer.concat([Buffer.from([0xfe]), Buffer.alloc(31, 0xff)])

export const SIGNATURE_LENGTH = 64

function sha512(...parts: Buffer[]): Buffer {
	const hash = createHash('sha512')

	for (const part of parts) {
		hash.update(part)
	}

	return hash.digest()
}

function mod(a: bigint, m: bigint): bigint {
	const result = a % m

	return result >= 0n ? result : result + m
}

/** Modular inverse via Fermat — `m` is prime in both uses in this library. */
function invert(a: bigint, m: bigint): bigint {
	if (a === 0n) {
		throw new Error('zero has no modular inverse')
	}

	let result = 1n
	let base = mod(a, m)
	let exp = m - 2n

	while (exp > 0n) {
		if (exp & 1n) {
			result = (result * base) % m
		}

		base = (base * base) % m
		exp >>= 1n
	}

	return result
}

function bytesToNumberLE(bytes: Uint8Array): bigint {
	let value = 0n

	for (let i = bytes.length - 1; i >= 0; i--) {
		value = (value << 8n) | BigInt(bytes[i]!)
	}

	return value
}

function numberToBytesLE(value: bigint, length: number): Buffer {
	const out = Buffer.alloc(length)
	let v = value

	for (let i = 0; i < length; i++) {
		out[i] = Number(v & 0xffn)
		v >>= 8n
	}

	return out
}

/**
 * RFC 7748 clamping. X25519 clamps internally when multiplying, but here the
 * scalar is used directly on the Edwards curve — it must arrive clamped, or the
 * derived public key will not match the one used for ECDH.
 */
function clamp(key: Buffer): Buffer {
	if (key.length !== 32) {
		throw new Error(`private key must be 32 bytes, got ${key.length}`)
	}

	const out = Buffer.from(key)
	out[0]! &= 248
	out[31]! &= 127
	out[31]! |= 64

	return out
}

/**
 * Derives the Edwards key pair equivalent to a Montgomery scalar.
 *
 * The conversion clears the sign bit of the public key; when the original point
 * had sign 1, the scalar is negated to compensate. Without this, roughly half
 * of all keys produce invalid signatures — a bug that only shows up
 * intermittently.
 */
function calculateKeyPair(k: bigint): { publicKey: Buffer; scalar: bigint } {
	const point = ed25519.Point.BASE.multiply(mod(k, Q))
	const encoded = Buffer.from(point.toBytes())
	const signBit = (encoded[31]! >> 7) & 1

	encoded[31]! &= 0x7f

	return { publicKey: encoded, scalar: signBit === 1 ? mod(-k, Q) : mod(k, Q) }
}

/**
 * Converts the Montgomery `u` coordinate to Edwards `y`: y = (u-1)/(u+1).
 * The sign bit is left cleared, as XEdDSA requires.
 */
export function montgomeryToEdwardsPublic(montgomeryPublic: Buffer): Buffer {
	const u = mod(bytesToNumberLE(stripKeyType(montgomeryPublic)), P)

	if (u === P - 1n) {
		throw new Error('invalid Montgomery public key (u = -1)')
	}

	const y = mod((u - 1n) * invert(u + 1n, P), P)

	return numberToBytesLE(y, 32)
}

/**
 * Signs `message` with an X25519 private key.
 *
 * `nonce` exists only for deterministic tests — leave it out in production and
 * 64 random bytes are drawn. Unlike plain Ed25519, XEdDSA is randomized:
 * reusing a nonce across different messages leaks the private key.
 */
export function xeddsaSign(privateKey: Buffer, message: Buffer, nonce?: Buffer): Buffer {
	const k = bytesToNumberLE(clamp(privateKey))
	const { publicKey, scalar } = calculateKeyPair(k)

	const z = nonce ?? randomBytes(64)
	const r = mod(bytesToNumberLE(sha512(HASH1_PREFIX, numberToBytesLE(scalar, 32), message, z)), Q)

	if (r === 0n) {
		throw new Error('degenerate nonce; try again')
	}

	const R = Buffer.from(ed25519.Point.BASE.multiply(r).toBytes())
	const h = mod(bytesToNumberLE(sha512(R, publicKey, message)), Q)
	const s = mod(r + h * scalar, Q)

	return Buffer.concat([R, numberToBytesLE(s, 32)])
}

/**
 * Verifies an XEdDSA signature using Node's native Ed25519 verifier.
 *
 * This works because the verification equation is identical to Ed25519's — all
 * that is needed is converting the public key to Edwards form.
 */
export function xeddsaVerify(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
	if (signature.length !== SIGNATURE_LENGTH) {
		return false
	}

	try {
		const edwards = montgomeryToEdwardsPublic(publicKey)

		const key = createPublicKey({
			key: Buffer.concat([ED25519_SPKI_PREFIX, edwards]),
			format: 'der',
			type: 'spki',
		})

		return nodeVerify(null, message, key, signature)
	} catch {
		return false
	}
}
