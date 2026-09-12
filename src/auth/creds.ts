import { randomBytes, randomUUID } from 'node:crypto'
import { Curve, addKeyType, xeddsaSign, type KeyPair } from '../crypto/index.ts'

/**
 * Credentials for a companion device.
 *
 * Everything here is serializable by design: this object (plus the
 * SignalKeyStore) is what lets you kill the process and start another one
 * without scanning a QR again. Hence no Buffers hidden in closures and no
 * memory-only state.
 */

export type SignedKeyPair = {
	keyPair: KeyPair
	/** XEdDSA signature over the public key (with the 0x05 byte) by the identity. */
	signature: Buffer
	keyId: number
}

export type SignalIdentity = {
	identifier: { name: string; deviceId: number }
	identifierKey: Buffer
}

export type Me = {
	id: string
	lid?: string
	name?: string
}

export type AuthenticationCreds = {
	/** Noise static key — identifies this connection, not the account. */
	noiseKey: KeyPair
	/** Ephemeral pairing key pair, present in the QR. */
	pairingEphemeralKeyPair: KeyPair
	/** This device's long-term Signal identity. */
	signedIdentityKey: KeyPair
	signedPreKey: SignedKeyPair
	registrationId: number
	/** Pairing secret (base64); validates the HMAC coming from the phone. */
	advSecretKey: string

	nextPreKeyId: number
	firstUnuploadedPreKeyId: number

	deviceId: string
	phoneId: string
	identityId: Buffer
	backupToken: Buffer

	/** false until `pair-success`; from then on connections are logins. */
	registered: boolean

	me?: Me
	/** ADVSignedDeviceIdentity received during pairing, already serialized. */
	account?: Buffer
	signalIdentities?: SignalIdentity[]
	platform?: string
	/** Edge shard; resent in the intro of subsequent connections. */
	routingInfo?: Buffer
	pairingCode?: string
	lastPropHash?: string
	accountSyncCounter: number
}

/** Signal registration id: 14 bits. */
export function generateRegistrationId(): number {
	return Uint16Array.from(randomBytes(2))[0]! & 16383
}

/**
 * Generates a signed pre-key. The signature covers the public key WITH the
 * 0x05 type byte — signing the raw 32 bytes produces something the server
 * rejects.
 */
export function makeSignedKeyPair(identityKey: KeyPair, keyId: number): SignedKeyPair {
	const preKey = Curve.generateKeyPair()
	const signature = xeddsaSign(identityKey.private, addKeyType(preKey.public))

	return { keyPair: preKey, signature, keyId }
}

export function initAuthCreds(): AuthenticationCreds {
	const identityKey = Curve.generateKeyPair()

	return {
		noiseKey: Curve.generateKeyPair(),
		pairingEphemeralKeyPair: Curve.generateKeyPair(),
		signedIdentityKey: identityKey,
		signedPreKey: makeSignedKeyPair(identityKey, 1),
		registrationId: generateRegistrationId(),
		advSecretKey: randomBytes(32).toString('base64'),

		nextPreKeyId: 1,
		firstUnuploadedPreKeyId: 1,

		deviceId: randomBytes(16).toString('base64url'),
		phoneId: randomUUID(),
		identityId: randomBytes(20),
		backupToken: randomBytes(20),

		registered: false,
		accountSyncCounter: 0,
	}
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/**
 * Buffers do not survive JSON.stringify, so they are tagged explicitly.
 * Use with `JSON.stringify(creds, credsReplacer)` / `JSON.parse(s, credsReviver)`.
 *
 * The value has to be read from `this[key]` rather than the `value` argument:
 * JSON.stringify calls the Buffer's `toJSON()` BEFORE the replacer runs, so
 * `value` already arrives as `{ type: 'Buffer', data: [1,2,3...] }` — an array
 * of numbers, which works but inflates the JSON roughly 4x. `this` still holds
 * the original Buffer.
 */
export function credsReplacer(this: unknown, key: string, value: unknown): unknown {
	const original = (this as Record<string, unknown> | undefined)?.[key]

	if (Buffer.isBuffer(original)) {
		return { type: 'Buffer', data: original.toString('base64') }
	}

	return value
}

export function credsReviver(_key: string, value: unknown): unknown {
	if (
		value &&
		typeof value === 'object' &&
		(value as { type?: string }).type === 'Buffer' &&
		typeof (value as { data?: unknown }).data === 'string'
	) {
		return Buffer.from((value as { data: string }).data, 'base64')
	}

	return value
}

export function serializeCreds(creds: AuthenticationCreds): string {
	return JSON.stringify(creds, credsReplacer, 2)
}

export function deserializeCreds(json: string): AuthenticationCreds {
	return JSON.parse(json, credsReviver) as AuthenticationCreds
}
