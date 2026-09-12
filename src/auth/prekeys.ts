import { S_WHATSAPP_NET } from '../binary/constants.ts'
import {
	getBinaryNodeChild,
	getBinaryNodeChildBuffer,
	getBinaryNodeChildren,
	type BinaryNode,
} from '../binary/node.ts'
import { Curve, addKeyType, stripKeyType, type KeyPair } from '../crypto/index.ts'
import type { PreKeyBundle } from '../signal/cipher.ts'
import type { AuthenticationCreds } from './creds.ts'

/**
 * One-time pre-keys.
 *
 * They exist so someone can start an encrypted conversation with a device that
 * is offline: the server hands out a pre-key on the device's behalf, and each
 * one is consumed exactly once. Run out and new sessions lose a DH — still
 * secure, but without the extra forward secrecy — so the stock has to be topped
 * up as the server hands them out.
 */

/** How many to upload at a time. */
export const PRE_KEYS_PER_UPLOAD = 30

/** Refill when the server reports fewer than this many left. */
export const MIN_PRE_KEY_COUNT = 5

export type PreKey = {
	keyId: number
	keyPair: KeyPair
}

export class PreKeyError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'PreKeyError'
	}
}

function encodeBigEndian(value: number, length = 4): Buffer {
	const out = Buffer.alloc(length)

	for (let i = length - 1; i >= 0; i--) {
		out[i] = value & 0xff
		value >>= 8
	}

	return out
}

function decodeBigEndian(buf: Buffer): number {
	let value = 0

	for (const byte of buf) {
		value = value * 256 + byte
	}

	return value
}

export function generatePreKeys(startId: number, count = PRE_KEYS_PER_UPLOAD): PreKey[] {
	return Array.from({ length: count }, (_, i) => ({
		keyId: startId + i,
		keyPair: Curve.generateKeyPair(),
	}))
}

/**
 * Builds the `<iq xmlns="encrypt">` that publishes our keys.
 *
 * Key ids are 3 bytes, not 4 — the extra byte the registration id gets is not a
 * typo. The signed pre-key goes up with its signature so peers can verify the
 * bundle came from our identity rather than from the server.
 */
export function buildPreKeyUploadNode(
	creds: Pick<AuthenticationCreds, 'registrationId' | 'signedIdentityKey' | 'signedPreKey'>,
	preKeys: PreKey[],
): BinaryNode {
	return {
		tag: 'iq',
		attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: 'encrypt' },
		content: [
			{ tag: 'registration', attrs: {}, content: encodeBigEndian(creds.registrationId) },
			// 5 = DJB_TYPE, the Curve25519 key type
			{ tag: 'type', attrs: {}, content: Buffer.from([5]) },
			{ tag: 'identity', attrs: {}, content: creds.signedIdentityKey.public },
			{
				tag: 'list',
				attrs: {},
				content: preKeys.map(pre => ({
					tag: 'key',
					attrs: {},
					content: [
						{ tag: 'id', attrs: {}, content: encodeBigEndian(pre.keyId, 3) },
						{ tag: 'value', attrs: {}, content: pre.keyPair.public },
					],
				})),
			},
			{
				tag: 'skey',
				attrs: {},
				content: [
					{ tag: 'id', attrs: {}, content: encodeBigEndian(creds.signedPreKey.keyId, 3) },
					{ tag: 'value', attrs: {}, content: creds.signedPreKey.keyPair.public },
					{ tag: 'signature', attrs: {}, content: creds.signedPreKey.signature },
				],
			},
		],
	}
}

/** Asks the server how many of our one-time pre-keys are still unused. */
export function buildPreKeyCountNode(): BinaryNode {
	return {
		tag: 'iq',
		attrs: { to: S_WHATSAPP_NET, type: 'get', xmlns: 'encrypt' },
		content: [{ tag: 'count', attrs: {} }],
	}
}

export function parsePreKeyCount(result: BinaryNode): number {
	const count = getBinaryNodeChild(result, 'count')
	const value = count?.attrs.value

	if (value === undefined) {
		throw new PreKeyError('<count> node has no value')
	}

	return Number(value)
}

/** Requests pre-key bundles so we can open sessions with these devices. */
export function buildPreKeyFetchNode(jids: string[]): BinaryNode {
	return {
		tag: 'iq',
		attrs: { to: S_WHATSAPP_NET, type: 'get', xmlns: 'encrypt' },
		content: [
			{
				tag: 'key',
				attrs: {},
				content: jids.map(jid => ({ tag: 'user', attrs: { jid, reason: 'identity' } })),
			},
		],
	}
}

/**
 * Parses the bundles out of a fetch result, keyed by JID.
 *
 * A `<user>` without a `<key>` child means the server had no one-time pre-keys
 * left for that device. That is normal, not an error — the session is built
 * with one DH fewer.
 */
export function parsePreKeyBundles(result: BinaryNode): Map<string, PreKeyBundle> {
	const bundles = new Map<string, PreKeyBundle>()
	const list = getBinaryNodeChild(result, 'list')

	for (const user of getBinaryNodeChildren(list, 'user')) {
		const jid = user.attrs.jid

		if (!jid) {
			continue
		}

		const registration = getBinaryNodeChildBuffer(user, 'registration')
		const identity = getBinaryNodeChildBuffer(user, 'identity')
		const skey = getBinaryNodeChild(user, 'skey')

		const signedId = getBinaryNodeChildBuffer(skey, 'id')
		const signedValue = getBinaryNodeChildBuffer(skey, 'value')
		const signature = getBinaryNodeChildBuffer(skey, 'signature')

		if (!registration || !identity || !signedId || !signedValue || !signature) {
			throw new PreKeyError(`bundle for ${jid} is missing required fields`)
		}

		const oneTime = getBinaryNodeChild(user, 'key')
		const oneTimeId = getBinaryNodeChildBuffer(oneTime, 'id')
		const oneTimeValue = getBinaryNodeChildBuffer(oneTime, 'value')

		bundles.set(jid, {
			registrationId: decodeBigEndian(registration),
			identityKeyPublic: stripKeyType(identity),
			signedPreKeyId: decodeBigEndian(signedId),
			signedPreKeyPublic: stripKeyType(signedValue),
			signedPreKeySignature: signature,
			preKeyId: oneTimeId ? decodeBigEndian(oneTimeId) : undefined,
			preKeyPublic: oneTimeValue ? stripKeyType(oneTimeValue) : undefined,
		})
	}

	return bundles
}

/**
 * Verifies that a bundle's signed pre-key really was signed by the identity in
 * the same bundle.
 *
 * Skipping this is the difference between end-to-end encryption and
 * encryption-to-whoever-the-server-says. Anything that can answer for the
 * server could otherwise hand out its own keys and read everything.
 */
export function verifyPreKeyBundle(
	bundle: PreKeyBundle,
	verify: (publicKey: Buffer, message: Buffer, signature: Buffer) => boolean,
): boolean {
	return verify(
		bundle.identityKeyPublic,
		addKeyType(bundle.signedPreKeyPublic),
		bundle.signedPreKeySignature,
	)
}
