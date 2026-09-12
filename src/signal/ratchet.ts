import { Curve, addKeyType, hkdf, hmacSha256, type KeyPair } from '../crypto/index.ts'

/**
 * Double Ratchet key derivation.
 *
 * Three ratchets turn at different rates:
 *
 *   root chain    turns once per DH exchange (each time the peer sends a new
 *                 ratchet key), producing a fresh chain key
 *   chain key     turns once per message, producing a message key
 *   message key   used exactly once, then thrown away
 *
 * The point of the design is that compromising one key does not unlock the
 * others: the chain key cannot be run backwards, and a new DH exchange heals
 * the session even if an old root key leaked.
 *
 * All the `info` strings below are part of the protocol. They are domain
 * separators — changing a byte changes every key derived from it, and the peer
 * silently fails to decrypt.
 */

/** Separator used when deriving the initial root and chain keys from X3DH. */
const INFO_TEXT = 'WhisperText'
/** Separator used when the root chain turns. */
const INFO_RATCHET = 'WhisperRatchet'
/** Separator used when a chain key becomes a message key. */
const INFO_MESSAGE_KEYS = 'WhisperMessageKeys'

/**
 * X3DH prefixes the concatenated DH outputs with 32 bytes of 0xFF.
 *
 * This is the "discontinuity" value: it exists so the master secret can never
 * be confused with one produced by an older protocol version that lacked it.
 */
const DISCONTINUITY = Buffer.alloc(32, 0xff)

/** Constants that separate the two things an HMAC over the chain key produces. */
const MESSAGE_KEY_SEED = Buffer.from([0x01])
const CHAIN_KEY_SEED = Buffer.from([0x02])

export type ChainKey = {
	key: Buffer
	index: number
}

export type MessageKeys = {
	cipherKey: Buffer
	macKey: Buffer
	iv: Buffer
	index: number
}

export type RootKeyResult = {
	rootKey: Buffer
	chainKey: Buffer
}

/**
 * Turns a chain key into the message key for the current index.
 *
 * The two HMACs use different seeds so the message key cannot be used to
 * recompute the chain key — that one-way step is what gives forward secrecy
 * between consecutive messages.
 */
export function deriveMessageKeys(chainKey: ChainKey): MessageKeys {
	const seed = hmacSha256(MESSAGE_KEY_SEED, chainKey.key)
	const derived = hkdf(seed, 80, { info: INFO_MESSAGE_KEYS })

	return {
		cipherKey: derived.subarray(0, 32),
		macKey: derived.subarray(32, 64),
		iv: derived.subarray(64, 80),
		index: chainKey.index,
	}
}

/** Advances a chain key by one message. */
export function nextChainKey(chainKey: ChainKey): ChainKey {
	return {
		key: hmacSha256(CHAIN_KEY_SEED, chainKey.key),
		index: chainKey.index + 1,
	}
}

/**
 * Turns the root chain: a fresh DH output plus the current root key produce the
 * next root key and the chain key for the new sending or receiving chain.
 */
export function deriveRootKey(rootKey: Buffer, dhOutput: Buffer): RootKeyResult {
	const derived = hkdf(dhOutput, 64, { salt: rootKey, info: INFO_RATCHET })

	return {
		rootKey: derived.subarray(0, 32),
		chainKey: derived.subarray(32, 64),
	}
}

/**
 * Derives the initial root and chain keys from an X3DH master secret.
 *
 * The salt is 32 zero bytes here, unlike the ratchet step which salts with the
 * current root key.
 */
export function deriveInitialKeys(masterSecret: Buffer): RootKeyResult {
	const derived = hkdf(masterSecret, 64, { salt: Buffer.alloc(32), info: INFO_TEXT })

	return {
		rootKey: derived.subarray(0, 32),
		chainKey: derived.subarray(32, 64),
	}
}

// ---------------------------------------------------------------------------
// X3DH
// ---------------------------------------------------------------------------

export type InitiatorSecretInput = {
	/** Our long-term identity. */
	identityKey: KeyPair
	/** The ephemeral key generated for this session. */
	baseKey: KeyPair
	theirIdentityPublic: Buffer
	theirSignedPreKeyPublic: Buffer
	/** Absent when the peer had no one-time pre-keys left on the server. */
	theirOneTimePreKeyPublic?: Buffer
}

export type ReceiverSecretInput = {
	identityKey: KeyPair
	signedPreKey: KeyPair
	theirIdentityPublic: Buffer
	theirBaseKeyPublic: Buffer
	oneTimePreKey?: KeyPair
}

/**
 * The initiator's X3DH master secret.
 *
 * The order of the three (or four) DH outputs is part of the protocol and is
 * mirrored by `calculateReceiverSecret`. Swapping two of them produces a valid
 * looking secret that simply never matches the peer's — the failure shows up as
 * "cannot decrypt", with nothing pointing at the cause.
 */
export function calculateInitiatorSecret(input: InitiatorSecretInput): Buffer {
	const parts = [
		DISCONTINUITY,
		// our identity x their signed pre-key: authenticates us to them
		Curve.sharedKey(input.identityKey.private, input.theirSignedPreKeyPublic),
		// our base key x their identity: authenticates them to us
		Curve.sharedKey(input.baseKey.private, input.theirIdentityPublic),
		// our base key x their signed pre-key: the forward-secret part
		Curve.sharedKey(input.baseKey.private, input.theirSignedPreKeyPublic),
	]

	if (input.theirOneTimePreKeyPublic) {
		parts.push(Curve.sharedKey(input.baseKey.private, input.theirOneTimePreKeyPublic))
	}

	return Buffer.concat(parts)
}

/** The receiver's side of the same computation, with the roles swapped. */
export function calculateReceiverSecret(input: ReceiverSecretInput): Buffer {
	const parts = [
		DISCONTINUITY,
		Curve.sharedKey(input.signedPreKey.private, input.theirIdentityPublic),
		Curve.sharedKey(input.identityKey.private, input.theirBaseKeyPublic),
		Curve.sharedKey(input.signedPreKey.private, input.theirBaseKeyPublic),
	]

	if (input.oneTimePreKey) {
		parts.push(Curve.sharedKey(input.oneTimePreKey.private, input.theirBaseKeyPublic))
	}

	return Buffer.concat(parts)
}

/** Public key in the form the Signal wire format uses: 33 bytes, 0x05-prefixed. */
export function signalPublicKey(key: Buffer): Buffer {
	return addKeyType(key)
}
