import {
	Curve,
	aesDecryptCBC,
	aesEncryptCBC,
	stripKeyType,
	type KeyPair,
} from '../crypto/index.ts'
import {
	parsePreKeySignalMessage,
	parseSignalMessage,
	peekSignalMessage,
	serializePreKeySignalMessage,
	serializeSignalMessage,
} from './message.ts'
import {
	calculateInitiatorSecret,
	calculateReceiverSecret,
	deriveInitialKeys,
	deriveRootKey,
} from './ratchet.ts'
import {
	SessionError,
	createSessionRecord,
	findReceiverChain,
	messageKeysForCounter,
	nextSenderMessageKeys,
	promoteSession,
	ratchetOnReceive,
	type SessionRecord,
	type SessionState,
} from './session.ts'

/**
 * Session establishment and message encryption.
 *
 * The asymmetry between the two sides is worth understanding, because it is not
 * arbitrary:
 *
 *  * The initiator turns the root chain immediately at setup, using a fresh
 *    ratchet key against the peer's signed pre-key. So it has a sending chain
 *    before it has ever heard from the peer.
 *  * The receiver's signed pre-key IS its first ratchet key. It starts with no
 *    sending chain at all; the chain appears when it processes the first
 *    message and ratchets in response.
 *
 * Both arrive at the same root key. The test drives both sides to prove it.
 */

export const SESSION_VERSION = 3

export type PreKeyBundle = {
	registrationId: number
	identityKeyPublic: Buffer
	signedPreKeyId: number
	signedPreKeyPublic: Buffer
	signedPreKeySignature: Buffer
	/** Absent when the server has no one-time pre-keys left for this device. */
	preKeyId?: number
	preKeyPublic?: Buffer
}

export type LocalIdentity = {
	identityKey: KeyPair
	registrationId: number
}

export type EncryptedMessage = {
	/** `pkmsg` until the peer replies, `msg` afterwards. */
	type: 'pkmsg' | 'msg'
	ciphertext: Buffer
}

/**
 * Builds a session as the initiator, from a pre-key bundle fetched for the peer.
 *
 * The caller is responsible for having verified `signedPreKeySignature` against
 * the bundle's identity key before getting here — an unverified bundle means
 * anyone who can answer for the server can become a man in the middle.
 */
export function createOutgoingSession(
	local: LocalIdentity,
	bundle: PreKeyBundle,
	record: SessionRecord = createSessionRecord(),
): SessionRecord {
	const baseKey = Curve.generateKeyPair()
	const theirIdentity = stripKeyType(bundle.identityKeyPublic)
	const theirSignedPreKey = stripKeyType(bundle.signedPreKeyPublic)

	const masterSecret = calculateInitiatorSecret({
		identityKey: local.identityKey,
		baseKey,
		theirIdentityPublic: theirIdentity,
		theirSignedPreKeyPublic: theirSignedPreKey,
		theirOneTimePreKeyPublic: bundle.preKeyPublic ? stripKeyType(bundle.preKeyPublic) : undefined,
	})

	const initial = deriveInitialKeys(masterSecret)

	// The initiator turns the root chain right away, so it can send before ever
	// hearing back. Its first ratchet key goes out on the message.
	const ourRatchet = Curve.generateKeyPair()
	const sending = deriveRootKey(
		initial.rootKey,
		Curve.sharedKey(ourRatchet.private, theirSignedPreKey),
	)

	const session: SessionState = {
		version: SESSION_VERSION,
		localIdentityPublic: local.identityKey.public,
		remoteIdentityPublic: theirIdentity,
		rootKey: sending.rootKey,
		ourRatchetKey: ourRatchet,
		previousCounter: 0,
		senderChain: {
			ratchetKey: ourRatchet.public,
			ratchetKeyPrivate: ourRatchet.private,
			chainKey: { key: sending.chainKey, index: 0 },
			messageKeys: new Map(),
		},
		receiverChains: [],
		pendingPreKey: {
			preKeyId: bundle.preKeyId,
			signedPreKeyId: bundle.signedPreKeyId,
			baseKey: baseKey.public,
		},
		localRegistrationId: local.registrationId,
		remoteRegistrationId: bundle.registrationId,
	}

	promoteSession(record, session)

	return record
}

export type IncomingPreKeyContext = {
	local: LocalIdentity
	/** The signed pre-key the sender addressed. Doubles as our first ratchet key. */
	signedPreKey: KeyPair
	/** The one-time pre-key consumed, if the sender used one. */
	preKey?: KeyPair
}

/**
 * Builds a session as the receiver, from an incoming `pkmsg`.
 *
 * No root chain turn happens here: the receiver's signed pre-key is already its
 * ratchet key, and the turn happens when the nested SignalMessage is processed
 * and its unfamiliar ratchet key shows up.
 */
export function createIncomingSession(
	ctx: IncomingPreKeyContext,
	theirIdentityPublic: Buffer,
	theirBaseKeyPublic: Buffer,
	remoteRegistrationId: number,
): SessionState {
	const theirIdentity = stripKeyType(theirIdentityPublic)
	const theirBaseKey = stripKeyType(theirBaseKeyPublic)

	const masterSecret = calculateReceiverSecret({
		identityKey: ctx.local.identityKey,
		signedPreKey: ctx.signedPreKey,
		theirIdentityPublic: theirIdentity,
		theirBaseKeyPublic: theirBaseKey,
		oneTimePreKey: ctx.preKey,
	})

	const initial = deriveInitialKeys(masterSecret)

	return {
		version: SESSION_VERSION,
		localIdentityPublic: ctx.local.identityKey.public,
		remoteIdentityPublic: theirIdentity,
		rootKey: initial.rootKey,
		ourRatchetKey: ctx.signedPreKey,
		previousCounter: 0,
		senderChain: undefined,
		receiverChains: [],
		localRegistrationId: ctx.local.registrationId,
		remoteRegistrationId: remoteRegistrationId,
	}
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

export function encrypt(record: SessionRecord, plaintext: Buffer): EncryptedMessage {
	const session = record.currentSession

	if (!session) {
		throw new SessionError('no session to encrypt with')
	}

	if (!session.senderChain) {
		throw new SessionError('session has no sending chain yet — nothing received from the peer')
	}

	const keys = nextSenderMessageKeys(session)
	const ciphertext = aesEncryptCBC(plaintext, keys.cipherKey, keys.iv)

	const signalMessage = serializeSignalMessage(
		{
			ratchetKey: session.senderChain.ratchetKey,
			counter: keys.index,
			previousCounter: session.previousCounter,
			ciphertext,
		},
		keys.macKey,
		session.localIdentityPublic,
		session.remoteIdentityPublic,
	)

	// Until the peer answers, every message has to carry the bundle data: they
	// may not have processed the first one yet.
	if (session.pendingPreKey) {
		return {
			type: 'pkmsg',
			ciphertext: serializePreKeySignalMessage({
				registrationId: session.localRegistrationId,
				preKeyId: session.pendingPreKey.preKeyId,
				signedPreKeyId: session.pendingPreKey.signedPreKeyId,
				baseKey: session.pendingPreKey.baseKey,
				identityKey: session.localIdentityPublic,
				message: signalMessage,
			}),
		}
	}

	return { type: 'msg', ciphertext: signalMessage }
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/** Decrypts an `<enc type="msg">` body against an existing session. */
export function decryptSignalMessage(record: SessionRecord, serialized: Buffer): Buffer {
	const sessions = [record.currentSession, ...record.previousSessions].filter(
		(s): s is SessionState => !!s,
	)

	if (!sessions.length) {
		throw new SessionError('no session to decrypt with')
	}

	let lastError: unknown

	// A message may belong to a session the peer has since replaced. Trying the
	// archived ones is what keeps messages sent across a re-key from being lost.
	for (const session of sessions) {
		try {
			const plaintext = decryptWithSession(session, serialized)

			// Whichever session worked becomes current again.
			if (session !== record.currentSession) {
				promoteSession(record, session)
			}

			return plaintext
		} catch (err) {
			lastError = err
		}
	}

	throw lastError instanceof Error
		? lastError
		: new SessionError('could not decrypt with any known session')
}

function decryptWithSession(session: SessionState, serialized: Buffer): Buffer {
	const { ratchetKey, counter } = peekSignalMessage(serialized)

	let chain = findReceiverChain(session, ratchetKey)

	if (!chain) {
		// An unseen ratchet key means the peer moved the root chain forward.
		chain = ratchetOnReceive(session, ratchetKey)
	}

	const keys = messageKeysForCounter(chain, counter)

	// The MAC is verified inside parse, before the ciphertext is touched.
	const message = parseSignalMessage(
		serialized,
		keys.macKey,
		session.remoteIdentityPublic,
		session.localIdentityPublic,
	)

	const plaintext = aesDecryptCBC(message.ciphertext, keys.cipherKey, keys.iv)

	// The peer has clearly received from us, so stop advertising the bundle.
	session.pendingPreKey = undefined

	return plaintext
}

export type DecryptPreKeyResult = {
	plaintext: Buffer
	/** The one-time pre-key the sender consumed; delete it after this. */
	usedPreKeyId?: number
}

/**
 * Decrypts an `<enc type="pkmsg">` body, building the session if needed.
 *
 * `resolveKeys` is called only when a new session has to be built, so the caller
 * does not have to load pre-keys for every message.
 */
export function decryptPreKeyMessage(
	record: SessionRecord,
	serialized: Buffer,
	resolveKeys: (signedPreKeyId: number, preKeyId?: number) => IncomingPreKeyContext,
): DecryptPreKeyResult {
	const message = parsePreKeySignalMessage(serialized)
	const baseKey = stripKeyType(message.baseKey)

	// A retried pkmsg carries the same base key. Rebuilding the session would
	// throw away the ratchet state and lose everything since.
	const existing = [record.currentSession, ...record.previousSessions].find(
		session => session?.pendingPreKey?.baseKey.equals(baseKey),
	)

	if (!existing) {
		const ctx = resolveKeys(message.signedPreKeyId, message.preKeyId)

		promoteSession(
			record,
			createIncomingSession(ctx, message.identityKey, message.baseKey, message.registrationId),
		)
	}

	return {
		plaintext: decryptSignalMessage(record, message.message),
		usedPreKeyId: message.preKeyId,
	}
}
