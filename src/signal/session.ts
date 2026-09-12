import { Curve, stripKeyType, type KeyPair } from '../crypto/index.ts'
import { SessionRecordStructure } from './protobuf.ts'
import {
	deriveMessageKeys,
	deriveRootKey,
	nextChainKey,
	type ChainKey,
	type MessageKeys,
} from './ratchet.ts'

/**
 * Double Ratchet session state.
 *
 * Everything here is plain data so the whole session can be written to the
 * SignalKeyStore and read back on another process. No key material lives in a
 * closure — that is what lets the worker be disposable.
 */

/**
 * Upper bound on message keys derived to catch up with a counter gap.
 *
 * A peer (or an attacker) can claim any counter it likes. Without a cap, a
 * message claiming counter 4 billion would have us derive that many keys and
 * hang the process. Real reordering never spans more than a handful.
 */
export const MAX_SKIPPED_MESSAGE_KEYS = 2000

/** How many skipped keys a chain keeps before the oldest are dropped. */
export const MAX_STORED_MESSAGE_KEYS = 2000

export type Chain = {
	/** The ratchet public key (32 bytes, no type byte) this chain belongs to. */
	ratchetKey: Buffer
	/** Present only on our sending chain. */
	ratchetKeyPrivate?: Buffer
	chainKey: ChainKey
	/** Keys for messages that never arrived, or arrived out of order. */
	messageKeys: Map<number, MessageKeys>
}

export type PendingPreKey = {
	preKeyId?: number
	signedPreKeyId: number
	baseKey: Buffer
}

export type SessionState = {
	version: number
	localIdentityPublic: Buffer
	remoteIdentityPublic: Buffer

	rootKey: Buffer
	/** Our current ratchet pair; its public key rides on every message we send. */
	ourRatchetKey: KeyPair
	/** How many messages the previous sending chain held. */
	previousCounter: number

	senderChain?: Chain
	receiverChains: Chain[]

	/** Set until the peer replies, so retries keep going out as a `pkmsg`. */
	pendingPreKey?: PendingPreKey

	localRegistrationId: number
	remoteRegistrationId: number
}

export type SessionRecord = {
	currentSession?: SessionState
	/**
	 * Sessions the peer replaced. Kept because messages sent just before a
	 * re-key are still in flight and would otherwise be lost.
	 */
	previousSessions: SessionState[]
}

/** How many stale sessions to keep around. */
const MAX_PREVIOUS_SESSIONS = 5

export class SessionError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'SessionError'
	}
}

export function createSessionRecord(): SessionRecord {
	return { previousSessions: [] }
}

/**
 * Promotes a new session, archiving the one it replaces.
 */
export function promoteSession(record: SessionRecord, session: SessionState): void {
	if (record.currentSession) {
		record.previousSessions.unshift(record.currentSession)
		record.previousSessions.length = Math.min(record.previousSessions.length, MAX_PREVIOUS_SESSIONS)
	}

	record.currentSession = session
}

export function findReceiverChain(session: SessionState, ratchetKey: Buffer): Chain | undefined {
	const key = stripKeyType(ratchetKey)

	return session.receiverChains.find(chain => chain.ratchetKey.equals(key))
}

/**
 * Turns the root chain because the peer sent a ratchet key we have not seen.
 *
 * Two derivations happen, in this order and no other: first the receiving chain
 * for their new key, then a brand new sending chain from a fresh key of ours.
 * Doing them in the other order feeds the wrong root key into the second, and
 * the peer's very next message fails to decrypt.
 */
export function ratchetOnReceive(session: SessionState, theirRatchetKey: Buffer): Chain {
	const theirKey = stripKeyType(theirRatchetKey)

	// Remember how far the outgoing chain got, so the peer can close it off.
	session.previousCounter = session.senderChain?.chainKey.index ?? 0

	// 1. receiving chain for the key they just used
	const receiving = deriveRootKey(
		session.rootKey,
		Curve.sharedKey(session.ourRatchetKey.private, theirKey),
	)

	const receiverChain: Chain = {
		ratchetKey: theirKey,
		chainKey: { key: receiving.chainKey, index: 0 },
		messageKeys: new Map(),
	}

	session.receiverChains.push(receiverChain)

	// Bound the number of chains kept; old ones can no longer receive anything.
	if (session.receiverChains.length > MAX_PREVIOUS_SESSIONS) {
		session.receiverChains.shift()
	}

	// 2. new sending chain, from a fresh ratchet key of ours
	const ourNewRatchet = Curve.generateKeyPair()
	const sending = deriveRootKey(receiving.rootKey, Curve.sharedKey(ourNewRatchet.private, theirKey))

	session.senderChain = {
		ratchetKey: ourNewRatchet.public,
		ratchetKeyPrivate: ourNewRatchet.private,
		chainKey: { key: sending.chainKey, index: 0 },
		messageKeys: new Map(),
	}

	session.ourRatchetKey = ourNewRatchet
	session.rootKey = sending.rootKey

	return receiverChain
}

/**
 * Produces the message keys for `counter` on a receiving chain, deriving and
 * storing keys for anything skipped along the way.
 */
export function messageKeysForCounter(chain: Chain, counter: number): MessageKeys {
	const stored = chain.messageKeys.get(counter)

	if (stored) {
		// Each key is used exactly once; keeping it would allow a replay.
		chain.messageKeys.delete(counter)
		return stored
	}

	if (counter < chain.chainKey.index) {
		throw new SessionError(
			`message key for counter ${counter} is gone (chain is at ${chain.chainKey.index}) — duplicate or too old`,
		)
	}

	const gap = counter - chain.chainKey.index

	if (gap > MAX_SKIPPED_MESSAGE_KEYS) {
		throw new SessionError(`counter gap of ${gap} exceeds the limit of ${MAX_SKIPPED_MESSAGE_KEYS}`)
	}

	// Walk the chain forward, banking the keys we pass so late messages still
	// decrypt.
	while (chain.chainKey.index < counter) {
		chain.messageKeys.set(chain.chainKey.index, deriveMessageKeys(chain.chainKey))
		chain.chainKey = nextChainKey(chain.chainKey)
	}

	const keys = deriveMessageKeys(chain.chainKey)
	chain.chainKey = nextChainKey(chain.chainKey)

	pruneMessageKeys(chain)

	return keys
}

function pruneMessageKeys(chain: Chain): void {
	if (chain.messageKeys.size <= MAX_STORED_MESSAGE_KEYS) {
		return
	}

	// Map preserves insertion order, and we insert in ascending counter order,
	// so the oldest keys come first.
	const excess = chain.messageKeys.size - MAX_STORED_MESSAGE_KEYS

	for (const key of [...chain.messageKeys.keys()].slice(0, excess)) {
		chain.messageKeys.delete(key)
	}
}

/** Advances our sending chain and returns the keys for the message. */
export function nextSenderMessageKeys(session: SessionState): MessageKeys {
	if (!session.senderChain) {
		throw new SessionError('session has no sending chain')
	}

	const keys = deriveMessageKeys(session.senderChain.chainKey)
	session.senderChain.chainKey = nextChainKey(session.senderChain.chainKey)

	return keys
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

function serializeChain(chain: Chain) {
	return {
		senderRatchetKey: chain.ratchetKey,
		senderRatchetKeyPrivate: chain.ratchetKeyPrivate,
		chainKeyIndex: chain.chainKey.index,
		chainKeyValue: chain.chainKey.key,
		messageKeys: [...chain.messageKeys.values()].map(mk => ({
			index: mk.index,
			cipherKey: mk.cipherKey,
			macKey: mk.macKey,
			iv: mk.iv,
		})),
	}
}

function deserializeChain(raw: ReturnType<typeof serializeChain>): Chain {
	const messageKeys = new Map<number, MessageKeys>()

	for (const mk of raw.messageKeys ?? []) {
		if (mk.cipherKey && mk.macKey && mk.iv) {
			messageKeys.set(mk.index ?? 0, {
				index: mk.index ?? 0,
				cipherKey: mk.cipherKey,
				macKey: mk.macKey,
				iv: mk.iv,
			})
		}
	}

	return {
		ratchetKey: raw.senderRatchetKey!,
		ratchetKeyPrivate: raw.senderRatchetKeyPrivate,
		chainKey: { key: raw.chainKeyValue!, index: raw.chainKeyIndex ?? 0 },
		messageKeys,
	}
}

function serializeState(state: SessionState) {
	return {
		sessionVersion: state.version,
		localIdentityPublic: state.localIdentityPublic,
		remoteIdentityPublic: state.remoteIdentityPublic,
		rootKey: state.rootKey,
		previousCounter: state.previousCounter,
		// Our ratchet pair rides along inside the sender chain fields; when there
		// is no sending chain yet we still have to keep it, so it gets its own
		// synthetic chain entry.
		senderChain: state.senderChain
			? serializeChain(state.senderChain)
			: {
					senderRatchetKey: state.ourRatchetKey.public,
					senderRatchetKeyPrivate: state.ourRatchetKey.private,
					chainKeyIndex: 0,
					chainKeyValue: Buffer.alloc(0),
					messageKeys: [],
				},
		receiverChains: state.receiverChains.map(serializeChain),
		pendingPreKey: state.pendingPreKey
			? {
					preKeyId: state.pendingPreKey.preKeyId,
					signedPreKeyId: state.pendingPreKey.signedPreKeyId,
					baseKey: state.pendingPreKey.baseKey,
				}
			: undefined,
		localRegistrationId: state.localRegistrationId,
		remoteRegistrationId: state.remoteRegistrationId,
	}
}

function deserializeState(raw: ReturnType<typeof serializeState>): SessionState {
	const senderRaw = raw.senderChain!
	const hasSenderChain = (senderRaw.chainKeyValue?.length ?? 0) > 0

	return {
		version: raw.sessionVersion ?? 3,
		localIdentityPublic: raw.localIdentityPublic!,
		remoteIdentityPublic: raw.remoteIdentityPublic!,
		rootKey: raw.rootKey!,
		ourRatchetKey: {
			public: senderRaw.senderRatchetKey!,
			private: senderRaw.senderRatchetKeyPrivate!,
		},
		previousCounter: raw.previousCounter ?? 0,
		senderChain: hasSenderChain ? deserializeChain(senderRaw) : undefined,
		receiverChains: (raw.receiverChains ?? []).map(deserializeChain),
		pendingPreKey: raw.pendingPreKey?.baseKey
			? {
					preKeyId: raw.pendingPreKey.preKeyId,
					signedPreKeyId: raw.pendingPreKey.signedPreKeyId ?? 0,
					baseKey: raw.pendingPreKey.baseKey,
				}
			: undefined,
		localRegistrationId: raw.localRegistrationId ?? 0,
		remoteRegistrationId: raw.remoteRegistrationId ?? 0,
	}
}

export function serializeSessionRecord(record: SessionRecord): Buffer {
	return SessionRecordStructure.encode({
		currentSession: record.currentSession ? serializeState(record.currentSession) : undefined,
		previousSessions: record.previousSessions.map(serializeState),
	})
}

export function deserializeSessionRecord(buf: Buffer): SessionRecord {
	const raw = SessionRecordStructure.decode(buf)

	return {
		currentSession: raw.currentSession ? deserializeState(raw.currentSession as never) : undefined,
		previousSessions: (raw.previousSessions ?? []).map(s => deserializeState(s as never)),
	}
}
