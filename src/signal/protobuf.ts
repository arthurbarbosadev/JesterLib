import { defineMessage, f, r } from '../proto/schema.ts'

/**
 * Signal Protocol wire messages.
 *
 * These are libsignal's own protobufs, not WAProto — a separate schema that
 * happens to travel inside WhatsApp's `<enc>` nodes. Keeping them in their own
 * module makes that boundary obvious.
 */

/**
 * The body of an `<enc type="msg">` node: one Double Ratchet message.
 *
 * `previousCounter` is what lets the receiver close off the previous chain and
 * compute any message keys it skipped, so out-of-order delivery still decrypts.
 */
export const SignalMessage = defineMessage('SignalMessage', {
	/** Sender's current ratchet public key, with the 0x05 type byte. */
	ratchetKey: f(1, 'bytes'),
	/** Index of this message within the current sending chain. */
	counter: f(2, 'uint32'),
	/** How many messages the previous chain held. */
	previousCounter: f(3, 'uint32'),
	ciphertext: f(4, 'bytes'),
})

/**
 * The body of an `<enc type="pkmsg">` node: the first message of a session.
 *
 * It carries everything the receiver needs to run X3DH from its side and derive
 * the same root key, then a full SignalMessage nested inside `message`.
 */
export const PreKeySignalMessage = defineMessage('PreKeySignalMessage', {
	/** Which one-time pre-key was consumed. Absent when none was available. */
	preKeyId: f(1, 'uint32'),
	/** Sender's ephemeral base key for this session, with the 0x05 byte. */
	baseKey: f(2, 'bytes'),
	/** Sender's long-term identity key, with the 0x05 byte. */
	identityKey: f(3, 'bytes'),
	/** A serialized SignalMessage. */
	message: f(4, 'bytes'),
	registrationId: f(5, 'uint32'),
	signedPreKeyId: f(6, 'uint32'),
})

/** Group messaging: the body of an `<enc type="skmsg">` node. */
export const SenderKeyMessage = defineMessage('SenderKeyMessage', {
	id: f(1, 'uint32'),
	iteration: f(2, 'uint32'),
	ciphertext: f(3, 'bytes'),
})

/** Handed to each group member so they can decrypt that sender's messages. */
export const SenderKeyDistributionMessage = defineMessage('SenderKeyDistributionMessage', {
	id: f(1, 'uint32'),
	iteration: f(2, 'uint32'),
	chainKey: f(3, 'bytes'),
	signingKey: f(4, 'bytes'),
})

// ---------------------------------------------------------------------------
// Persisted session state
// ---------------------------------------------------------------------------
//
// Not wire formats — this is how a session is written to the SignalKeyStore.
// Using protobuf here too means the stored blob is compact and versionable,
// and it round-trips through jsonb without a bespoke serializer.

export const Chain = defineMessage('Chain', {
	/** The other side's ratchet key this chain belongs to. */
	senderRatchetKey: f(1, 'bytes'),
	senderRatchetKeyPrivate: f(2, 'bytes'),
	chainKeyIndex: f(3, 'uint32'),
	chainKeyValue: f(4, 'bytes'),
	/** Keys for messages that arrived out of order, kept for late delivery. */
	messageKeys: r(5, () => MessageKey),
})

export const MessageKey = defineMessage('MessageKey', {
	index: f(1, 'uint32'),
	cipherKey: f(2, 'bytes'),
	macKey: f(3, 'bytes'),
	iv: f(4, 'bytes'),
})

export const PendingPreKey = defineMessage('PendingPreKey', {
	preKeyId: f(1, 'uint32'),
	signedPreKeyId: f(2, 'uint32'),
	baseKey: f(3, 'bytes'),
})

export const SessionStructure = defineMessage('SessionStructure', {
	sessionVersion: f(1, 'uint32'),
	localIdentityPublic: f(2, 'bytes'),
	remoteIdentityPublic: f(3, 'bytes'),

	rootKey: f(4, 'bytes'),
	previousCounter: f(5, 'uint32'),

	senderChain: f(6, Chain),
	receiverChains: r(7, Chain),

	/** Set until the peer replies, so retries keep sending a `pkmsg`. */
	pendingPreKey: f(8, PendingPreKey),

	remoteRegistrationId: f(9, 'uint32'),
	localRegistrationId: f(10, 'uint32'),
})

export const SessionRecordStructure = defineMessage('SessionRecordStructure', {
	currentSession: f(1, SessionStructure),
	/**
	 * Sessions the peer replaced but whose in-flight messages may still arrive.
	 * Dropping these means losing messages sent just before a re-key.
	 */
	previousSessions: r(2, SessionStructure),
})
