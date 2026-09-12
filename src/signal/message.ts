import { addKeyType, hmacSha256 } from '../crypto/index.ts'
import { PreKeySignalMessage, SignalMessage } from './protobuf.ts'

/**
 * Signal message wire format.
 *
 * A SignalMessage on the wire is three concatenated pieces:
 *
 *   [1 byte version] [protobuf] [8 byte MAC]
 *
 * Two details that are easy to get wrong and impossible to debug from the
 * symptom:
 *
 *  * The MAC covers the identity keys of BOTH parties, in sender-then-receiver
 *    order, followed by the version byte and the protobuf. Leaving the identity
 *    keys out still produces a self-consistent implementation that talks only to
 *    itself.
 *  * The MAC is truncated to 8 bytes. Comparing all 32 fails against every real
 *    peer.
 *
 * A PreKeySignalMessage has no MAC of its own — the SignalMessage nested inside
 * it carries one.
 */

export const CIPHERTEXT_VERSION = 3
export const MAC_LENGTH = 8

/** High nibble is the current version, low nibble the minimum supported. */
const VERSION_BYTE = (CIPHERTEXT_VERSION << 4) | CIPHERTEXT_VERSION

export class SignalMessageError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'SignalMessageError'
	}
}

export type SignalMessageFields = {
	ratchetKey: Buffer
	counter: number
	previousCounter: number
	ciphertext: Buffer
}

export type PreKeySignalMessageFields = {
	registrationId: number
	preKeyId?: number
	signedPreKeyId: number
	baseKey: Buffer
	identityKey: Buffer
	message: Buffer
}

/**
 * The MAC input. Both identity keys are included in their 33-byte form, which
 * binds the ciphertext to the pair of identities — without that, a message
 * could be replayed into a different conversation.
 */
function macInput(
	senderIdentityPublic: Buffer,
	receiverIdentityPublic: Buffer,
	serialized: Buffer,
): Buffer {
	return Buffer.concat([
		addKeyType(senderIdentityPublic),
		addKeyType(receiverIdentityPublic),
		serialized,
	])
}

function computeMac(
	macKey: Buffer,
	senderIdentityPublic: Buffer,
	receiverIdentityPublic: Buffer,
	serialized: Buffer,
): Buffer {
	const full = hmacSha256(macInput(senderIdentityPublic, receiverIdentityPublic, serialized), macKey)

	return full.subarray(0, MAC_LENGTH)
}

export function serializeSignalMessage(
	fields: SignalMessageFields,
	macKey: Buffer,
	senderIdentityPublic: Buffer,
	receiverIdentityPublic: Buffer,
): Buffer {
	const body = SignalMessage.encode({
		ratchetKey: addKeyType(fields.ratchetKey),
		counter: fields.counter,
		previousCounter: fields.previousCounter,
		ciphertext: fields.ciphertext,
	})

	const versioned = Buffer.concat([Buffer.from([VERSION_BYTE]), body])
	const mac = computeMac(macKey, senderIdentityPublic, receiverIdentityPublic, versioned)

	return Buffer.concat([versioned, mac])
}

/**
 * Parses and authenticates a SignalMessage.
 *
 * The MAC is verified before the protobuf is trusted for anything, so a forged
 * message never reaches the decryption path.
 */
export function parseSignalMessage(
	serialized: Buffer,
	macKey: Buffer,
	senderIdentityPublic: Buffer,
	receiverIdentityPublic: Buffer,
): SignalMessageFields {
	if (serialized.length <= 1 + MAC_LENGTH) {
		throw new SignalMessageError('SignalMessage too short')
	}

	const version = serialized.readUInt8(0) >> 4

	if (version !== CIPHERTEXT_VERSION) {
		throw new SignalMessageError(`unsupported message version ${version}`)
	}

	const versioned = serialized.subarray(0, serialized.length - MAC_LENGTH)
	const receivedMac = serialized.subarray(serialized.length - MAC_LENGTH)
	const expectedMac = computeMac(macKey, senderIdentityPublic, receiverIdentityPublic, versioned)

	if (!expectedMac.equals(receivedMac)) {
		throw new SignalMessageError('bad MAC — message forged, corrupted, or wrong session')
	}

	const decoded = SignalMessage.decode(versioned.subarray(1))

	if (!decoded.ratchetKey || !decoded.ciphertext) {
		throw new SignalMessageError('SignalMessage missing ratchetKey or ciphertext')
	}

	return {
		ratchetKey: decoded.ratchetKey,
		counter: decoded.counter ?? 0,
		previousCounter: decoded.previousCounter ?? 0,
		ciphertext: decoded.ciphertext,
	}
}

/** Reads the counter and ratchet key without verifying the MAC. */
export function peekSignalMessage(serialized: Buffer): { counter: number; ratchetKey: Buffer } {
	if (serialized.length <= 1 + MAC_LENGTH) {
		throw new SignalMessageError('SignalMessage too short')
	}

	const decoded = SignalMessage.decode(serialized.subarray(1, serialized.length - MAC_LENGTH))

	if (!decoded.ratchetKey) {
		throw new SignalMessageError('SignalMessage missing ratchetKey')
	}

	return { counter: decoded.counter ?? 0, ratchetKey: decoded.ratchetKey }
}

export function serializePreKeySignalMessage(fields: PreKeySignalMessageFields): Buffer {
	const body = PreKeySignalMessage.encode({
		registrationId: fields.registrationId,
		preKeyId: fields.preKeyId,
		signedPreKeyId: fields.signedPreKeyId,
		baseKey: addKeyType(fields.baseKey),
		identityKey: addKeyType(fields.identityKey),
		message: fields.message,
	})

	return Buffer.concat([Buffer.from([VERSION_BYTE]), body])
}

export function parsePreKeySignalMessage(serialized: Buffer): PreKeySignalMessageFields {
	if (serialized.length < 2) {
		throw new SignalMessageError('PreKeySignalMessage too short')
	}

	const version = serialized.readUInt8(0) >> 4

	if (version !== CIPHERTEXT_VERSION) {
		throw new SignalMessageError(`unsupported prekey message version ${version}`)
	}

	const decoded = PreKeySignalMessage.decode(serialized.subarray(1))

	if (!decoded.baseKey || !decoded.identityKey || !decoded.message) {
		throw new SignalMessageError('PreKeySignalMessage is incomplete')
	}

	return {
		registrationId: decoded.registrationId ?? 0,
		preKeyId: decoded.preKeyId,
		signedPreKeyId: decoded.signedPreKeyId ?? 0,
		baseKey: decoded.baseKey,
		identityKey: decoded.identityKey,
		message: decoded.message,
	}
}
