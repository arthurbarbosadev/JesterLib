import { S_WHATSAPP_NET } from '../binary/constants.ts'
import {
	getBinaryNodeChild,
	getBinaryNodeChildren,
	type BinaryNode,
} from '../binary/node.ts'
import { addKeyType, hmacSha256, xeddsaSign, xeddsaVerify } from '../crypto/index.ts'
import {
	ADVDeviceIdentity,
	ADVEncryptionType,
	ADVSignedDeviceIdentity,
	ADVSignedDeviceIdentityHMAC,
} from '../proto/wa.ts'
import type { AuthenticationCreds, SignalIdentity } from './creds.ts'

/**
 * QR-code pairing.
 *
 * The flow has three acts:
 *
 *  1. The server sends `<pair-device>` with a list of `ref`s. Each ref becomes
 *     a QR code; they expire within seconds, hence the rotation.
 *  2. The phone scans the QR and returns, through the server, a `<pair-success>`
 *     carrying this device's identity signed by the account.
 *  3. The client validates that signature, counter-signs with its own identity
 *     and replies with `<pair-device-sign>`.
 *
 * After that the server drops the connection with `stream:error code="515"`
 * (restartRequired) — that is expected behaviour, not an error: just reconnect,
 * this time with the login payload.
 */

/** Prefixes that separate the domains of the two pairing signatures. */
const ACCOUNT_SIGNATURE_PREFIX = Buffer.from([6, 0])
const DEVICE_SIGNATURE_PREFIX = Buffer.from([6, 1])

export class PairingError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'PairingError'
	}
}

// ---------------------------------------------------------------------------
// Act 1 — the QR code
// ---------------------------------------------------------------------------

/**
 * Builds the QR string from a `ref`.
 *
 * The phone reads these four fields: the ref identifies the pairing session on
 * the server, and the three keys let it talk to this device.
 */
export function buildQrString(ref: string, creds: AuthenticationCreds): string {
	return [
		ref,
		creds.noiseKey.public.toString('base64'),
		creds.signedIdentityKey.public.toString('base64'),
		creds.advSecretKey,
	].join(',')
}

/** Extracts the refs from an `<iq><pair-device>` node, in the order to use them. */
export function extractPairingRefs(stanza: BinaryNode): string[] {
	const pairDevice = getBinaryNodeChild(stanza, 'pair-device')

	if (!pairDevice) {
		throw new PairingError('node has no <pair-device>')
	}

	return getBinaryNodeChildren(pairDevice, 'ref')
		.map(node =>
			Buffer.isBuffer(node.content) ? node.content.toString('utf-8') : (node.content as string | undefined),
		)
		.filter((ref): ref is string => typeof ref === 'string' && ref.length > 0)
}

/** Mandatory ACK for `<pair-device>`; without it the server does not continue. */
export function buildPairDeviceAck(stanzaId: string): BinaryNode {
	return { tag: 'iq', attrs: { to: S_WHATSAPP_NET, type: 'result', id: stanzaId } }
}

// ---------------------------------------------------------------------------
// Act 3 — validation and counter-signature
// ---------------------------------------------------------------------------

/**
 * Serializes the signed identity. The account signature key is omitted in the
 * reply to the server — it already has it, and sending it back invalidates the
 * pairing.
 */
export function encodeSignedDeviceIdentity(
	account: {
		details?: Buffer
		accountSignatureKey?: Buffer
		accountSignature?: Buffer
		deviceSignature?: Buffer
	},
	includeSignatureKey: boolean,
): Buffer {
	const payload = { ...account }

	if (!includeSignatureKey || !payload.accountSignatureKey?.length) {
		delete payload.accountSignatureKey
	}

	return ADVSignedDeviceIdentity.encode(payload)
}

export function createSignalIdentity(jid: string, accountSignatureKey: Buffer): SignalIdentity {
	return {
		identifier: { name: jid, deviceId: 0 },
		identifierKey: addKeyType(accountSignatureKey),
	}
}

export type PairingResult = {
	/** The reply to send back to the server. */
	reply: BinaryNode
	/** Fields to apply to the credentials and persist. */
	update: Partial<AuthenticationCreds>
}

/**
 * Validates `<pair-success>` and produces `<pair-device-sign>`.
 *
 * There are three checks, in this order — any failure aborts the pairing:
 *
 *  1. HMAC over the signed identity, keyed with `advSecretKey`. Proves the
 *     responder actually scanned the QR, since the secret was only there.
 *  2. Account signature over `[6,0] || deviceDetails || our identity`. Proves
 *     the account authorized THIS device and not another one.
 *  3. Our counter-signature over `[6,1] || deviceDetails || our identity ||
 *     account key`. Proves to the server that we accept.
 */
export function configureSuccessfulPairing(
	stanza: BinaryNode,
	creds: Pick<AuthenticationCreds, 'advSecretKey' | 'signedIdentityKey' | 'signalIdentities'>,
): PairingResult {
	const stanzaId = stanza.attrs.id

	if (!stanzaId) {
		throw new PairingError('<pair-success> has no id')
	}

	const pairSuccess = getBinaryNodeChild(stanza, 'pair-success')
	const deviceIdentityNode = getBinaryNodeChild(pairSuccess, 'device-identity')
	const deviceNode = getBinaryNodeChild(pairSuccess, 'device')
	const platformNode = getBinaryNodeChild(pairSuccess, 'platform')
	const bizNode = getBinaryNodeChild(pairSuccess, 'biz')

	if (!deviceIdentityNode || !deviceNode) {
		throw new PairingError('<pair-success> is missing <device-identity> or <device>')
	}

	if (!Buffer.isBuffer(deviceIdentityNode.content)) {
		throw new PairingError('<device-identity> has no binary content')
	}

	const jid = deviceNode.attrs.jid

	if (!jid) {
		throw new PairingError('<device> has no jid')
	}

	const hmacContainer = ADVSignedDeviceIdentityHMAC.decode(deviceIdentityNode.content)

	if (!hmacContainer.details || !hmacContainer.hmac) {
		throw new PairingError('incomplete ADVSignedDeviceIdentityHMAC')
	}

	// Hosted accounts use an extra prefix in the signatures. Without a real
	// sample to check against, refusing is more honest than guessing the bytes.
	if (hmacContainer.accountType === ADVEncryptionType.HOSTED) {
		throw new PairingError('hosted accounts (HOSTED) are not supported yet')
	}

	// (1) the HMAC proves the other side knew the advSecretKey from the QR
	const expectedHmac = hmacSha256(hmacContainer.details, Buffer.from(creds.advSecretKey, 'base64'))

	if (expectedHmac.length !== hmacContainer.hmac.length || !expectedHmac.equals(hmacContainer.hmac)) {
		throw new PairingError('identity HMAC mismatch — the scanned QR is not this device\'s')
	}

	const account = ADVSignedDeviceIdentity.decode(hmacContainer.details)
	const { details: deviceDetails, accountSignatureKey, accountSignature } = account

	if (!deviceDetails || !accountSignatureKey || !accountSignature) {
		throw new PairingError('incomplete ADVSignedDeviceIdentity')
	}

	const identityPublic = creds.signedIdentityKey.public

	// (2) the account signed THIS device
	const accountMessage = Buffer.concat([ACCOUNT_SIGNATURE_PREFIX, deviceDetails, identityPublic])

	if (!xeddsaVerify(accountSignatureKey, accountMessage, accountSignature)) {
		throw new PairingError('invalid account signature')
	}

	// (3) this device's counter-signature
	const deviceMessage = Buffer.concat([
		DEVICE_SIGNATURE_PREFIX,
		deviceDetails,
		identityPublic,
		accountSignatureKey,
	])

	const deviceSignature = xeddsaSign(creds.signedIdentityKey.private, deviceMessage)
	const signedAccount = { ...account, deviceSignature }

	const deviceIdentity = ADVDeviceIdentity.decode(deviceDetails)

	const reply: BinaryNode = {
		tag: 'iq',
		attrs: { to: S_WHATSAPP_NET, type: 'result', id: stanzaId },
		content: [
			{
				tag: 'pair-device-sign',
				attrs: {},
				content: [
					{
						tag: 'device-identity',
						attrs: { 'key-index': String(deviceIdentity.keyIndex ?? 0) },
						content: encodeSignedDeviceIdentity(signedAccount, false),
					},
				],
			},
		],
	}

	const update: Partial<AuthenticationCreds> = {
		account: encodeSignedDeviceIdentity(signedAccount, true),
		me: { id: jid, lid: deviceNode.attrs.lid, name: bizNode?.attrs.name },
		signalIdentities: [...(creds.signalIdentities ?? []), createSignalIdentity(jid, accountSignatureKey)],
		platform: platformNode?.attrs.name,
		registered: true,
	}

	return { reply, update }
}
