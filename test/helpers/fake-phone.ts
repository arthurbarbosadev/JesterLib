import type { BinaryNode } from '../../src/binary/node.ts'
import { Curve, hmacSha256, xeddsaSign, xeddsaVerify, type KeyPair } from '../../src/crypto/index.ts'
import {
	ADVDeviceIdentity,
	ADVSignedDeviceIdentity,
	ADVSignedDeviceIdentityHMAC,
} from '../../src/proto/wa.ts'

/**
 * The phone that scans the QR.
 *
 * It does exactly what the handset does during `<pair-success>`: signs the new
 * device's identity with the account key, then checks the counter-signature the
 * client sends back. Testing against this exercises all three pairing checks for
 * real, including the [6,0] / [6,1] prefixes — getting one of those wrong goes
 * unnoticed in any test that does not reproduce the other side.
 */

const ACCOUNT_SIGNATURE_PREFIX = Buffer.from([6, 0])
const DEVICE_SIGNATURE_PREFIX = Buffer.from([6, 1])

export type FakePhone = {
	accountKey: KeyPair
	jid: string
	/** Builds the `<device-identity>` content for a `<pair-success>`. */
	buildPairSuccess(opts: {
		stanzaId: string
		/** The client's identity key, read from the QR. */
		clientIdentityPublic: Buffer
		/** The client's advSecretKey, read from the QR (base64). */
		advSecretKey: string
		keyIndex?: number
	}): BinaryNode
	/** Validates the `<pair-device-sign>` returned by the client. */
	verifyDeviceSignature(reply: BinaryNode, clientIdentityPublic: Buffer): boolean
	/** The `deviceDetails` used in the last call — for fine-grained assertions. */
	lastDeviceDetails(): Buffer | undefined
}

export function makeFakePhone(jid = '5511987654321:12@s.whatsapp.net'): FakePhone {
	const accountKey = Curve.generateKeyPair()
	let deviceDetails: Buffer | undefined

	return {
		accountKey,
		jid,
		lastDeviceDetails: () => deviceDetails,

		buildPairSuccess({ stanzaId, clientIdentityPublic, advSecretKey, keyIndex = 0 }): BinaryNode {
			deviceDetails = ADVDeviceIdentity.encode({
				rawId: 42,
				timestamp: BigInt(Math.floor(Date.now() / 1000)),
				keyIndex,
				accountType: 0,
				deviceType: 0,
			})

			const accountSignature = xeddsaSign(
				accountKey.private,
				Buffer.concat([ACCOUNT_SIGNATURE_PREFIX, deviceDetails, clientIdentityPublic]),
			)

			// The outer layer (what the HMAC covers) is the serialized
			// ADVSignedDeviceIdentity — not the ADVDeviceIdentity nested inside it.
			const signedIdentity = ADVSignedDeviceIdentity.encode({
				details: deviceDetails,
				accountSignatureKey: accountKey.public,
				accountSignature,
			})

			const content = ADVSignedDeviceIdentityHMAC.encode({
				details: signedIdentity,
				hmac: hmacSha256(signedIdentity, Buffer.from(advSecretKey, 'base64')),
			})

			return {
				tag: 'iq',
				attrs: { id: stanzaId, type: 'set', from: 's.whatsapp.net' },
				content: [
					{
						tag: 'pair-success',
						attrs: {},
						content: [
							{ tag: 'device-identity', attrs: {}, content },
							{ tag: 'device', attrs: { jid, lid: '998877:12@lid' } },
							{ tag: 'platform', attrs: { name: 'android' } },
							{ tag: 'biz', attrs: { name: 'Arthur Store' } },
						],
					},
				],
			}
		},

		verifyDeviceSignature(reply, clientIdentityPublic) {
			const sign = Array.isArray(reply.content) ? reply.content[0] : undefined
			const identity = Array.isArray(sign?.content) ? sign.content[0] : undefined

			if (!identity || !Buffer.isBuffer(identity.content) || !deviceDetails) {
				return false
			}

			const account = ADVSignedDeviceIdentity.decode(identity.content)

			if (!account.deviceSignature) {
				return false
			}

			return xeddsaVerify(
				clientIdentityPublic,
				Buffer.concat([
					DEVICE_SIGNATURE_PREFIX,
					deviceDetails,
					clientIdentityPublic,
					accountKey.public,
				]),
				account.deviceSignature,
			)
		},
	}
}
