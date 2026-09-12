import type { BinaryNode } from '../../src/binary/node.ts'
import { Curve, hmacSha256, xeddsaSign, xeddsaVerify, type KeyPair } from '../../src/crypto/index.ts'
import {
	ADVDeviceIdentity,
	ADVSignedDeviceIdentity,
	ADVSignedDeviceIdentityHMAC,
} from '../../src/proto/wa.ts'

/**
 * O celular que lê o QR.
 *
 * Faz exatamente o que o aparelho faz no `<pair-success>`: assina a identidade
 * do dispositivo novo com a chave da conta, e depois confere a contra-assinatura
 * que o cliente devolve. Testar contra isto exercita as três verificações do
 * pareamento de verdade, inclusive os prefixos [6,0] / [6,1] — errar um deles
 * passa despercebido em qualquer teste que não reproduza o outro lado.
 */

const ACCOUNT_SIGNATURE_PREFIX = Buffer.from([6, 0])
const DEVICE_SIGNATURE_PREFIX = Buffer.from([6, 1])

export type FakePhone = {
	accountKey: KeyPair
	jid: string
	/** Constrói o conteúdo do `<device-identity>` para o `<pair-success>`. */
	buildPairSuccess(opts: {
		stanzaId: string
		/** Chave de identidade do cliente, lida do QR. */
		clientIdentityPublic: Buffer
		/** advSecretKey do cliente, lido do QR (base64). */
		advSecretKey: string
		keyIndex?: number
	}): BinaryNode
	/** Valida o `<pair-device-sign>` devolvido pelo cliente. */
	verifyDeviceSignature(reply: BinaryNode, clientIdentityPublic: Buffer): boolean
	/** `deviceDetails` usado na última chamada — para asserções finas. */
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

			// A camada externa (o que o HMAC cobre) é a ADVSignedDeviceIdentity
			// serializada — não o ADVDeviceIdentity de dentro dela.
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
							{ tag: 'biz', attrs: { name: 'Loja do Arthur' } },
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
