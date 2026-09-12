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
 * Pareamento por QR code.
 *
 * O fluxo tem três atos:
 *
 *  1. O servidor manda `<pair-device>` com uma lista de `ref`s. Cada ref vira um
 *     QR; eles expiram em segundos, por isso a rotação.
 *  2. O celular lê o QR e devolve, via servidor, um `<pair-success>` contendo a
 *     identidade deste dispositivo assinada pela conta.
 *  3. O cliente valida essa assinatura, contra-assina com a própria identidade e
 *     responde `<pair-device-sign>`.
 *
 * Depois disso o servidor derruba a conexão com `stream:error code="515"`
 * (restartRequired) — é o comportamento esperado, e não um erro: basta
 * reconectar, agora com o payload de login.
 */

/** Prefixos que separam os domínios das duas assinaturas do pareamento. */
const ACCOUNT_SIGNATURE_PREFIX = Buffer.from([6, 0])
const DEVICE_SIGNATURE_PREFIX = Buffer.from([6, 1])

export class PairingError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'PairingError'
	}
}

// ---------------------------------------------------------------------------
// Ato 1 — QR
// ---------------------------------------------------------------------------

/**
 * Monta a string do QR a partir de um `ref`.
 *
 * O celular lê estes quatro campos: o ref identifica a sessão de pareamento no
 * servidor, e as três chaves permitem que ele fale com este dispositivo.
 */
export function buildQrString(ref: string, creds: AuthenticationCreds): string {
	return [
		ref,
		creds.noiseKey.public.toString('base64'),
		creds.signedIdentityKey.public.toString('base64'),
		creds.advSecretKey,
	].join(',')
}

/** Extrai os refs de um nó `<iq><pair-device>`, na ordem em que devem ser usados. */
export function extractPairingRefs(stanza: BinaryNode): string[] {
	const pairDevice = getBinaryNodeChild(stanza, 'pair-device')

	if (!pairDevice) {
		throw new PairingError('nó sem <pair-device>')
	}

	return getBinaryNodeChildren(pairDevice, 'ref')
		.map(node =>
			Buffer.isBuffer(node.content) ? node.content.toString('utf-8') : (node.content as string | undefined),
		)
		.filter((ref): ref is string => typeof ref === 'string' && ref.length > 0)
}

/** ACK obrigatório do `<pair-device>`; sem ele o servidor não continua. */
export function buildPairDeviceAck(stanzaId: string): BinaryNode {
	return { tag: 'iq', attrs: { to: S_WHATSAPP_NET, type: 'result', id: stanzaId } }
}

// ---------------------------------------------------------------------------
// Ato 3 — validação e contra-assinatura
// ---------------------------------------------------------------------------

/**
 * Serializa a identidade assinada. A chave de assinatura da conta é omitida na
 * resposta ao servidor — ele já a tem, e reenviá-la invalida o pareamento.
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
	/** Resposta a enviar ao servidor. */
	reply: BinaryNode
	/** Campos a aplicar nas credenciais e persistir. */
	update: Partial<AuthenticationCreds>
}

/**
 * Valida o `<pair-success>` e produz o `<pair-device-sign>`.
 *
 * São três verificações, nesta ordem — cada uma falha fecha o pareamento:
 *
 *  1. HMAC sobre a identidade assinada, com `advSecretKey`. Prova que quem
 *     respondeu leu o QR, já que o segredo só estava lá.
 *  2. Assinatura da conta sobre `[6,0] || deviceDetails || nossa identidade`.
 *     Prova que a conta autorizou ESTE dispositivo, e não outro.
 *  3. Contra-assinatura nossa sobre `[6,1] || deviceDetails || nossa identidade
 *     || chave da conta`. Prova ao servidor que aceitamos.
 */
export function configureSuccessfulPairing(
	stanza: BinaryNode,
	creds: Pick<AuthenticationCreds, 'advSecretKey' | 'signedIdentityKey' | 'signalIdentities'>,
): PairingResult {
	const stanzaId = stanza.attrs.id

	if (!stanzaId) {
		throw new PairingError('<pair-success> sem id')
	}

	const pairSuccess = getBinaryNodeChild(stanza, 'pair-success')
	const deviceIdentityNode = getBinaryNodeChild(pairSuccess, 'device-identity')
	const deviceNode = getBinaryNodeChild(pairSuccess, 'device')
	const platformNode = getBinaryNodeChild(pairSuccess, 'platform')
	const bizNode = getBinaryNodeChild(pairSuccess, 'biz')

	if (!deviceIdentityNode || !deviceNode) {
		throw new PairingError('<pair-success> sem <device-identity> ou <device>')
	}

	if (!Buffer.isBuffer(deviceIdentityNode.content)) {
		throw new PairingError('<device-identity> sem conteúdo binário')
	}

	const jid = deviceNode.attrs.jid

	if (!jid) {
		throw new PairingError('<device> sem jid')
	}

	const hmacContainer = ADVSignedDeviceIdentityHMAC.decode(deviceIdentityNode.content)

	if (!hmacContainer.details || !hmacContainer.hmac) {
		throw new PairingError('ADVSignedDeviceIdentityHMAC incompleto')
	}

	// Contas hospedadas usam um prefixo extra nas assinaturas. Sem um caso real
	// para conferir, é mais honesto recusar do que adivinhar os bytes.
	if (hmacContainer.accountType === ADVEncryptionType.HOSTED) {
		throw new PairingError('contas hospedadas (HOSTED) ainda não são suportadas')
	}

	// (1) o HMAC prova que o outro lado conhecia o advSecretKey do QR
	const expectedHmac = hmacSha256(hmacContainer.details, Buffer.from(creds.advSecretKey, 'base64'))

	if (expectedHmac.length !== hmacContainer.hmac.length || !expectedHmac.equals(hmacContainer.hmac)) {
		throw new PairingError('HMAC da identidade não confere — o QR lido não é deste dispositivo')
	}

	const account = ADVSignedDeviceIdentity.decode(hmacContainer.details)
	const { details: deviceDetails, accountSignatureKey, accountSignature } = account

	if (!deviceDetails || !accountSignatureKey || !accountSignature) {
		throw new PairingError('ADVSignedDeviceIdentity incompleto')
	}

	const identityPublic = creds.signedIdentityKey.public

	// (2) a conta assinou ESTE dispositivo
	const accountMessage = Buffer.concat([ACCOUNT_SIGNATURE_PREFIX, deviceDetails, identityPublic])

	if (!xeddsaVerify(accountSignatureKey, accountMessage, accountSignature)) {
		throw new PairingError('assinatura da conta inválida')
	}

	// (3) contra-assinatura deste dispositivo
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
