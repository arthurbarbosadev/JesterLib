import { randomBytes, randomUUID } from 'node:crypto'
import { Curve, addKeyType, xeddsaSign, type KeyPair } from '../crypto/index.ts'

/**
 * Credenciais de um dispositivo companheiro.
 *
 * Tudo aqui é serializável de propósito: é esse objeto (mais o SignalKeyStore)
 * que permite derrubar o processo e subir outro sem ler QR de novo. Por isso
 * nada de Buffer escondido em closure ou estado só em memória.
 */

export type SignedKeyPair = {
	keyPair: KeyPair
	/** Assinatura XEdDSA da pública (com o byte 0x05) pela identidade. */
	signature: Buffer
	keyId: number
}

export type SignalIdentity = {
	identifier: { name: string; deviceId: number }
	identifierKey: Buffer
}

export type Me = {
	id: string
	lid?: string
	name?: string
}

export type AuthenticationCreds = {
	/** Chave estática do Noise — identifica esta conexão, não a conta. */
	noiseKey: KeyPair
	/** Par efêmero do pareamento, presente no QR. */
	pairingEphemeralKeyPair: KeyPair
	/** Identidade Signal de longo prazo deste dispositivo. */
	signedIdentityKey: KeyPair
	signedPreKey: SignedKeyPair
	registrationId: number
	/** Segredo do pareamento (base64); valida o HMAC vindo do celular. */
	advSecretKey: string

	nextPreKeyId: number
	firstUnuploadedPreKeyId: number

	deviceId: string
	phoneId: string
	identityId: Buffer
	backupToken: Buffer

	/** false até o `pair-success`; a partir daí a conexão é de login. */
	registered: boolean

	me?: Me
	/** ADVSignedDeviceIdentity recebida no pareamento, já serializada. */
	account?: Buffer
	signalIdentities?: SignalIdentity[]
	platform?: string
	/** Shard do edge; reenviado no intro das próximas conexões. */
	routingInfo?: Buffer
	pairingCode?: string
	lastPropHash?: string
	accountSyncCounter: number
}

/** ID de registro do Signal: 14 bits. */
export function generateRegistrationId(): number {
	return Uint16Array.from(randomBytes(2))[0]! & 16383
}

/**
 * Gera uma prekey assinada. A assinatura cobre a pública COM o byte de tipo
 * 0x05 — assinar os 32 bytes crus produz algo que o servidor rejeita.
 */
export function makeSignedKeyPair(identityKey: KeyPair, keyId: number): SignedKeyPair {
	const preKey = Curve.generateKeyPair()
	const signature = xeddsaSign(identityKey.private, addKeyType(preKey.public))

	return { keyPair: preKey, signature, keyId }
}

export function initAuthCreds(): AuthenticationCreds {
	const identityKey = Curve.generateKeyPair()

	return {
		noiseKey: Curve.generateKeyPair(),
		pairingEphemeralKeyPair: Curve.generateKeyPair(),
		signedIdentityKey: identityKey,
		signedPreKey: makeSignedKeyPair(identityKey, 1),
		registrationId: generateRegistrationId(),
		advSecretKey: randomBytes(32).toString('base64'),

		nextPreKeyId: 1,
		firstUnuploadedPreKeyId: 1,

		deviceId: randomBytes(16).toString('base64url'),
		phoneId: randomUUID(),
		identityId: randomBytes(20),
		backupToken: randomBytes(20),

		registered: false,
		accountSyncCounter: 0,
	}
}

// ---------------------------------------------------------------------------
// Serialização
// ---------------------------------------------------------------------------

/**
 * Buffers não sobrevivem a JSON.stringify, então são marcados explicitamente.
 * Use com `JSON.stringify(creds, credsReplacer)` / `JSON.parse(s, credsReviver)`.
 *
 * O valor precisa ser lido de `this[key]`, e não do argumento `value`: o
 * JSON.stringify chama o `toJSON()` do Buffer ANTES do replacer, então `value`
 * já chega como `{ type: 'Buffer', data: [1,2,3...] }` — um array de números,
 * que funciona mas incha o JSON em ~4x. `this` ainda tem o Buffer original.
 */
export function credsReplacer(this: unknown, key: string, value: unknown): unknown {
	const original = (this as Record<string, unknown> | undefined)?.[key]

	if (Buffer.isBuffer(original)) {
		return { type: 'Buffer', data: original.toString('base64') }
	}

	return value
}

export function credsReviver(_key: string, value: unknown): unknown {
	if (
		value &&
		typeof value === 'object' &&
		(value as { type?: string }).type === 'Buffer' &&
		typeof (value as { data?: unknown }).data === 'string'
	) {
		return Buffer.from((value as { data: string }).data, 'base64')
	}

	return value
}

export function serializeCreds(creds: AuthenticationCreds): string {
	return JSON.stringify(creds, credsReplacer, 2)
}

export function deserializeCreds(json: string): AuthenticationCreds {
	return JSON.parse(json, credsReviver) as AuthenticationCreds
}
