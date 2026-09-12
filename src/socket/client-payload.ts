import { createHash } from 'node:crypto'
import type { AuthenticationCreds } from '../auth/creds.ts'
import { jidDecode } from '../binary/jid.ts'
import { addKeyType } from '../crypto/index.ts'
import {
	ClientPayload,
	ConnectReason,
	ConnectType,
	DeviceProps,
	Platform,
	PlatformType,
	ReleaseChannel,
	WebSubPlatform,
	type ClientPayloadType,
} from '../proto/wa.ts'

/**
 * O ClientPayload é a primeira coisa que o servidor lê sobre você — vai cifrado
 * dentro do ClientFinish. Existem duas formas:
 *
 * - registro: sem conta ainda, carrega `devicePairingData` e pede o QR;
 * - login: já pareado, identifica a conta por `username` + `device`.
 *
 * Campos "cosméticos" (versão de SO, fabricante) não são cosméticos: eles
 * compõem o que o celular mostra na lista de dispositivos conectados.
 */

export type ClientPayloadConfig = {
	/** Versão do WhatsApp Web. Defasada demais e o servidor recusa a conexão. */
	version: [number, number, number]
	/** [navegador, sistema, versão] — aparece na lista de aparelhos do celular. */
	browser: [string, string, string]
	countryCode?: string
	languageCode?: string
}

export const DEFAULT_BROWSER: [string, string, string] = ['Jester', 'Chrome', '120.0.0']

function encodeBigEndian(value: number, length = 4): Buffer {
	const out = Buffer.alloc(length)

	for (let i = length - 1; i >= 0; i--) {
		out[i] = value & 0xff
		value >>= 8
	}

	return out
}

function baseClientPayload(config: ClientPayloadConfig): ClientPayloadType {
	const [primary, secondary, tertiary] = config.version

	return {
		connectType: ConnectType.WIFI_UNKNOWN,
		connectReason: ConnectReason.USER_ACTIVATED,
		userAgent: {
			appVersion: { primary, secondary, tertiary },
			platform: Platform.WEB,
			releaseChannel: ReleaseChannel.RELEASE,
			osVersion: '0.1',
			device: 'Desktop',
			osBuildNumber: '0.1',
			localeLanguageIso6391: config.languageCode ?? 'pt',
			localeCountryIso31661Alpha2: config.countryCode ?? 'BR',
			mcc: '000',
			mnc: '000',
		},
		webInfo: { webSubPlatform: WebSubPlatform.WEB_BROWSER },
	}
}

/** `DeviceProps` serializado, embutido dentro de `devicePairingData`. */
export function buildDeviceProps(config: ClientPayloadConfig): Buffer {
	const [browserName, , browserVersion] = config.browser
	const [primary = 0, secondary = 0, tertiary = 0] = browserVersion.split('.').map(Number)

	return DeviceProps.encode({
		os: browserName,
		version: { primary, secondary, tertiary },
		platformType: PlatformType.CHROME,
		requireFullSync: false,
	})
}

/**
 * Payload de registro — usado enquanto `creds.registered` é false.
 * É ele que faz o servidor começar a emitir os refs do QR code.
 */
export function buildRegisterClientPayload(
	creds: AuthenticationCreds,
	config: ClientPayloadConfig,
): Buffer {
	const appVersionBuf = createHash('md5').update(config.browser.join(' ')).digest()

	const payload: ClientPayloadType = {
		...baseClientPayload(config),
		passive: false,
		devicePairingData: {
			buildHash: appVersionBuf,
			deviceProps: buildDeviceProps(config),
			eRegid: encodeBigEndian(creds.registrationId),
			// 5 = DJB_TYPE, o tipo de chave do Curve25519 no libsignal
			eKeytype: Buffer.from([5]),
			eIdent: creds.signedIdentityKey.public,
			eSkeyId: encodeBigEndian(creds.signedPreKey.keyId, 3),
			eSkeyVal: creds.signedPreKey.keyPair.public,
			eSkeySig: creds.signedPreKey.signature,
		},
	}

	return ClientPayload.encode(payload)
}

/** Payload de login — usado quando já existe `creds.me`. */
export function buildLoginClientPayload(
	creds: AuthenticationCreds,
	config: ClientPayloadConfig,
): Buffer {
	const decoded = jidDecode(creds.me?.id)

	if (!decoded?.user) {
		throw new Error('credenciais sem `me.id`: não dá para montar o payload de login')
	}

	const payload: ClientPayloadType = {
		...baseClientPayload(config),
		passive: true,
		username: BigInt(decoded.user),
		device: decoded.device ?? 0,
	}

	return ClientPayload.encode(payload)
}

export function buildClientPayload(
	creds: AuthenticationCreds,
	config: ClientPayloadConfig,
): Buffer {
	return creds.registered && creds.me?.id
		? buildLoginClientPayload(creds, config)
		: buildRegisterClientPayload(creds, config)
}

/** Chave pública no formato do libsignal (33 bytes, prefixada com 0x05). */
export { addKeyType as signalPublicKey }
