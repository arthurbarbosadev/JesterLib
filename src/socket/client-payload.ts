import { createHash } from 'node:crypto'
import type { AuthenticationCreds } from '../auth/creds.ts'
import { jidDecode } from '../binary/jid.ts'
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
 * The ClientPayload is the first thing the server learns about you — it travels
 * encrypted inside the ClientFinish. There are two shapes:
 *
 * - register: no account yet, carries `devicePairingData` and asks for the QR;
 * - login: already paired, identifies the account by `username` + `device`.
 *
 * The "cosmetic" fields (OS version, manufacturer) are not cosmetic: they make
 * up what the phone shows in its list of linked devices.
 */

export type ClientPayloadConfig = {
	/** WhatsApp Web version. Too far behind and the server refuses the connection. */
	version: [number, number, number]
	/** [browser, os, version] — shown in the phone's linked-devices list. */
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

/** Serialized `DeviceProps`, embedded inside `devicePairingData`. */
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
 * Registration payload — used while `creds.registered` is false.
 * This is what makes the server start emitting QR code refs.
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
			// 5 = DJB_TYPE, libsignal's Curve25519 key type
			eKeytype: Buffer.from([5]),
			eIdent: creds.signedIdentityKey.public,
			eSkeyId: encodeBigEndian(creds.signedPreKey.keyId, 3),
			eSkeyVal: creds.signedPreKey.keyPair.public,
			eSkeySig: creds.signedPreKey.signature,
		},
	}

	return ClientPayload.encode(payload)
}

/** Login payload — used once `creds.me` exists. */
export function buildLoginClientPayload(
	creds: AuthenticationCreds,
	config: ClientPayloadConfig,
): Buffer {
	const decoded = jidDecode(creds.me?.id)

	if (!decoded?.user) {
		throw new Error('credentials have no `me.id`: cannot build the login payload')
	}

	const payload: ClientPayloadType = {
		...baseClientPayload(config),
		passive: true,
		username: BigInt(decoded.user),
		device: decoded.device ?? 0,
	}

	return ClientPayload.encode(payload)
}

/**
 * The choice is driven by `me.id`, not `registered`: `me` is what the protocol
 * actually requires to log in, and credentials restored from an older format
 * (without the flag) would loop on the QR forever.
 */
export function buildClientPayload(
	creds: AuthenticationCreds,
	config: ClientPayloadConfig,
): Buffer {
	return creds.me?.id ? buildLoginClientPayload(creds, config) : buildRegisterClientPayload(creds, config)
}

