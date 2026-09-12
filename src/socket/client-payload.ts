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
 * Several values here look cosmetic and are not. The server cross-checks
 * `buildHash` against the advertised version, and the phone refuses a pairing
 * whose `DeviceProps` it does not recognise — with a generic "cannot connect",
 * which is a miserable thing to debug.
 */

export type ClientPayloadConfig = {
	/** WhatsApp Web version. Too far behind and the server refuses the connection. */
	version: [number, number, number]
	/** [os label, browser, version] — the os label shows in the phone's device list. */
	browser: [string, string, string]
	countryCode?: string
	languageCode?: string
}

export const DEFAULT_BROWSER: [string, string, string] = ['Jester', 'Chrome', '120.0.0']

/**
 * The companion app version reported in DeviceProps.
 *
 * Fixed, and deliberately NOT derived from `browser`: this is the WhatsApp
 * companion client version the phone expects to see, not the browser's. Sending
 * the browser version here makes the phone reject the pairing.
 */
const COMPANION_VERSION = { primary: 10, secondary: 15, tertiary: 7 }

function encodeBigEndian(value: number, length = 4): Buffer {
	const out = Buffer.alloc(length)

	for (let i = length - 1; i >= 0; i--) {
		out[i] = value & 0xff
		value >>= 8
	}

	return out
}

function platformTypeFor(browser: string): number {
	const key = browser.toUpperCase() as keyof typeof PlatformType

	return PlatformType[key] ?? PlatformType.CHROME
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
			localeLanguageIso6391: config.languageCode ?? 'en',
			localeCountryIso31661Alpha2: config.countryCode ?? 'US',
			mcc: '000',
			mnc: '000',
		},
		webInfo: { webSubPlatform: WebSubPlatform.WEB_BROWSER },
	}
}

/** Serialized `DeviceProps`, embedded inside `devicePairingData`. */
export function buildDeviceProps(config: ClientPayloadConfig): Buffer {
	const [osLabel, browser] = config.browser

	return DeviceProps.encode({
		os: osLabel,
		version: COMPANION_VERSION,
		platformType: platformTypeFor(browser),
		requireFullSync: false,
		historySyncConfig: {
			storageQuotaMb: 10240,
			inlineInitialPayloadInE2EeMsg: true,
			supportCallLogHistory: false,
			supportBotUserAgentChatHistory: true,
			supportCagReactionsAndPolls: true,
		},
	})
}

/**
 * Registration payload — used while there is no account yet.
 * This is what makes the server start emitting QR code refs.
 */
export function buildRegisterClientPayload(
	creds: AuthenticationCreds,
	config: ClientPayloadConfig,
): Buffer {
	// MD5 of the WhatsApp Web version, dotted — NOT of the browser string. The
	// server checks it against the version in userAgent, and a mismatch fails
	// the pairing rather than the connection, so the QR scans and then the phone
	// says it cannot connect.
	const buildHash = createHash('md5').update(config.version.join('.')).digest()

	const payload: ClientPayloadType = {
		...baseClientPayload(config),
		passive: false,
		pull: false,
		devicePairingData: {
			buildHash,
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
		pull: true,
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
