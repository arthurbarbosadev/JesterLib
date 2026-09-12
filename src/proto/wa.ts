import { defineMessage, f, r, type Infer } from './schema.ts'

/**
 * Subconjunto do WAProto necessário para handshake, login e pareamento.
 *
 * Os números de campo vêm do bundle do WhatsApp Web e são a parte que NÃO pode
 * ser adivinhada: trocar um id quebra silenciosamente (o servidor apenas fecha
 * a conexão). Os nomes são livres — usamos os mesmos do bundle para facilitar o
 * diff contra implementações de referência.
 */

// ---------------------------------------------------------------------------
// Handshake Noise
// ---------------------------------------------------------------------------

export const ClientHello = defineMessage('ClientHello', {
	ephemeral: f(1, 'bytes'),
	static: f(2, 'bytes'),
	payload: f(3, 'bytes'),
})

export const ServerHello = defineMessage('ServerHello', {
	ephemeral: f(1, 'bytes'),
	static: f(2, 'bytes'),
	payload: f(3, 'bytes'),
})

export const ClientFinish = defineMessage('ClientFinish', {
	static: f(1, 'bytes'),
	payload: f(2, 'bytes'),
})

export const HandshakeMessage = defineMessage('HandshakeMessage', {
	clientHello: f(2, ClientHello),
	serverHello: f(3, ServerHello),
	clientFinish: f(4, ClientFinish),
})

// ---------------------------------------------------------------------------
// Certificado do servidor (validado ao final do handshake)
// ---------------------------------------------------------------------------

export const NoiseCertificateDetails = defineMessage('NoiseCertificate.Details', {
	serial: f(1, 'uint32'),
	issuerSerial: f(2, 'uint32'),
	key: f(3, 'bytes'),
	notBefore: f(4, 'uint64'),
	notAfter: f(5, 'uint64'),
})

export const NoiseCertificate = defineMessage('NoiseCertificate', {
	details: f(1, 'bytes'),
	signature: f(2, 'bytes'),
})

export const CertChain = defineMessage('CertChain', {
	leaf: f(1, NoiseCertificate),
	intermediate: f(2, NoiseCertificate),
})

// ---------------------------------------------------------------------------
// ClientPayload — enviado cifrado dentro do ClientFinish
// ---------------------------------------------------------------------------

export const AppVersion = defineMessage('AppVersion', {
	primary: f(1, 'uint32'),
	secondary: f(2, 'uint32'),
	tertiary: f(3, 'uint32'),
	quaternary: f(4, 'uint32'),
	quinary: f(5, 'uint32'),
})

export const UserAgent = defineMessage('UserAgent', {
	platform: f(1, 'enum'),
	appVersion: f(2, AppVersion),
	mcc: f(3, 'string'),
	mnc: f(4, 'string'),
	osVersion: f(5, 'string'),
	manufacturer: f(6, 'string'),
	device: f(7, 'string'),
	osBuildNumber: f(8, 'string'),
	phoneId: f(9, 'string'),
	releaseChannel: f(10, 'enum'),
	localeLanguageIso6391: f(11, 'string'),
	localeCountryIso31661Alpha2: f(12, 'string'),
	deviceBoard: f(13, 'string'),
	deviceExpId: f(14, 'string'),
	deviceType: f(15, 'enum'),
})

export const WebdPayload = defineMessage('WebdPayload', {
	usesParticipantInKey: f(1, 'bool'),
	supportsStarredMessages: f(2, 'bool'),
	supportsDocumentMessages: f(3, 'bool'),
	supportsUrlMessages: f(4, 'bool'),
	supportsMediaRetry: f(5, 'bool'),
	supportsE2EImage: f(6, 'bool'),
	supportsE2EVideo: f(7, 'bool'),
	supportsE2EAudio: f(8, 'bool'),
	supportsE2EDocument: f(9, 'bool'),
	documentTypes: f(10, 'string'),
	features: f(11, 'bytes'),
})

export const WebInfo = defineMessage('WebInfo', {
	refToken: f(1, 'string'),
	version: f(2, 'string'),
	webdPayload: f(3, WebdPayload),
	webSubPlatform: f(4, 'enum'),
})

export const DNSSource = defineMessage('DNSSource', {
	dnsMethod: f(15, 'enum'),
	appCached: f(16, 'bool'),
})

export const DevicePairingRegistrationData = defineMessage('DevicePairingRegistrationData', {
	eRegid: f(1, 'bytes'),
	eKeytype: f(2, 'bytes'),
	eIdent: f(3, 'bytes'),
	eSkeyId: f(4, 'bytes'),
	eSkeyVal: f(5, 'bytes'),
	eSkeySig: f(6, 'bytes'),
	buildHash: f(7, 'bytes'),
	deviceProps: f(8, 'bytes'),
})

export const ClientPayload = defineMessage('ClientPayload', {
	username: f(1, 'uint64'),
	passive: f(3, 'bool'),
	userAgent: f(5, UserAgent),
	webInfo: f(6, WebInfo),
	pushName: f(7, 'string'),
	sessionId: f(9, 'sfixed32'),
	shortConnect: f(10, 'bool'),
	connectType: f(12, 'enum'),
	connectReason: f(13, 'enum'),
	shards: r(14, 'int32'),
	dnsSource: f(15, DNSSource),
	connectAttemptCount: f(16, 'uint32'),
	device: f(18, 'uint32'),
	devicePairingData: f(19, DevicePairingRegistrationData),
	product: f(20, 'enum'),
	fbCat: f(21, 'bytes'),
	fbUserAgent: f(22, 'bytes'),
	oc: f(23, 'bool'),
	lc: f(24, 'int32'),
	iosAppExtension: f(30, 'enum'),
	fbAppId: f(31, 'uint64'),
	fbDeviceId: f(32, 'bytes'),
	pull: f(33, 'bool'),
	paddingBytes: f(34, 'bytes'),
	yearClass: f(36, 'int32'),
	memClass: f(37, 'int32'),
})

// ---------------------------------------------------------------------------
// DeviceProps — serializado e embutido em devicePairingData.deviceProps
// ---------------------------------------------------------------------------

export const HistorySyncConfig = defineMessage('DeviceProps.HistorySyncConfig', {
	fullSyncDaysLimit: f(1, 'uint32'),
	fullSyncSizeMbLimit: f(2, 'uint32'),
	storageQuotaMb: f(3, 'uint32'),
	inlineInitialPayloadInE2EeMsg: f(4, 'bool'),
	recentSyncDaysLimit: f(5, 'uint32'),
	supportCallLogHistory: f(6, 'bool'),
	supportBotUserAgentChatHistory: f(7, 'bool'),
	supportCagReactionsAndPolls: f(8, 'bool'),
})

export const DeviceProps = defineMessage('DeviceProps', {
	os: f(1, 'string'),
	version: f(2, AppVersion),
	platformType: f(3, 'enum'),
	requireFullSync: f(4, 'bool'),
	historySyncConfig: f(5, HistorySyncConfig),
})

// ---------------------------------------------------------------------------
// ADV — identidade do dispositivo companheiro (fluxo de pareamento)
// ---------------------------------------------------------------------------

export const ADVSignedDeviceIdentityHMAC = defineMessage('ADVSignedDeviceIdentityHMAC', {
	details: f(1, 'bytes'),
	hmac: f(2, 'bytes'),
	accountType: f(3, 'enum'),
})

export const ADVSignedDeviceIdentity = defineMessage('ADVSignedDeviceIdentity', {
	details: f(1, 'bytes'),
	accountSignatureKey: f(2, 'bytes'),
	accountSignature: f(3, 'bytes'),
	deviceSignature: f(4, 'bytes'),
})

export const ADVDeviceIdentity = defineMessage('ADVDeviceIdentity', {
	rawId: f(1, 'uint32'),
	timestamp: f(2, 'uint64'),
	keyIndex: f(3, 'uint32'),
	accountType: f(4, 'enum'),
	deviceType: f(5, 'enum'),
})

export const ADVKeyIndexList = defineMessage('ADVKeyIndexList', {
	rawId: f(1, 'uint32'),
	timestamp: f(2, 'uint64'),
	currentIndex: f(3, 'uint32'),
	validIndexes: r(4, 'uint32'),
	accountType: f(5, 'enum'),
})

export const ADVSignedKeyIndexList = defineMessage('ADVSignedKeyIndexList', {
	details: f(1, 'bytes'),
	accountSignature: f(2, 'bytes'),
	accountSignatureKey: f(3, 'bytes'),
})

// ---------------------------------------------------------------------------
// Enums — objetos const, porque `enum` do TS não sobrevive ao type stripping
// ---------------------------------------------------------------------------

export const Platform = {
	ANDROID: 0,
	IOS: 1,
	WINDOWS: 2,
	BLACKBERRY: 3,
	BLACKBERRYX: 4,
	S40: 5,
	S60: 6,
	PYTHON_CLIENT: 7,
	TIZEN: 8,
	ENTERPRISE: 9,
	SMB_ANDROID: 10,
	KAIOS: 11,
	SMB_IOS: 12,
	WINDOWS10: 13,
	WEB: 14,
	MACOS: 15,
	IPAD: 16,
} as const

export const PlatformType = {
	UNKNOWN: 0,
	CHROME: 1,
	FIREFOX: 2,
	IE: 3,
	OPERA: 4,
	SAFARI: 5,
	EDGE: 6,
	DESKTOP: 7,
	IPAD: 8,
	ANDROID_TABLET: 9,
	OHANA: 10,
	ALOHA: 11,
	CATALINA: 12,
	TCL_TV: 13,
} as const

export const ConnectType = { CELLULAR_UNKNOWN: 0, WIFI_UNKNOWN: 1 } as const

export const ConnectReason = {
	PUSH: 0,
	USER_ACTIVATED: 1,
	SCHEDULED: 2,
	ERROR_RECONNECT: 3,
	NETWORK_SWITCH: 4,
	PING_RECONNECT: 5,
} as const

export const Product = { WHATSAPP: 0, MESSENGER: 1, INTEROP: 2 } as const

export const ReleaseChannel = { RELEASE: 0, BETA: 1, ALPHA: 2, DEBUG: 3 } as const

export const WebSubPlatform = {
	WEB_BROWSER: 0,
	APP_STORE: 1,
	WIN_STORE: 2,
	DARWIN: 3,
	WIN32: 4,
} as const

export const ADVEncryptionType = { E2EE: 0, HOSTED: 1 } as const

export type ClientPayloadType = Infer<typeof ClientPayload.fields>
export type ADVSignedDeviceIdentityType = Infer<typeof ADVSignedDeviceIdentity.fields>
