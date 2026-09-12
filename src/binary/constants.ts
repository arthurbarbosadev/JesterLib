/**
 * Tags do WABinary — o "XML binário" do WhatsApp.
 *
 * O stream é uma sequência de valores auto-descritos: cada um começa por um
 * byte de tag que diz como ler o resto. Valores de 1..len(SINGLE_BYTE_TOKENS)
 * são tokens do dicionário; os valores abaixo são os tipos estruturais.
 */
export const TAGS = {
	LIST_EMPTY: 0,
	STREAM_END: 2,
	DICTIONARY_0: 236,
	DICTIONARY_1: 237,
	DICTIONARY_2: 238,
	DICTIONARY_3: 239,
	AD_JID: 247,
	LIST_8: 248,
	LIST_16: 249,
	JID_PAIR: 250,
	HEX_8: 251,
	BINARY_8: 252,
	BINARY_20: 253,
	BINARY_32: 254,
	NIBBLE_8: 255,
} as const

/** Strings empacotadas (nibble/hex) não passam de 127 caracteres. */
export const PACKED_MAX_LENGTH = 127

/** Valor de nibble usado como preenchimento quando a string tem tamanho ímpar. */
export const PACKED_PAD = 15

export const NIBBLE_CHARS = '0123456789-.'
export const HEX_CHARS = '0123456789ABCDEF'

/** Domínios que aparecem como `server` em um JID. */
export const S_WHATSAPP_NET = 's.whatsapp.net'
export const GROUP_SERVER = 'g.us'
export const BROADCAST_SERVER = 'broadcast'
export const LID_SERVER = 'lid'
export const NEWSLETTER_SERVER = 'newsletter'
export const CALL_SERVER = 'call'
export const STATUS_BROADCAST = 'status@broadcast'

/**
 * `domainType` do AD_JID: identifica o servidor sem gastar bytes com a string.
 */
export const DOMAIN_TYPE = {
	WHATSAPP: 0,
	LID: 1,
} as const
