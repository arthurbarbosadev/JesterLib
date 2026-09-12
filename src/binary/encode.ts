import {
	HEX_CHARS,
	NIBBLE_CHARS,
	PACKED_MAX_LENGTH,
	PACKED_PAD,
	TAGS,
} from './constants.ts'
import { jidDecode, serverToDomainType, type FullJid } from './jid.ts'
import type { BinaryNode } from './node.ts'
import { lookupDoubleToken, lookupSingleToken } from './tokens.ts'

const NIBBLE_RE = /^[0-9.-]+$/
const HEX_RE = /^[0-9A-F]+$/

class BinaryWriter {
	private chunks: number[] = []

	byte(value: number): void {
		this.chunks.push(value & 0xff)
	}

	bytes(buf: Buffer | Uint8Array): void {
		for (const b of buf) {
			this.chunks.push(b)
		}
	}

	/** Inteiro big-endian de `size` bytes. */
	int(value: number, size: number): void {
		for (let i = size - 1; i >= 0; i--) {
			this.byte((value >> (i * 8)) & 0xff)
		}
	}

	/** Inteiro de 20 bits em 3 bytes — usado só pelo tamanho BINARY_20. */
	int20(value: number): void {
		this.byte((value >> 16) & 0x0f)
		this.byte((value >> 8) & 0xff)
		this.byte(value & 0xff)
	}

	finish(): Buffer {
		return Buffer.from(this.chunks)
	}
}

function packNibble(char: string): number {
	if (char >= '0' && char <= '9') {
		return char.charCodeAt(0) - 48
	}

	if (char === '-') {
		return 10
	}

	if (char === '.') {
		return 11
	}

	if (char === '\0') {
		return PACKED_PAD
	}

	throw new Error(`caractere inválido para nibble: ${JSON.stringify(char)}`)
}

function packHex(char: string): number {
	if (char >= '0' && char <= '9') {
		return char.charCodeAt(0) - 48
	}

	if (char >= 'A' && char <= 'F') {
		return char.charCodeAt(0) - 55
	}

	if (char === '\0') {
		return PACKED_PAD
	}

	throw new Error(`caractere inválido para hex: ${JSON.stringify(char)}`)
}

export class BinaryNodeEncoder {
	private w = new BinaryWriter()

	private writeListStart(size: number): void {
		if (size === 0) {
			this.w.byte(TAGS.LIST_EMPTY)
		} else if (size < 256) {
			this.w.byte(TAGS.LIST_8)
			this.w.byte(size)
		} else {
			this.w.byte(TAGS.LIST_16)
			this.w.int(size, 2)
		}
	}

	private writeByteLength(length: number): void {
		if (length >= 4294967296) {
			throw new Error(`conteúdo grande demais para o WABinary: ${length} bytes`)
		}

		if (length >= 1 << 20) {
			this.w.byte(TAGS.BINARY_32)
			this.w.int(length, 4)
		} else if (length >= 256) {
			this.w.byte(TAGS.BINARY_20)
			this.w.int20(length)
		} else {
			this.w.byte(TAGS.BINARY_8)
			this.w.byte(length)
		}
	}

	/**
	 * Empacota dois caracteres por byte. Se o tamanho for ímpar, o bit alto do
	 * byte de tamanho sinaliza que o último nibble é preenchimento.
	 */
	private writePacked(value: string, kind: 'nibble' | 'hex'): void {
		this.w.byte(kind === 'nibble' ? TAGS.NIBBLE_8 : TAGS.HEX_8)

		const pack = kind === 'nibble' ? packNibble : packHex
		const odd = value.length % 2 !== 0
		let roundedLength = Math.ceil(value.length / 2)

		if (odd) {
			roundedLength |= 0x80
		}

		this.w.byte(roundedLength)

		const pairs = Math.floor(value.length / 2)

		for (let i = 0; i < pairs; i++) {
			this.w.byte((pack(value[2 * i]!) << 4) | pack(value[2 * i + 1]!))
		}

		if (odd) {
			this.w.byte((pack(value[value.length - 1]!) << 4) | PACKED_PAD)
		}
	}

	private writeJid(jid: FullJid): void {
		const domainType = serverToDomainType(jid.server)

		// AD_JID só existe para endereçar um device específico em s.whatsapp.net/lid.
		if (jid.device !== undefined && domainType !== undefined) {
			this.w.byte(TAGS.AD_JID)
			this.w.byte(domainType)
			this.w.byte(jid.device)
			this.writeString(jid.user)
			return
		}

		this.w.byte(TAGS.JID_PAIR)

		if (jid.user.length) {
			this.writeString(jid.user)
		} else {
			this.w.byte(TAGS.LIST_EMPTY)
		}

		this.writeString(jid.server)
	}

	private writeStringRaw(value: string): void {
		if (value.length <= PACKED_MAX_LENGTH && NIBBLE_RE.test(value)) {
			this.writePacked(value, 'nibble')
			return
		}

		if (value.length <= PACKED_MAX_LENGTH && HEX_RE.test(value)) {
			this.writePacked(value, 'hex')
			return
		}

		const bytes = Buffer.from(value, 'utf-8')
		this.writeByteLength(bytes.length)
		this.w.bytes(bytes)
	}

	writeString(value: string): void {
		const single = lookupSingleToken(value)

		if (single !== undefined) {
			this.w.byte(single)
			return
		}

		const double = lookupDoubleToken(value)

		if (double) {
			this.w.byte(TAGS.DICTIONARY_0 + double[0])
			this.w.byte(double[1])
			return
		}

		// Um JID cabe em muito menos bytes do que a sua forma textual.
		const jid = jidDecode(value)

		if (jid) {
			this.writeJid(jid)
			return
		}

		this.writeStringRaw(value)
	}

	private writeContent(content: BinaryNode['content']): void {
		if (typeof content === 'string') {
			this.writeString(content)
			return
		}

		if (Buffer.isBuffer(content) || content instanceof Uint8Array) {
			this.writeByteLength(content.length)
			this.w.bytes(content)
			return
		}

		if (Array.isArray(content)) {
			this.writeListStart(content.length)

			for (const child of content) {
				this.writeNode(child)
			}

			return
		}

		throw new Error(`tipo de conteúdo não suportado: ${typeof content}`)
	}

	writeNode(node: BinaryNode): void {
		const attrs = Object.entries(node.attrs).filter(([, v]) => v !== undefined && v !== null)
		const hasContent = node.content !== undefined

		// Um nó é uma lista: [tag, k1, v1, k2, v2, ..., content?]
		this.writeListStart(2 * attrs.length + 1 + (hasContent ? 1 : 0))
		this.writeString(node.tag)

		for (const [key, value] of attrs) {
			this.writeString(key)
			this.writeString(String(value))
		}

		if (hasContent) {
			this.writeContent(node.content)
		}
	}

	finish(): Buffer {
		return this.w.finish()
	}
}

/**
 * Serializa um nó. O byte 0 na frente é o flag de compressão do frame —
 * sempre 0 no envio (o cliente não comprime; o servidor pode comprimir).
 */
export function encodeBinaryNode(node: BinaryNode): Buffer {
	const encoder = new BinaryNodeEncoder()
	encoder.writeNode(node)

	return Buffer.concat([Buffer.from([0]), encoder.finish()])
}

/** Serializa sem o byte de flag — útil para testar o codec isoladamente. */
export function encodeBinaryNodeBody(node: BinaryNode): Buffer {
	const encoder = new BinaryNodeEncoder()
	encoder.writeNode(node)

	return encoder.finish()
}
