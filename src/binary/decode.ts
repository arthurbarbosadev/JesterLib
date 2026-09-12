import { inflateSync } from 'node:zlib'
import { PACKED_PAD, TAGS } from './constants.ts'
import { domainTypeToServer, jidEncode } from './jid.ts'
import type { BinaryNode } from './node.ts'
import { doubleTokenAt, singleTokenAt, singleTokenCount } from './tokens.ts'

/** Bit in the frame flag byte marking a zlib-compressed payload. */
const FLAG_COMPRESSED = 0x02

function unpackNibble(value: number): string {
	if (value < 10) {
		return String.fromCharCode(48 + value)
	}

	if (value === 10) {
		return '-'
	}

	if (value === 11) {
		return '.'
	}

	if (value === PACKED_PAD) {
		return '\0'
	}

	throw new Error(`invalid nibble: ${value}`)
}

function unpackHex(value: number): string {
	if (value < 10) {
		return String.fromCharCode(48 + value)
	}

	if (value < 16) {
		return String.fromCharCode(55 + value)
	}

	throw new Error(`invalid hex digit: ${value}`)
}

class BinaryReader {
	private readonly buf: Buffer
	private pos = 0

	constructor(buf: Buffer) {
		this.buf = buf
	}

	get remaining(): number {
		return this.buf.length - this.pos
	}

	byte(): number {
		if (this.pos >= this.buf.length) {
			throw new Error('unexpected end of buffer')
		}

		return this.buf[this.pos++]!
	}

	bytes(length: number): Buffer {
		if (this.pos + length > this.buf.length) {
			throw new Error(`reading ${length} bytes overruns the buffer`)
		}

		const out = this.buf.subarray(this.pos, this.pos + length)
		this.pos += length

		return out
	}

	int(size: number): number {
		let value = 0

		for (let i = 0; i < size; i++) {
			value = (value << 8) | this.byte()
		}

		return value >>> 0
	}

	int20(): number {
		return ((this.byte() & 0x0f) << 16) | (this.byte() << 8) | this.byte()
	}
}

function isListTag(tag: number): boolean {
	return tag === TAGS.LIST_EMPTY || tag === TAGS.LIST_8 || tag === TAGS.LIST_16
}

class BinaryNodeDecoder {
	private readonly r: BinaryReader

	constructor(buf: Buffer) {
		this.r = new BinaryReader(buf)
	}

	private readListSize(tag: number): number {
		switch (tag) {
			case TAGS.LIST_EMPTY:
				return 0
			case TAGS.LIST_8:
				return this.r.byte()
			case TAGS.LIST_16:
				return this.r.int(2)
			default:
				throw new Error(`invalid list tag: ${tag}`)
		}
	}

	private readPacked(tag: number): string {
		const startByte = this.r.byte()
		const unpack = tag === TAGS.NIBBLE_8 ? unpackNibble : unpackHex
		let value = ''

		for (let i = 0; i < (startByte & 0x7f); i++) {
			const byte = this.r.byte()
			value += unpack((byte & 0xf0) >> 4)
			value += unpack(byte & 0x0f)
		}

		// High bit set => the last nibble was padding.
		return startByte >> 7 !== 0 ? value.slice(0, -1) : value
	}

	readString(tag: number): string {
		if (tag >= 1 && tag < singleTokenCount()) {
			return singleTokenAt(tag)
		}

		switch (tag) {
			case TAGS.DICTIONARY_0:
			case TAGS.DICTIONARY_1:
			case TAGS.DICTIONARY_2:
			case TAGS.DICTIONARY_3:
				return doubleTokenAt(tag - TAGS.DICTIONARY_0, this.r.byte())

			case TAGS.LIST_EMPTY:
				return ''

			case TAGS.BINARY_8:
				return this.r.bytes(this.r.byte()).toString('utf-8')

			case TAGS.BINARY_20:
				return this.r.bytes(this.r.int20()).toString('utf-8')

			case TAGS.BINARY_32:
				return this.r.bytes(this.r.int(4)).toString('utf-8')

			case TAGS.JID_PAIR: {
				const user = this.readString(this.r.byte())
				const server = this.readString(this.r.byte())

				if (!server) {
					throw new Error('JID_PAIR without a server')
				}

				return jidEncode(user, server)
			}

			case TAGS.AD_JID: {
				const domainType = this.r.byte()
				const device = this.r.byte()
				const user = this.readString(this.r.byte())

				return jidEncode(user, domainTypeToServer(domainType), device)
			}

			case TAGS.HEX_8:
			case TAGS.NIBBLE_8:
				return this.readPacked(tag)

			default:
				throw new Error(`unknown tag while reading a string: ${tag}`)
		}
	}

	readNode(): BinaryNode {
		const listSize = this.readListSize(this.r.byte())
		const tag = this.readString(this.r.byte())

		if (!listSize || !tag) {
			throw new Error('invalid node: empty list or missing tag')
		}

		const attrs: Record<string, string> = {}
		const attrCount = (listSize - 1) >> 1

		for (let i = 0; i < attrCount; i++) {
			const key = this.readString(this.r.byte())
			attrs[key] = this.readString(this.r.byte())
		}

		// An even-sized list => the last item is the content.
		if (listSize % 2 !== 0) {
			return { tag, attrs }
		}

		const contentTag = this.r.byte()

		if (isListTag(contentTag)) {
			const size = this.readListSize(contentTag)
			const content: BinaryNode[] = []

			for (let i = 0; i < size; i++) {
				content.push(this.readNode())
			}

			return { tag, attrs, content }
		}

		switch (contentTag) {
			case TAGS.BINARY_8:
				return { tag, attrs, content: Buffer.from(this.r.bytes(this.r.byte())) }
			case TAGS.BINARY_20:
				return { tag, attrs, content: Buffer.from(this.r.bytes(this.r.int20())) }
			case TAGS.BINARY_32:
				return { tag, attrs, content: Buffer.from(this.r.bytes(this.r.int(4))) }
			default:
				return { tag, attrs, content: this.readString(contentTag) }
		}
	}
}

/**
 * Decodes an already-decrypted frame: the first byte is the compression flag,
 * the rest is the node (possibly zlib-compressed).
 */
export function decodeBinaryNode(frame: Buffer): BinaryNode {
	if (!frame.length) {
		throw new Error('empty frame')
	}

	const flags = frame.readUInt8(0)
	const body = flags & FLAG_COMPRESSED ? inflateSync(frame.subarray(1)) : frame.subarray(1)

	return new BinaryNodeDecoder(body).readNode()
}

/** Decodes without the flag byte — counterpart to `encodeBinaryNodeBody`. */
export function decodeBinaryNodeBody(body: Buffer): BinaryNode {
	return new BinaryNodeDecoder(body).readNode()
}
