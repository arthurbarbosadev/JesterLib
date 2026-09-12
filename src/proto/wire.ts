/**
 * Minimal protobuf runtime (proto2/proto3 wire format).
 *
 * WhatsApp uses protobuf everywhere, but only a subset of the format: varint,
 * 64-bit, length-delimited and 32-bit. There are no `group` fields (deprecated)
 * and no need for reflection. That fits in ~200 lines and avoids pulling in a
 * codegen dependency just to read a few dozen messages.
 */

export const WireType = {
	VARINT: 0,
	FIXED64: 1,
	LENGTH_DELIMITED: 2,
	FIXED32: 5,
} as const

export class ProtoReader {
	private readonly buf: Buffer
	private pos: number
	private readonly end: number

	constructor(buf: Buffer, start = 0, end = buf.length) {
		this.buf = buf
		this.pos = start
		this.end = end
	}

	get eof(): boolean {
		return this.pos >= this.end
	}

	varint(): bigint {
		let result = 0n
		let shift = 0n

		for (;;) {
			if (this.pos >= this.end) {
				throw new Error('truncated varint')
			}

			const byte = this.buf[this.pos++]!
			result |= BigInt(byte & 0x7f) << shift

			if ((byte & 0x80) === 0) {
				return result
			}

			shift += 7n

			if (shift > 63n) {
				throw new Error('varint larger than 64 bits')
			}
		}
	}

	varintNumber(): number {
		return Number(this.varint())
	}

	fixed32(): number {
		const value = this.buf.readUInt32LE(this.pos)
		this.pos += 4

		return value
	}

	fixed64(): bigint {
		const value = this.buf.readBigUInt64LE(this.pos)
		this.pos += 8

		return value
	}

	float(): number {
		const value = this.buf.readFloatLE(this.pos)
		this.pos += 4

		return value
	}

	double(): number {
		const value = this.buf.readDoubleLE(this.pos)
		this.pos += 8

		return value
	}

	bytes(): Buffer {
		const length = this.varintNumber()

		if (this.pos + length > this.end) {
			throw new Error(`length-delimited field overruns the buffer (${length} bytes)`)
		}

		const out = this.buf.subarray(this.pos, this.pos + length)
		this.pos += length

		return out
	}

	/** Skips an unknown field while keeping the stream aligned. */
	skip(wireType: number): void {
		switch (wireType) {
			case WireType.VARINT:
				this.varint()
				break
			case WireType.FIXED64:
				this.pos += 8
				break
			case WireType.LENGTH_DELIMITED:
				this.bytes()
				break
			case WireType.FIXED32:
				this.pos += 4
				break
			default:
				throw new Error(`unknown wire type: ${wireType}`)
		}
	}

	/** Iterates (fieldNumber, wireType) until the end of the message. */
	*fields(): Generator<[number, number]> {
		while (!this.eof) {
			const tag = this.varintNumber()
			yield [tag >>> 3, tag & 0x07]
		}
	}
}

export class ProtoWriter {
	private chunks: Buffer[] = []

	private push(buf: Buffer): void {
		this.chunks.push(buf)
	}

	tag(fieldNumber: number, wireType: number): this {
		return this.varint((fieldNumber << 3) | wireType)
	}

	varint(value: number | bigint | boolean): this {
		let v = typeof value === 'boolean' ? BigInt(value ? 1 : 0) : BigInt(value)

		if (v < 0n) {
			// Negative integers are encoded as two's complement over 64 bits.
			v += 1n << 64n
		}

		const out: number[] = []

		do {
			let byte = Number(v & 0x7fn)
			v >>= 7n

			if (v > 0n) {
				byte |= 0x80
			}

			out.push(byte)
		} while (v > 0n)

		return this.push(Buffer.from(out)), this
	}

	fixed32(value: number): this {
		const buf = Buffer.alloc(4)
		buf.writeUInt32LE(value >>> 0)

		return this.push(buf), this
	}

	fixed64(value: number | bigint): this {
		const buf = Buffer.alloc(8)
		buf.writeBigUInt64LE(BigInt(value))

		return this.push(buf), this
	}

	float(value: number): this {
		const buf = Buffer.alloc(4)
		buf.writeFloatLE(value)

		return this.push(buf), this
	}

	double(value: number): this {
		const buf = Buffer.alloc(8)
		buf.writeDoubleLE(value)

		return this.push(buf), this
	}

	bytes(value: Buffer): this {
		this.varint(value.length)

		return this.push(value), this
	}

	string(value: string): this {
		return this.bytes(Buffer.from(value, 'utf-8'))
	}

	finish(): Buffer {
		return Buffer.concat(this.chunks)
	}
}

/** ZigZag encoding for the `sint32` / `sint64` types. */
export function zigzagEncode(value: number | bigint): bigint {
	const v = BigInt(value)

	return (v << 1n) ^ (v >> 63n)
}

export function zigzagDecode(value: bigint): bigint {
	return (value >> 1n) ^ -(value & 1n)
}
