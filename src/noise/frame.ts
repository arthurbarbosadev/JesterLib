/**
 * WhatsApp framing: every message on the WebSocket is preceded by a 3-byte
 * big-endian length (max ~16 MiB). A single WebSocket `message` may carry
 * several frames, or half of one — which is why decoding is streaming.
 */

const LENGTH_PREFIX_SIZE = 3
const MAX_FRAME_SIZE = (1 << 24) - 1

/**
 * The first frame of the connection is preceded by the intro. With routing
 * info, it gains an 'ED' header telling the edge which shard to forward to.
 */
export function buildIntro(waHeader: Buffer, routingInfo?: Buffer): Buffer {
	if (!routingInfo?.length) {
		return waHeader
	}

	// 'E', 'D', version (0), type (1), and 3 length bytes = 7
	const routingHeader = Buffer.alloc(7)
	routingHeader.write('ED', 0, 'utf-8')
	routingHeader.writeUInt8(0, 2)
	routingHeader.writeUInt8(1, 3)
	routingHeader.writeUInt8(routingInfo.length >> 16, 4)
	routingHeader.writeUInt16BE(routingInfo.length & 0xffff, 5)

	return Buffer.concat([routingHeader, routingInfo, waHeader])
}

export function encodeFrame(payload: Buffer, intro?: Buffer): Buffer {
	if (payload.length > MAX_FRAME_SIZE) {
		throw new Error(`frame of ${payload.length} bytes exceeds the maximum of ${MAX_FRAME_SIZE}`)
	}

	const introSize = intro?.length ?? 0
	const frame = Buffer.alloc(introSize + LENGTH_PREFIX_SIZE + payload.length)

	if (intro?.length) {
		intro.copy(frame, 0)
	}

	frame.writeUInt8(payload.length >> 16, introSize)
	frame.writeUInt16BE(payload.length & 0xffff, introSize + 1)
	payload.copy(frame, introSize + LENGTH_PREFIX_SIZE)

	return frame
}

/** Reassembles complete frames out of arbitrary chunks from the socket. */
export class FrameDecoder {
	private buffered: Buffer = Buffer.alloc(0)

	push(chunk: Buffer): Buffer[] {
		this.buffered = this.buffered.length ? Buffer.concat([this.buffered, chunk]) : chunk

		const frames: Buffer[] = []

		while (this.buffered.length >= LENGTH_PREFIX_SIZE) {
			const size = (this.buffered.readUInt8(0) << 16) | this.buffered.readUInt16BE(1)

			if (this.buffered.length < size + LENGTH_PREFIX_SIZE) {
				break
			}

			frames.push(this.buffered.subarray(LENGTH_PREFIX_SIZE, size + LENGTH_PREFIX_SIZE))
			this.buffered = this.buffered.subarray(size + LENGTH_PREFIX_SIZE)
		}

		return frames
	}

	/** Bytes received that do not yet form a complete frame. */
	get pending(): number {
		return this.buffered.length
	}

	reset(): void {
		this.buffered = Buffer.alloc(0)
	}
}
