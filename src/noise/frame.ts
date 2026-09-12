/**
 * Framing do WhatsApp: cada mensagem no WebSocket é precedida por um tamanho
 * big-endian de 3 bytes (máximo ~16 MiB). Um único `message` do WebSocket pode
 * conter vários frames, ou metade de um — por isso a decodificação é streaming.
 */

const LENGTH_PREFIX_SIZE = 3
const MAX_FRAME_SIZE = (1 << 24) - 1

/**
 * O primeiro frame da conexão é precedido pelo intro. Com routing info, ele
 * ganha um cabeçalho 'ED' que diz ao edge para qual shard encaminhar.
 */
export function buildIntro(waHeader: Buffer, routingInfo?: Buffer): Buffer {
	if (!routingInfo?.length) {
		return waHeader
	}

	// 'E','D', versão (0), tipo (1), e 3 bytes de tamanho = 7
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
		throw new Error(`frame de ${payload.length} bytes excede o máximo de ${MAX_FRAME_SIZE}`)
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

/** Reassembla frames completos a partir de chunks arbitrários do socket. */
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

	/** Bytes recebidos que ainda não formam um frame completo. */
	get pending(): number {
		return this.buffered.length
	}

	reset(): void {
		this.buffered = Buffer.alloc(0)
	}
}
