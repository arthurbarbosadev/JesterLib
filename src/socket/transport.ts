import { EventEmitter } from 'node:events'
import WebSocket from 'ws'

/**
 * Transport layer, abstracted away from the WebSocket.
 *
 * This is not abstraction for its own sake: it lets the entire connection —
 * handshake, framing, node routing — be exercised against an in-process
 * simulated server, with no network. That makes testable the part that is
 * normally only debuggable in production.
 *
 * Events: `open`, `data` (Buffer), `close` (code, reason), `error` (Error).
 */
export interface Transport extends EventEmitter {
	send(data: Buffer): void
	close(): void
	readonly isOpen: boolean
}

export const DEFAULT_WS_URL = 'wss://web.whatsapp.com/ws/chat'
export const DEFAULT_ORIGIN = 'https://web.whatsapp.com'

export type WebSocketTransportOptions = {
	url?: string
	origin?: string
	headers?: Record<string, string>
	handshakeTimeoutMs?: number
}

export function createWebSocketTransport(opts: WebSocketTransportOptions = {}): Transport {
	const emitter = new EventEmitter() as Transport & { ws: WebSocket }

	const ws = new WebSocket(opts.url ?? DEFAULT_WS_URL, {
		origin: opts.origin ?? DEFAULT_ORIGIN,
		headers: opts.headers,
		handshakeTimeout: opts.handshakeTimeoutMs ?? 20_000,
	})

	ws.on('open', () => emitter.emit('open'))
	ws.on('message', (data: Buffer) => emitter.emit('data', Buffer.from(data)))
	ws.on('close', (code: number, reason: Buffer) => emitter.emit('close', code, reason?.toString()))
	ws.on('error', (err: Error) => emitter.emit('error', err))

	emitter.ws = ws
	emitter.send = (data: Buffer) => ws.send(data)
	emitter.close = () => {
		if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
			ws.close()
		}
	}

	Object.defineProperty(emitter, 'isOpen', { get: () => ws.readyState === WebSocket.OPEN })

	return emitter
}

/**
 * A pair of in-memory linked transports, for tests.
 * Whatever one sends, the other receives as `data`.
 */
export function createLinkedTransports(): [Transport, Transport] {
	const make = () => {
		const e = new EventEmitter() as Transport & { peer?: Transport; open: boolean }
		e.open = true

		return e
	}

	const a = make()
	const b = make()

	const wire = (self: typeof a, other: typeof b) => {
		self.send = (data: Buffer) => {
			if (self.open && other.open) {
				// asynchronous, like a real socket
				queueMicrotask(() => other.emit('data', Buffer.from(data)))
			}
		}

		self.close = () => {
			if (!self.open) {
				return
			}

			self.open = false
			queueMicrotask(() => {
				self.emit('close', 1000, 'closed')

				if (other.open) {
					other.open = false
					other.emit('close', 1000, 'peer closed')
				}
			})
		}

		Object.defineProperty(self, 'isOpen', { get: () => self.open })
	}

	wire(a, b)
	wire(b, a)

	return [a, b]
}
