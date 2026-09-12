import { EventEmitter } from 'node:events'
import WebSocket from 'ws'

/**
 * Camada de transporte, abstraída do WebSocket.
 *
 * Não é abstração gratuita: com ela a conexão inteira — handshake, framing,
 * roteamento de nós — pode ser exercitada contra um servidor simulado em
 * processo, sem rede. Isso é o que torna testável a parte que normalmente só se
 * depura em produção.
 *
 * Eventos: `open`, `data` (Buffer), `close` (code, reason), `error` (Error).
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
 * Par de transportes ligados em memória, para testes.
 * O que um envia, o outro recebe como `data`.
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
				// assíncrono, como um socket de verdade
				queueMicrotask(() => other.emit('data', Buffer.from(data)))
			}
		}

		self.close = () => {
			if (!self.open) {
				return
			}

			self.open = false
			queueMicrotask(() => {
				self.emit('close', 1000, 'fechado')

				if (other.open) {
					other.open = false
					other.emit('close', 1000, 'par fechou')
				}
			})
		}

		Object.defineProperty(self, 'isOpen', { get: () => self.open })
	}

	wire(a, b)
	wire(b, a)

	return [a, b]
}
