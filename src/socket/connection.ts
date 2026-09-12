import { EventEmitter } from 'node:events'
import { randomBytes } from 'node:crypto'
import type { AuthenticationState } from '../auth/state.ts'
import { decodeBinaryNode } from '../binary/decode.ts'
import { encodeBinaryNode } from '../binary/encode.ts'
import { getBinaryNodeChild, type BinaryNode } from '../binary/node.ts'
import { S_WHATSAPP_NET } from '../binary/constants.ts'
import { Curve } from '../crypto/index.ts'
import { FrameDecoder, buildIntro, encodeFrame } from '../noise/frame.ts'
import { NoiseHandler, makeWaHeader } from '../noise/handler.ts'
import { completeHandshake, createClientHello } from '../noise/handshake.ts'
import { buildClientPayload, DEFAULT_BROWSER, type ClientPayloadConfig } from './client-payload.ts'
import { createWebSocketTransport, type Transport } from './transport.ts'

/** Códigos que o servidor devolve em `<failure>` / `<stream:error>`. */
export const DisconnectReason = {
	connectionClosed: 428,
	connectionLost: 408,
	connectionReplaced: 440,
	timedOut: 408,
	loggedOut: 401,
	badSession: 500,
	restartRequired: 515,
	multideviceMismatch: 411,
	forbidden: 403,
	unavailableService: 503,
} as const

export class ConnectionError extends Error {
	readonly code: number

	constructor(message: string, code: number) {
		super(message)
		this.name = 'ConnectionError'
		this.code = code
	}
}

export type ConnectionStatus = 'close' | 'connecting' | 'open'

export type ConnectionState = {
	connection: ConnectionStatus
	lastDisconnect?: { error?: Error; date: Date }
	qr?: string
	isNewLogin?: boolean
}

export type Logger = {
	debug(obj: unknown, msg?: string): void
	info(obj: unknown, msg?: string): void
	warn(obj: unknown, msg?: string): void
	error(obj: unknown, msg?: string): void
}

const silentLogger: Logger = {
	debug: () => {},
	info: () => {},
	warn: () => {},
	error: () => {},
}

export type JesterSocketOptions = {
	auth: AuthenticationState
	version?: [number, number, number]
	browser?: [string, string, string]
	/** Versão do dicionário de tokens; entra no header WA (prólogo do Noise). */
	dictVersion?: number
	transport?: Transport
	url?: string
	logger?: Logger
	connectTimeoutMs?: number
	keepAliveIntervalMs?: number
	defaultQueryTimeoutMs?: number
	countryCode?: string
	languageCode?: string
}

const DEFAULT_VERSION: [number, number, number] = [2, 3000, 1015901307]

/**
 * Conexão com o WhatsApp: handshake, framing e roteamento de nós.
 *
 * Responsabilidade termina no nó: ela entrega `BinaryNode` decodificado e
 * envia `BinaryNode`. Pareamento, Signal e mensagens são camadas acima.
 *
 * Eventos:
 *   `connection.update` — mudanças de estado (connecting/open/close, qr)
 *   `node`              — todo nó recebido, já decodificado
 *   `creds.update`      — credenciais mudaram e precisam ser persistidas
 */
export class JesterSocket extends EventEmitter {
	readonly auth: AuthenticationState
	private readonly logger: Logger
	private readonly config: ClientPayloadConfig
	private readonly options: JesterSocketOptions
	private readonly waHeader: Buffer

	private transport?: Transport
	private noise?: NoiseHandler
	private ephemeral = Curve.generateKeyPair()
	private frames = new FrameDecoder()
	private sentIntro = false

	private state: ConnectionState = { connection: 'close' }
	private pendingRequests = new Map<
		string,
		{ resolve: (node: BinaryNode) => void; reject: (err: Error) => void; timer: NodeJS.Timeout }
	>()

	private keepAliveTimer?: NodeJS.Timeout
	private epoch = 0
	private closed = false

	constructor(options: JesterSocketOptions) {
		super()

		this.options = options
		this.auth = options.auth
		this.logger = options.logger ?? silentLogger
		this.waHeader = makeWaHeader(options.dictVersion ?? 3)
		this.config = {
			version: options.version ?? DEFAULT_VERSION,
			browser: options.browser ?? DEFAULT_BROWSER,
			countryCode: options.countryCode,
			languageCode: options.languageCode,
		}
	}

	get connectionState(): Readonly<ConnectionState> {
		return this.state
	}

	/** Tag única por mensagem — o servidor ecoa em `attrs.id` na resposta. */
	generateMessageTag(): string {
		return `${randomBytes(8).toString('hex')}.${this.epoch++}`
	}

	private updateState(update: Partial<ConnectionState>): void {
		Object.assign(this.state, update)
		this.emit('connection.update', update)
	}

	// -------------------------------------------------------------------------
	// Envio
	// -------------------------------------------------------------------------

	/** Frame sem cifra — só o handshake usa. */
	private sendRawFrame(payload: Buffer): void {
		if (!this.transport?.isOpen) {
			throw new ConnectionError('conexão fechada', DisconnectReason.connectionClosed)
		}

		const intro = this.sentIntro ? undefined : buildIntro(this.waHeader, this.auth.creds.routingInfo)
		this.sentIntro = true

		this.transport.send(encodeFrame(payload, intro))
	}

	sendNode(node: BinaryNode): void {
		if (!this.noise?.isHandshakeFinished) {
			throw new ConnectionError('handshake ainda não terminou', DisconnectReason.connectionClosed)
		}

		this.logger.debug({ node: node.tag, attrs: node.attrs }, 'enviando nó')
		this.sendRawFrame(this.noise.encrypt(encodeBinaryNode(node)))
	}

	/**
	 * Envia e espera a resposta com o mesmo `id`. Se o nó não tiver id, um é
	 * gerado — sem isso não há como casar a resposta.
	 */
	async query(node: BinaryNode, timeoutMs?: number): Promise<BinaryNode> {
		const id = node.attrs.id ?? this.generateMessageTag()
		const withId: BinaryNode = { ...node, attrs: { ...node.attrs, id } }

		const promise = this.waitForReply(id, timeoutMs ?? this.options.defaultQueryTimeoutMs ?? 60_000)
		this.sendNode(withId)

		const result = await promise

		if (result.attrs.type === 'error') {
			const error = getBinaryNodeChild(result, 'error')
			const code = Number(error?.attrs.code ?? 500)

			throw new ConnectionError(error?.attrs.text ?? `query ${id} falhou`, code)
		}

		return result
	}

	private waitForReply(id: string, timeoutMs: number): Promise<BinaryNode> {
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pendingRequests.delete(id)
				reject(new ConnectionError(`timeout esperando resposta de ${id}`, DisconnectReason.timedOut))
			}, timeoutMs)

			this.pendingRequests.set(id, { resolve, reject, timer })
		})
	}

	// -------------------------------------------------------------------------
	// Conexão
	// -------------------------------------------------------------------------

	async connect(): Promise<void> {
		if (this.transport) {
			throw new Error('socket já foi conectado; crie uma nova instância')
		}

		this.updateState({ connection: 'connecting' })

		const transport =
			this.options.transport ?? createWebSocketTransport({ url: this.options.url })

		this.transport = transport

		transport.on('data', chunk => this.onData(chunk))
		transport.on('error', err => this.onClose(err))
		transport.on('close', () => this.onClose(new ConnectionError('conexão fechada', DisconnectReason.connectionClosed)))

		if (!transport.isOpen) {
			await this.waitForEvent(transport, 'open', this.options.connectTimeoutMs ?? 20_000)
		}

		this.startHandshake()
	}

	private waitForEvent(emitter: EventEmitter, event: string, timeoutMs: number): Promise<void> {
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup()
				reject(new ConnectionError(`timeout esperando "${event}"`, DisconnectReason.timedOut))
			}, timeoutMs)

			const onEvent = () => {
				cleanup()
				resolve()
			}

			const onError = (err: Error) => {
				cleanup()
				reject(err)
			}

			const cleanup = () => {
				clearTimeout(timer)
				emitter.off(event, onEvent)
				emitter.off('error', onError)
			}

			emitter.once(event, onEvent)
			emitter.once('error', onError)
		})
	}

	private startHandshake(): void {
		this.ephemeral = Curve.generateKeyPair()
		this.noise = new NoiseHandler({
			ephemeralPublic: this.ephemeral.public,
			prologue: this.waHeader,
		})

		this.logger.debug({}, 'enviando ClientHello')
		this.sendRawFrame(createClientHello(this.ephemeral))
	}

	private onData(chunk: Buffer): void {
		let frames: Buffer[]

		try {
			frames = this.frames.push(chunk)
		} catch (err) {
			this.onClose(err as Error)
			return
		}

		for (const frame of frames) {
			try {
				this.onFrame(frame)
			} catch (err) {
				this.logger.error({ err }, 'erro processando frame')
				this.onClose(err as Error)
				return
			}
		}
	}

	private onFrame(frame: Buffer): void {
		const noise = this.noise

		if (!noise) {
			return
		}

		// Antes do fim do handshake o único frame esperado é o ServerHello.
		if (!noise.isHandshakeFinished) {
			const payload = buildClientPayload(this.auth.creds, this.config)
			const finish = completeHandshake(
				{ noise, ephemeral: this.ephemeral, staticKey: this.auth.creds.noiseKey },
				frame,
				payload,
			)

			this.logger.debug({}, 'handshake concluído, enviando ClientFinish')
			this.sendRawFrame(finish)
			this.startKeepAlive()

			return
		}

		const node = decodeBinaryNode(noise.decrypt(frame))
		this.onNode(node)
	}

	private onNode(node: BinaryNode): void {
		this.logger.debug({ tag: node.tag, attrs: node.attrs }, 'nó recebido')

		// Resposta a uma query pendente tem precedência sobre o roteamento geral.
		const id = node.attrs.id

		if (id) {
			const pending = this.pendingRequests.get(id)

			if (pending) {
				clearTimeout(pending.timer)
				this.pendingRequests.delete(id)
				pending.resolve(node)
			}
		}

		this.emit('node', node)

		switch (node.tag) {
			case 'success':
				this.onSuccess(node)
				break
			case 'failure':
				this.onFailure(node)
				break
			case 'stream:error':
				this.onStreamError(node)
				break
			case 'ib':
				this.onIb(node)
				break
			case 'xmlstreamend':
				this.onClose(new ConnectionError('stream encerrado pelo servidor', DisconnectReason.connectionClosed))
				break
		}
	}

	private onSuccess(node: BinaryNode): void {
		const { creds } = this.auth
		let changed = false

		if (node.attrs.lid && creds.me && !creds.me.lid) {
			creds.me.lid = node.attrs.lid
			changed = true
		}

		if (node.attrs.platform && creds.platform !== node.attrs.platform) {
			creds.platform = node.attrs.platform
			changed = true
		}

		if (changed) {
			this.emit('creds.update', creds)
		}

		this.updateState({ connection: 'open' })
	}

	private onFailure(node: BinaryNode): void {
		const code = Number(node.attrs.reason ?? DisconnectReason.badSession)

		this.onClose(new ConnectionError(node.attrs.text ?? `falha de conexão (${code})`, code))
	}

	private onStreamError(node: BinaryNode): void {
		// O motivo real costuma estar no primeiro filho (`conflict`, `ack`, ...).
		const child = Array.isArray(node.content) ? node.content[0] : undefined
		const code = Number(node.attrs.code ?? DisconnectReason.connectionClosed)
		const detail = [node.attrs.code, child?.tag, child?.attrs?.type].filter(Boolean).join(' ')

		this.onClose(new ConnectionError(`stream:error ${detail}`.trim(), code))
	}

	/**
	 * `ib` carrega informações fora de banda. A que importa aqui é o
	 * `edge_routing`: guardar o shard faz as próximas conexões irem direto ao
	 * servidor certo.
	 */
	private onIb(node: BinaryNode): void {
		const routing = getBinaryNodeChild(node, 'edge_routing')
		const value = getBinaryNodeChild(routing, 'routing_info')?.content

		if (Buffer.isBuffer(value)) {
			this.auth.creds.routingInfo = value
			this.emit('creds.update', this.auth.creds)
		}
	}

	// -------------------------------------------------------------------------
	// Keep-alive e encerramento
	// -------------------------------------------------------------------------

	private startKeepAlive(): void {
		const interval = this.options.keepAliveIntervalMs ?? 30_000

		this.keepAliveTimer = setInterval(() => {
			if (this.closed) {
				return
			}

			this.query({
				tag: 'iq',
				attrs: { to: S_WHATSAPP_NET, type: 'get', xmlns: 'w:p' },
				content: [{ tag: 'ping', attrs: {} }],
			}).catch(err => {
				this.logger.warn({ err }, 'keep-alive falhou')
			})
		}, interval)

		// Não segura o processo vivo só por causa do ping.
		this.keepAliveTimer.unref?.()
	}

	private onClose(error: Error): void {
		if (this.closed) {
			return
		}

		this.closed = true

		clearInterval(this.keepAliveTimer)

		for (const [, pending] of this.pendingRequests) {
			clearTimeout(pending.timer)
			pending.reject(error)
		}

		this.pendingRequests.clear()

		this.updateState({ connection: 'close', lastDisconnect: { error, date: new Date() } })
		this.transport?.close()
	}

	/** Encerra a conexão. `error` fica disponível em `lastDisconnect`. */
	end(error?: Error): void {
		this.onClose(error ?? new ConnectionError('encerrado pelo cliente', DisconnectReason.connectionClosed))
	}
}
