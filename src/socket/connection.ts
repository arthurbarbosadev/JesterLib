import { EventEmitter } from 'node:events'
import { randomBytes } from 'node:crypto'
import type { AuthenticationCreds } from '../auth/creds.ts'
import {
	buildPairDeviceAck,
	buildQrString,
	configureSuccessfulPairing,
	extractPairingRefs,
} from '../auth/pairing.ts'
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

/** Codes the server returns in `<failure>` / `<stream:error>`. */
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
	/** Token dictionary version; goes into the WA header (the Noise prologue). */
	dictVersion?: number
	transport?: Transport
	url?: string
	logger?: Logger
	connectTimeoutMs?: number
	keepAliveIntervalMs?: number
	defaultQueryTimeoutMs?: number
	countryCode?: string
	languageCode?: string
	/** Lifetime of the first QR; the phone needs time to open the camera. */
	qrTimeoutMs?: number
	/** Lifetime of subsequent QRs — refs expire quickly on the server. */
	qrRefreshMs?: number
}

const DEFAULT_VERSION: [number, number, number] = [2, 3000, 1015901307]

/**
 * Connection to WhatsApp: handshake, framing and node routing.
 *
 * Its responsibility ends at the node: it hands out decoded `BinaryNode`s and
 * sends `BinaryNode`s. Pairing, Signal and messages are layers on top.
 *
 * Events:
 *   `connection.update` — state changes (connecting/open/close, qr)
 *   `node`              — every node received, already decoded
 *   `creds.update`      — credentials changed and need to be persisted
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
	private qrTimer?: NodeJS.Timeout
	private qrRefs: string[] = []
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

	/** Unique per-message tag — the server echoes it back in `attrs.id`. */
	generateMessageTag(): string {
		return `${randomBytes(8).toString('hex')}.${this.epoch++}`
	}

	private updateState(update: Partial<ConnectionState>): void {
		Object.assign(this.state, update)
		this.emit('connection.update', update)
	}

	// -------------------------------------------------------------------------
	// Sending
	// -------------------------------------------------------------------------

	/** Unencrypted frame — only the handshake uses this. */
	private sendRawFrame(payload: Buffer): void {
		if (!this.transport?.isOpen) {
			throw new ConnectionError('connection closed', DisconnectReason.connectionClosed)
		}

		const intro = this.sentIntro ? undefined : buildIntro(this.waHeader, this.auth.creds.routingInfo)
		this.sentIntro = true

		this.transport.send(encodeFrame(payload, intro))
	}

	sendNode(node: BinaryNode): void {
		if (!this.noise?.isHandshakeFinished) {
			throw new ConnectionError('handshake has not finished yet', DisconnectReason.connectionClosed)
		}

		this.logger.debug({ node: node.tag, attrs: node.attrs }, 'sending node')
		this.sendRawFrame(this.noise.encrypt(encodeBinaryNode(node)))
	}

	/**
	 * Sends and waits for the reply carrying the same `id`. If the node has no id,
	 * one is generated — without it there is no way to match the response.
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

			throw new ConnectionError(error?.attrs.text ?? `query ${id} failed`, code)
		}

		return result
	}

	private waitForReply(id: string, timeoutMs: number): Promise<BinaryNode> {
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pendingRequests.delete(id)
				reject(new ConnectionError(`timed out waiting for a reply to ${id}`, DisconnectReason.timedOut))
			}, timeoutMs)

			this.pendingRequests.set(id, { resolve, reject, timer })
		})
	}

	// -------------------------------------------------------------------------
	// Connection
	// -------------------------------------------------------------------------

	async connect(): Promise<void> {
		if (this.transport) {
			throw new Error('socket has already connected; create a new instance')
		}

		this.updateState({ connection: 'connecting' })

		const transport =
			this.options.transport ?? createWebSocketTransport({ url: this.options.url })

		this.transport = transport

		transport.on('data', chunk => this.onData(chunk))
		transport.on('error', err => this.onClose(err))
		transport.on('close', () => this.onClose(new ConnectionError('connection closed', DisconnectReason.connectionClosed)))

		if (!transport.isOpen) {
			await this.waitForEvent(transport, 'open', this.options.connectTimeoutMs ?? 20_000)
		}

		this.startHandshake()
	}

	private waitForEvent(emitter: EventEmitter, event: string, timeoutMs: number): Promise<void> {
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup()
				reject(new ConnectionError(`timed out waiting for "${event}"`, DisconnectReason.timedOut))
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

		this.logger.debug({}, 'sending ClientHello')
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
				this.logger.error({ err }, 'error while processing a frame')
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

		// Before the handshake finishes, the only expected frame is the ServerHello.
		if (!noise.isHandshakeFinished) {
			const payload = buildClientPayload(this.auth.creds, this.config)
			const finish = completeHandshake(
				{ noise, ephemeral: this.ephemeral, staticKey: this.auth.creds.noiseKey },
				frame,
				payload,
			)

			this.logger.debug({}, 'handshake complete, sending ClientFinish')
			this.sendRawFrame(finish)
			this.startKeepAlive()

			return
		}

		const node = decodeBinaryNode(noise.decrypt(frame))
		this.onNode(node)
	}

	private onNode(node: BinaryNode): void {
		this.logger.debug({ tag: node.tag, attrs: node.attrs }, 'node received')

		// A reply to a pending query takes precedence over general routing.
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
			case 'iq':
				this.onIq(node)
				break
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
				this.onClose(new ConnectionError('stream ended by the server', DisconnectReason.connectionClosed))
				break
		}
	}

	// -------------------------------------------------------------------------
	// Pairing
	// -------------------------------------------------------------------------

	/** Server-initiated IQs. The pairing ones are what matter here. */
	private onIq(node: BinaryNode): void {
		if (getBinaryNodeChild(node, 'pair-device')) {
			this.onPairDevice(node)
			return
		}

		if (getBinaryNodeChild(node, 'pair-success')) {
			this.onPairSuccess(node)
		}
	}

	private onPairDevice(node: BinaryNode): void {
		const id = node.attrs.id

		if (!id) {
			this.logger.warn({}, '<pair-device> has no id; ignoring')
			return
		}

		// The server only emits further refs after the ACK.
		this.sendNode(buildPairDeviceAck(id))

		this.qrRefs = extractPairingRefs(node)
		this.emitNextQr(this.options.qrTimeoutMs ?? 60_000)
	}

	/**
	 * Publishes the next QR and schedules the rotation. When the refs run out the
	 * pairing has expired — retrying is pointless, the server needs a fresh
	 * connection.
	 */
	private emitNextQr(validForMs: number): void {
		clearTimeout(this.qrTimer)

		const ref = this.qrRefs.shift()

		if (!ref) {
			this.onClose(new ConnectionError('ran out of QR refs', DisconnectReason.timedOut))
			return
		}

		this.updateState({ qr: buildQrString(ref, this.auth.creds) })

		// Deliberately NOT unref'd: while a QR is pending, the process is waiting
		// for a human to scan it and must stay alive. `onClose` clears the timer,
		// so it never keeps the loop open longer than the pairing attempt.
		this.qrTimer = setTimeout(
			() => this.emitNextQr(this.options.qrRefreshMs ?? 20_000),
			validForMs,
		)
	}

	private onPairSuccess(node: BinaryNode): void {
		clearTimeout(this.qrTimer)

		try {
			const { reply, update } = configureSuccessfulPairing(node, this.auth.creds)

			this.applyCredsUpdate(update)
			this.sendNode(reply)

			// The server closes right after with stream:error 515 (restartRequired):
			// that is expected, and the reconnect already uses the login payload.
			this.updateState({ isNewLogin: true, qr: undefined })
		} catch (err) {
			this.logger.error({ err }, 'pairing failed')
			this.onClose(err as Error)
		}
	}

	private applyCredsUpdate(update: Partial<AuthenticationCreds>): void {
		Object.assign(this.auth.creds, update)
		this.emit('creds.update', this.auth.creds)
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

		this.onClose(new ConnectionError(node.attrs.text ?? `connection failure (${code})`, code))
	}

	private onStreamError(node: BinaryNode): void {
		// The real reason is usually in the first child (`conflict`, `ack`, ...).
		const child = Array.isArray(node.content) ? node.content[0] : undefined
		const code = Number(node.attrs.code ?? DisconnectReason.connectionClosed)
		const detail = [node.attrs.code, child?.tag, child?.attrs?.type].filter(Boolean).join(' ')

		this.onClose(new ConnectionError(`stream:error ${detail}`.trim(), code))
	}

	/**
	 * `ib` carries out-of-band information. The one that matters here is
	 * `edge_routing`: storing the shard makes later connections go straight to
	 * the right server.
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
	// Keep-alive and shutdown
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
				this.logger.warn({ err }, 'keep-alive failed')
			})
		}, interval)

		// Do not keep the process alive just for the ping.
		this.keepAliveTimer.unref?.()
	}

	private onClose(error: Error): void {
		if (this.closed) {
			return
		}

		this.closed = true

		clearInterval(this.keepAliveTimer)
		clearTimeout(this.qrTimer)

		for (const [, pending] of this.pendingRequests) {
			clearTimeout(pending.timer)
			pending.reject(error)
		}

		this.pendingRequests.clear()

		this.updateState({ connection: 'close', lastDisconnect: { error, date: new Date() } })
		this.transport?.close()
	}

	/** Ends the connection. `error` is exposed through `lastDisconnect`. */
	end(error?: Error): void {
		this.onClose(error ?? new ConnectionError('closed by the client', DisconnectReason.connectionClosed))
	}
}
