import assert from 'node:assert/strict'
import { decodeBinaryNode } from '../../src/binary/decode.ts'
import { encodeBinaryNode } from '../../src/binary/encode.ts'
import type { BinaryNode } from '../../src/binary/node.ts'
import { Curve } from '../../src/crypto/index.ts'
import { FrameDecoder, encodeFrame } from '../../src/noise/frame.ts'
import { NoiseHandler, makeWaHeader } from '../../src/noise/handler.ts'
import { CertChain, ClientPayload, HandshakeMessage, NoiseCertificateDetails } from '../../src/proto/wa.ts'
import type { Transport } from '../../src/socket/transport.ts'
import type { ClientPayloadType } from '../../src/proto/wa.ts'

/**
 * WhatsApp simulado: fala Noise XX como responder e troca WABinary cifrado.
 *
 * Serve para exercitar a conexão inteira — intro, framing, handshake, modo
 * transporte, codec e roteamento de nós — sem tocar na rede. É o teste que
 * substitui "conecta e vê o que acontece".
 */
export type FakeServer = {
	/** ClientPayload que o cliente enviou, decodificado. */
	clientPayload(): ClientPayloadType | undefined
	/** Nós recebidos do cliente, em ordem. */
	received(): BinaryNode[]
	/** Envia um nó para o cliente (cifrado). */
	send(node: BinaryNode): void
	/** Responde automaticamente a nós que casem com o predicado. */
	autoRespond(match: (node: BinaryNode) => BinaryNode | undefined): void
	/** Promise que resolve quando o handshake termina. */
	ready(): Promise<void>
}

export function attachFakeServer(
	transport: Transport,
	opts: { dictVersion?: number; sendSuccessOnConnect?: boolean } = {},
): FakeServer {
	const waHeader = makeWaHeader(opts.dictVersion ?? 3)
	const ephemeral = Curve.generateKeyPair()
	const staticKey = Curve.generateKeyPair()

	const frames = new FrameDecoder()
	const nodes: BinaryNode[] = []
	const responders: Array<(node: BinaryNode) => BinaryNode | undefined> = []

	let noise: NoiseHandler | undefined
	let phase: 'hello' | 'finish' | 'transport' = 'hello'
	let introStripped = false
	let payload: ClientPayloadType | undefined
	let resolveReady: () => void
	const readyPromise = new Promise<void>(resolve => {
		resolveReady = resolve
	})

	const send = (node: BinaryNode) => {
		assert.ok(noise, 'servidor ainda não tem estado Noise')
		transport.send(encodeFrame(noise.encrypt(encodeBinaryNode(node))))
	}

	const handleHello = (frame: Buffer) => {
		const { clientHello } = HandshakeMessage.decode(frame)
		const clientEphemeral = clientHello?.ephemeral

		assert.ok(clientEphemeral, 'ClientHello sem efêmera')

		noise = new NoiseHandler({
			ephemeralPublic: clientEphemeral,
			prologue: waHeader,
			role: 'responder',
		})

		noise.authenticate(ephemeral.public)
		noise.mixIntoKey(Curve.sharedKey(ephemeral.private, clientEphemeral))

		const encryptedStatic = noise.encrypt(staticKey.public)
		noise.mixIntoKey(Curve.sharedKey(staticKey.private, clientEphemeral))

		const certPayload = CertChain.encode({
			intermediate: {
				details: NoiseCertificateDetails.encode({ serial: 1, issuerSerial: 0, key: staticKey.public }),
				signature: Buffer.alloc(64),
			},
		})

		transport.send(
			encodeFrame(
				HandshakeMessage.encode({
					serverHello: {
						ephemeral: ephemeral.public,
						static: encryptedStatic,
						payload: noise.encrypt(certPayload),
					},
				}),
			),
		)

		phase = 'finish'
	}

	const handleFinish = (frame: Buffer) => {
		assert.ok(noise)

		const { clientFinish } = HandshakeMessage.decode(frame)
		assert.ok(clientFinish?.static && clientFinish.payload, 'ClientFinish incompleto')

		const clientStatic = noise.decrypt(clientFinish.static)
		noise.mixIntoKey(Curve.sharedKey(ephemeral.private, clientStatic))

		payload = ClientPayload.decode(noise.decrypt(clientFinish.payload))
		noise.finishInit()

		phase = 'transport'
		resolveReady()

		if (opts.sendSuccessOnConnect !== false) {
			send({ tag: 'success', attrs: { lid: '123456789:1@lid', platform: 'android' } })
		}
	}

	const handleNode = (frame: Buffer) => {
		assert.ok(noise)

		const node = decodeBinaryNode(noise.decrypt(frame))
		nodes.push(node)

		for (const responder of responders) {
			const reply = responder(node)

			if (reply) {
				send(reply)
				return
			}
		}
	}

	transport.on('data', (chunk: Buffer) => {
		let data = chunk

		if (!introStripped) {
			// O primeiro frame do cliente vem precedido do header WA.
			assert.deepEqual(data.subarray(0, waHeader.length), waHeader, 'header WA ausente ou errado')
			data = data.subarray(waHeader.length)
			introStripped = true
		}

		for (const frame of frames.push(data)) {
			if (phase === 'hello') {
				handleHello(frame)
			} else if (phase === 'finish') {
				handleFinish(frame)
			} else {
				handleNode(frame)
			}
		}
	})

	return {
		clientPayload: () => payload,
		received: () => nodes,
		send,
		autoRespond: matcher => responders.push(matcher),
		ready: () => readyPromise,
	}
}
