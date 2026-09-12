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
 * Simulated WhatsApp server: speaks Noise XX as the responder and exchanges
 * encrypted WABinary.
 *
 * It exists to exercise the whole connection — intro, framing, handshake,
 * transport mode, codec and node routing — without touching the network. It is
 * the test that replaces "connect and see what happens".
 */
export type FakeServer = {
	/** The ClientPayload the client sent, decoded. */
	clientPayload(): ClientPayloadType | undefined
	/** Nodes received from the client, in order. */
	received(): BinaryNode[]
	/** Sends a node to the client (encrypted). */
	send(node: BinaryNode): void
	/** Automatically replies to nodes matching the predicate. */
	autoRespond(match: (node: BinaryNode) => BinaryNode | undefined): void
	/** Resolves once the handshake completes. */
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
		assert.ok(noise, 'server has no Noise state yet')
		transport.send(encodeFrame(noise.encrypt(encodeBinaryNode(node))))
	}

	const handleHello = (frame: Buffer) => {
		const { clientHello } = HandshakeMessage.decode(frame)
		const clientEphemeral = clientHello?.ephemeral

		assert.ok(clientEphemeral, 'ClientHello has no ephemeral key')

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
		assert.ok(clientFinish?.static && clientFinish.payload, 'incomplete ClientFinish')

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
			// The client's first frame is preceded by the WA header.
			assert.deepEqual(data.subarray(0, waHeader.length), waHeader, 'WA header missing or wrong')
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
