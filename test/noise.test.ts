import assert from 'node:assert/strict'
import { test } from 'node:test'
import { Curve } from '../src/crypto/index.ts'
import { FrameDecoder, buildIntro, encodeFrame } from '../src/noise/frame.ts'
import { NoiseHandler, makeWaHeader } from '../src/noise/handler.ts'
import { HandshakeError, completeHandshake, createClientHello } from '../src/noise/handshake.ts'
import { CertChain, HandshakeMessage, NoiseCertificateDetails } from '../src/proto/wa.ts'

const PROLOGUE = makeWaHeader(3)

/**
 * Simulated Noise XX server.
 *
 * Worth more than a fixed vector: if the client gets the DH ORDER wrong, or the
 * shared counter during the handshake, or the final split, the two sides derive
 * different keys and the message exchange below fails.
 */
function makeFakeServer(opts: { issuerSerial?: number } = {}) {
	const ephemeral = Curve.generateKeyPair()
	const staticKey = Curve.generateKeyPair()

	let noise: NoiseHandler

	return {
		ephemeral,
		staticKey,

		/** Consumes the ClientHello and returns the ServerHello frame. */
		respond(clientHelloFrame: Buffer): Buffer {
			const { clientHello } = HandshakeMessage.decode(clientHelloFrame)
			const clientEphemeral = clientHello?.ephemeral

			assert.ok(clientEphemeral, 'ClientHello has no ephemeral key')

			// The server absorbs the CLIENT's ephemeral key, same as the client.
			noise = new NoiseHandler({
				ephemeralPublic: clientEphemeral,
				prologue: PROLOGUE,
				role: 'responder',
			})

			noise.authenticate(ephemeral.public)
			noise.mixIntoKey(Curve.sharedKey(ephemeral.private, clientEphemeral))

			const encryptedStatic = noise.encrypt(staticKey.public)
			noise.mixIntoKey(Curve.sharedKey(staticKey.private, clientEphemeral))

			const details = NoiseCertificateDetails.encode({
				serial: 1,
				issuerSerial: opts.issuerSerial ?? 0,
				key: staticKey.public,
			})

			const certPayload = CertChain.encode({
				intermediate: { details, signature: Buffer.alloc(64) },
			})

			return HandshakeMessage.encode({
				serverHello: {
					ephemeral: ephemeral.public,
					static: encryptedStatic,
					payload: noise.encrypt(certPayload),
				},
			})
		},

		/** Consumes the ClientFinish and returns the plaintext ClientPayload. */
		finish(clientFinishFrame: Buffer): Buffer {
			const { clientFinish } = HandshakeMessage.decode(clientFinishFrame)

			assert.ok(clientFinish?.static && clientFinish.payload)

			const clientStatic = noise.decrypt(clientFinish.static)
			noise.mixIntoKey(Curve.sharedKey(ephemeral.private, clientStatic))

			const payload = noise.decrypt(clientFinish.payload)
			noise.finishInit()

			return payload
		},

		noise: () => noise,
	}
}

function makeClient() {
	const ephemeral = Curve.generateKeyPair()
	const staticKey = Curve.generateKeyPair()
	const noise = new NoiseHandler({ ephemeralPublic: ephemeral.public, prologue: PROLOGUE })

	return { ephemeral, staticKey, noise }
}

test('full XX handshake: both sides derive the same channel', () => {
	const client = makeClient()
	const server = makeFakeServer()

	const clientHello = createClientHello(client.ephemeral)
	const serverHello = server.respond(clientHello)

	const payload = Buffer.from('simulated ClientPayload')
	const clientFinish = completeHandshake(client, serverHello, payload)

	assert.deepEqual(server.finish(clientFinish), payload)
	assert.equal(client.noise.isHandshakeFinished, true)

	// One side's write key == the other side's read key.
	const c = client.noise.debugState()
	const s = server.noise().debugState()

	assert.equal(c.encKey, s.decKey)
	assert.equal(c.decKey, s.encKey)
	assert.equal(c.hash, '')
})

test('after the handshake the channel carries messages both ways', () => {
	const client = makeClient()
	const server = makeFakeServer()

	const serverHello = server.respond(createClientHello(client.ephemeral))
	server.finish(completeHandshake(client, serverHello, Buffer.from('payload')))

	const clientNoise = client.noise
	const serverNoise = server.noise()

	// Several messages in a row: checks the counters advance in lockstep.
	for (let i = 0; i < 5; i++) {
		const msg = Buffer.from(`client -> server #${i}`)
		assert.deepEqual(serverNoise.decrypt(clientNoise.encrypt(msg)), msg)
	}

	for (let i = 0; i < 5; i++) {
		const msg = Buffer.from(`server -> client #${i}`)
		assert.deepEqual(clientNoise.decrypt(serverNoise.encrypt(msg)), msg)
	}
})

test('a certificate with the wrong issuer serial is rejected', () => {
	const client = makeClient()
	const server = makeFakeServer({ issuerSerial: 99 })
	const serverHello = server.respond(createClientHello(client.ephemeral))

	assert.throws(() => completeHandshake(client, serverHello, Buffer.from('x')), HandshakeError)
})

test('an incomplete ServerHello fails with a clear error', () => {
	const client = makeClient()
	const bogus = HandshakeMessage.encode({ serverHello: { ephemeral: Buffer.alloc(32) } })

	assert.throws(() => completeHandshake(client, bogus, Buffer.from('x')), HandshakeError)
})

test('a tampered ServerHello breaks GCM authentication', () => {
	const client = makeClient()
	const server = makeFakeServer()
	const serverHello = server.respond(createClientHello(client.ephemeral))

	// flip a bit in the middle of the frame
	const tampered = Buffer.from(serverHello)
	const mid = Math.floor(tampered.length / 2)
	tampered.writeUInt8(tampered.readUInt8(mid) ^ 0x01, mid)

	assert.throws(() => completeHandshake(client, tampered, Buffer.from('x')))
})

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

test('encodeFrame writes the length as 3 big-endian bytes', () => {
	const frame = encodeFrame(Buffer.alloc(300, 1))

	assert.equal(frame.readUInt8(0), 0)
	assert.equal(frame.readUInt16BE(1), 300)
	assert.equal(frame.length, 303)
})

test('FrameDecoder reassembles frames split across chunks', () => {
	const payloads = [Buffer.from('one'), Buffer.alloc(500, 7), Buffer.from('three')]
	const stream = Buffer.concat(payloads.map(p => encodeFrame(p)))
	const decoder = new FrameDecoder()
	const out: Buffer[] = []

	// Feed 7 bytes at a time — no frame ever arrives whole.
	for (let i = 0; i < stream.length; i += 7) {
		out.push(...decoder.push(stream.subarray(i, i + 7)))
	}

	assert.equal(decoder.pending, 0)
	assert.deepEqual(out, payloads)
})

test('FrameDecoder yields several frames from a single chunk', () => {
	const stream = Buffer.concat([encodeFrame(Buffer.from('a')), encodeFrame(Buffer.from('b'))])

	assert.deepEqual(new FrameDecoder().push(stream), [Buffer.from('a'), Buffer.from('b')])
})

test('FrameDecoder holds an incomplete frame without emitting', () => {
	const decoder = new FrameDecoder()
	const frame = encodeFrame(Buffer.alloc(100, 9))

	assert.deepEqual(decoder.push(frame.subarray(0, 50)), [])
	assert.ok(decoder.pending > 0)
	assert.deepEqual(decoder.push(frame.subarray(50)), [Buffer.alloc(100, 9)])
})

test('an intro without routing info is just the WA header', () => {
	assert.deepEqual(buildIntro(PROLOGUE), PROLOGUE)
	assert.deepEqual([...PROLOGUE.subarray(0, 2)], [87, 65]) // 'W', 'A'
})

test('an intro with routing info gains the ED header', () => {
	const routing = Buffer.from([0xaa, 0xbb, 0xcc])
	const intro = buildIntro(PROLOGUE, routing)

	assert.equal(intro.subarray(0, 2).toString('utf-8'), 'ED')
	assert.equal(intro.readUInt8(2), 0)
	assert.equal(intro.readUInt8(3), 1)
	assert.equal((intro.readUInt8(4) << 16) | intro.readUInt16BE(5), routing.length)
	assert.deepEqual(intro.subarray(7, 10), routing)
	assert.deepEqual(intro.subarray(10), PROLOGUE)
	assert.equal(intro.length, 7 + routing.length + PROLOGUE.length)
})

test('the first frame carries the intro before the length', () => {
	const intro = buildIntro(PROLOGUE)
	const frame = encodeFrame(Buffer.from('oi'), intro)

	assert.deepEqual(frame.subarray(0, intro.length), intro)
	assert.equal((frame.readUInt8(intro.length) << 16) | frame.readUInt16BE(intro.length + 1), 2)
})
