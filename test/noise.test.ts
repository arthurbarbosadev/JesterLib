import assert from 'node:assert/strict'
import { test } from 'node:test'
import { Curve } from '../src/crypto/index.ts'
import { FrameDecoder, buildIntro, encodeFrame } from '../src/noise/frame.ts'
import { NoiseHandler, makeWaHeader } from '../src/noise/handler.ts'
import { HandshakeError, completeHandshake, createClientHello } from '../src/noise/handshake.ts'
import { CertChain, HandshakeMessage, NoiseCertificateDetails } from '../src/proto/wa.ts'

const PROLOGUE = makeWaHeader(3)

/**
 * Servidor Noise XX simulado.
 *
 * Vale mais que um vetor fixo: se o cliente errar a ORDEM dos DH, ou o
 * compartilhamento de contador durante o handshake, ou o split final, os dois
 * lados derivam chaves diferentes e a troca de mensagens abaixo falha.
 */
function makeFakeServer(opts: { issuerSerial?: number } = {}) {
	const ephemeral = Curve.generateKeyPair()
	const staticKey = Curve.generateKeyPair()

	let noise: NoiseHandler

	return {
		ephemeral,
		staticKey,

		/** Consome o ClientHello e devolve o frame do ServerHello. */
		respond(clientHelloFrame: Buffer): Buffer {
			const { clientHello } = HandshakeMessage.decode(clientHelloFrame)
			const clientEphemeral = clientHello?.ephemeral

			assert.ok(clientEphemeral, 'ClientHello sem chave efêmera')

			// O servidor absorve a efêmera DO CLIENTE, igual ao cliente.
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

		/** Consome o ClientFinish e devolve o ClientPayload em claro. */
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

test('handshake XX completo: os dois lados derivam o mesmo canal', () => {
	const client = makeClient()
	const server = makeFakeServer()

	const clientHello = createClientHello(client.ephemeral)
	const serverHello = server.respond(clientHello)

	const payload = Buffer.from('ClientPayload simulado')
	const clientFinish = completeHandshake(client, serverHello, payload)

	assert.deepEqual(server.finish(clientFinish), payload)
	assert.equal(client.noise.isHandshakeFinished, true)

	// Chave de escrita de um lado == chave de leitura do outro.
	const c = client.noise.debugState()
	const s = server.noise().debugState()

	assert.equal(c.encKey, s.decKey)
	assert.equal(c.decKey, s.encKey)
	assert.equal(c.hash, '')
})

test('após o handshake o canal transporta mensagens nos dois sentidos', () => {
	const client = makeClient()
	const server = makeFakeServer()

	const serverHello = server.respond(createClientHello(client.ephemeral))
	server.finish(completeHandshake(client, serverHello, Buffer.from('payload')))

	const clientNoise = client.noise
	const serverNoise = server.noise()

	// Várias mensagens seguidas: valida que os contadores avançam em sincronia.
	for (let i = 0; i < 5; i++) {
		const msg = Buffer.from(`cliente -> servidor #${i}`)
		assert.deepEqual(serverNoise.decrypt(clientNoise.encrypt(msg)), msg)
	}

	for (let i = 0; i < 5; i++) {
		const msg = Buffer.from(`servidor -> cliente #${i}`)
		assert.deepEqual(clientNoise.decrypt(serverNoise.encrypt(msg)), msg)
	}
})

test('certificado com serial de emissor errado é rejeitado', () => {
	const client = makeClient()
	const server = makeFakeServer({ issuerSerial: 99 })
	const serverHello = server.respond(createClientHello(client.ephemeral))

	assert.throws(() => completeHandshake(client, serverHello, Buffer.from('x')), HandshakeError)
})

test('ServerHello incompleto falha com erro claro', () => {
	const client = makeClient()
	const bogus = HandshakeMessage.encode({ serverHello: { ephemeral: Buffer.alloc(32) } })

	assert.throws(() => completeHandshake(client, bogus, Buffer.from('x')), HandshakeError)
})

test('ServerHello adulterado quebra a autenticação GCM', () => {
	const client = makeClient()
	const server = makeFakeServer()
	const serverHello = server.respond(createClientHello(client.ephemeral))

	// vira um bit no meio do frame
	const tampered = Buffer.from(serverHello)
	const mid = Math.floor(tampered.length / 2)
	tampered.writeUInt8(tampered.readUInt8(mid) ^ 0x01, mid)

	assert.throws(() => completeHandshake(client, tampered, Buffer.from('x')))
})

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

test('encodeFrame escreve o tamanho em 3 bytes big-endian', () => {
	const frame = encodeFrame(Buffer.alloc(300, 1))

	assert.equal(frame.readUInt8(0), 0)
	assert.equal(frame.readUInt16BE(1), 300)
	assert.equal(frame.length, 303)
})

test('FrameDecoder remonta frames partidos entre chunks', () => {
	const payloads = [Buffer.from('um'), Buffer.alloc(500, 7), Buffer.from('tres')]
	const stream = Buffer.concat(payloads.map(p => encodeFrame(p)))
	const decoder = new FrameDecoder()
	const out: Buffer[] = []

	// Alimenta 7 bytes por vez — nenhum frame chega inteiro de uma vez.
	for (let i = 0; i < stream.length; i += 7) {
		out.push(...decoder.push(stream.subarray(i, i + 7)))
	}

	assert.equal(decoder.pending, 0)
	assert.deepEqual(out, payloads)
})

test('FrameDecoder entrega vários frames de um chunk só', () => {
	const stream = Buffer.concat([encodeFrame(Buffer.from('a')), encodeFrame(Buffer.from('b'))])

	assert.deepEqual(new FrameDecoder().push(stream), [Buffer.from('a'), Buffer.from('b')])
})

test('FrameDecoder segura frame incompleto sem emitir', () => {
	const decoder = new FrameDecoder()
	const frame = encodeFrame(Buffer.alloc(100, 9))

	assert.deepEqual(decoder.push(frame.subarray(0, 50)), [])
	assert.ok(decoder.pending > 0)
	assert.deepEqual(decoder.push(frame.subarray(50)), [Buffer.alloc(100, 9)])
})

test('intro sem routing info é só o header WA', () => {
	assert.deepEqual(buildIntro(PROLOGUE), PROLOGUE)
	assert.deepEqual([...PROLOGUE.subarray(0, 2)], [87, 65]) // 'W', 'A'
})

test('intro com routing info ganha o cabeçalho ED', () => {
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

test('primeiro frame carrega o intro antes do tamanho', () => {
	const intro = buildIntro(PROLOGUE)
	const frame = encodeFrame(Buffer.from('oi'), intro)

	assert.deepEqual(frame.subarray(0, intro.length), intro)
	assert.equal((frame.readUInt8(intro.length) << 16) | frame.readUInt16BE(intro.length + 1), 2)
})
