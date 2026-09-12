import { aesDecryptGCM, aesEncryptGCM, hkdf, sha256 } from '../crypto/index.ts'

/**
 * Noise Protocol Framework state, pattern `XX` with X25519 + AES-GCM + SHA-256.
 *
 * XX means neither side knows the other's static key up front: both are
 * transmitted during the handshake. There are three messages — ClientHello,
 * ServerHello, ClientFinish — and at the end the channel becomes symmetric,
 * with one key per direction.
 *
 * Two traps that come from WhatsApp's usage rather than the Noise spec:
 *
 * 1. During the handshake, both directions share the SAME nonce counter. Only
 *    after `finishInit()` does each direction get its own.
 * 2. Every ciphertext exchanged is mixed into the transcript hash
 *    (`authenticate`), including the ones you produced yourself.
 */

const NOISE_MODE = 'Noise_XX_25519_AESGCM_SHA256'

/** 'W', 'A', major version, token dictionary version. */
export function makeWaHeader(dictVersion: number): Buffer {
	return Buffer.from([87, 65, 6, dictVersion])
}

function generateIV(counter: number): Buffer {
	const iv = Buffer.alloc(12)
	iv.writeUInt32BE(counter, 8)

	return iv
}

/**
 * Initial hash state: if the protocol name fits in HASHLEN it is used raw with
 * zero padding; otherwise its SHA-256 is used (Noise spec, §5.2).
 */
function initialHash(): Buffer {
	const name = Buffer.from(NOISE_MODE, 'utf-8')

	if (name.length === 32) {
		return name
	}

	if (name.length < 32) {
		return Buffer.concat([name, Buffer.alloc(32 - name.length)])
	}

	return sha256(name)
}

/**
 * `initiator` is the client. `responder` exists so the handshake can be tested
 * against a simulated server — both sides share all the logic and differ only
 * in the final split, where the keys swap direction.
 */
export type NoiseRole = 'initiator' | 'responder'

export type NoiseHandlerOptions = {
	/**
	 * The client's EPHEMERAL public key. Important: it is the ephemeral key that
	 * goes into the initial hash, not the static one — the static key only shows
	 * up in the ClientFinish. Both sides absorb the SAME key here (the client's).
	 */
	ephemeralPublic: Buffer
	/** Prologue: the WA header, mixed into the hash before anything else. */
	prologue: Buffer
	role?: NoiseRole
}

export class NoiseHandler {
	private hash: Buffer
	private salt: Buffer
	private encKey: Buffer
	private decKey: Buffer
	private readCounter = 0
	private writeCounter = 0
	private handshakeFinished = false
	private readonly role: NoiseRole

	constructor(opts: NoiseHandlerOptions) {
		const h = initialHash()

		this.hash = h
		this.salt = h
		this.encKey = h
		this.decKey = h
		this.role = opts.role ?? 'initiator'

		this.authenticate(opts.prologue)
		this.authenticate(opts.ephemeralPublic)
	}

	get isHandshakeFinished(): boolean {
		return this.handshakeFinished
	}

	/** Mixes data into the transcript hash. Inert once the handshake is done. */
	authenticate(data: Buffer): void {
		if (!this.handshakeFinished) {
			this.hash = sha256(Buffer.concat([this.hash, data]))
		}
	}

	encrypt(plaintext: Buffer): Buffer {
		const ciphertext = aesEncryptGCM(plaintext, this.encKey, generateIV(this.writeCounter), this.hash)

		this.writeCounter += 1
		this.authenticate(ciphertext)

		return ciphertext
	}

	decrypt(ciphertext: Buffer): Buffer {
		// Before finishInit, both directions share the write counter.
		const counter = this.handshakeFinished ? this.readCounter : this.writeCounter

		if (this.handshakeFinished) {
			this.readCounter += 1
		} else {
			this.writeCounter += 1
		}

		const plaintext = aesDecryptGCM(ciphertext, this.decKey, generateIV(counter), this.hash)

		this.authenticate(ciphertext)

		return plaintext
	}

	/** HKDF with the current salt, yielding two 32-byte keys. */
	private localHKDF(data: Buffer): [Buffer, Buffer] {
		const key = hkdf(data, 64, { salt: this.salt })

		return [key.subarray(0, 32), key.subarray(32)]
	}

	/** Absorbs a DH secret into the state, resetting the counters. */
	mixIntoKey(data: Buffer): void {
		const [write, read] = this.localHKDF(data)

		this.salt = write
		this.encKey = read
		this.decKey = read
		this.readCounter = 0
		this.writeCounter = 0
	}

	/**
	 * Final split: one key per direction, transcript discarded.
	 * One side's write key is the other side's read key.
	 */
	finishInit(): void {
		const [first, second] = this.localHKDF(Buffer.alloc(0))

		this.encKey = this.role === 'initiator' ? first : second
		this.decKey = this.role === 'initiator' ? second : first
		this.hash = Buffer.alloc(0)
		this.readCounter = 0
		this.writeCounter = 0
		this.handshakeFinished = true
	}

	/** Exposed for tests only: lets both sides' states be compared. */
	debugState(): { hash: string; salt: string; encKey: string; decKey: string } {
		return {
			hash: this.hash.toString('hex'),
			salt: this.salt.toString('hex'),
			encKey: this.encKey.toString('hex'),
			decKey: this.decKey.toString('hex'),
		}
	}
}
