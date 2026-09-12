import { aesDecryptGCM, aesEncryptGCM, hkdf, sha256 } from '../crypto/index.ts'

/**
 * Estado do Noise Protocol Framework, padrão `XX` com X25519 + AES-GCM + SHA-256.
 *
 * XX significa que nenhum dos lados conhece a chave estática do outro de
 * antemão: ambas são transmitidas durante o handshake. São três mensagens —
 * ClientHello, ServerHello, ClientFinish — e ao final o canal vira simétrico,
 * com uma chave por direção.
 *
 * Duas armadilhas que não aparecem na spec do Noise e sim no uso do WhatsApp:
 *
 * 1. Durante o handshake as duas direções compartilham o MESMO contador de
 *    nonce. Só depois de `finishInit()` cada direção passa a ter o seu.
 * 2. Todo ciphertext trocado entra no hash de transcrição (`authenticate`),
 *    inclusive o que você mesmo produziu.
 */

const NOISE_MODE = 'Noise_XX_25519_AESGCM_SHA256'

/** 'W', 'A', versão maior, versão do dicionário de tokens. */
export function makeWaHeader(dictVersion: number): Buffer {
	return Buffer.from([87, 65, 6, dictVersion])
}

function generateIV(counter: number): Buffer {
	const iv = Buffer.alloc(12)
	iv.writeUInt32BE(counter, 8)

	return iv
}

/**
 * Estado inicial do hash: se o nome do protocolo cabe em HASHLEN, ele é usado
 * cru com zero-padding; senão, usa-se o seu SHA-256 (Noise spec, §5.2).
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
 * `initiator` é o cliente. `responder` existe para testar o handshake contra um
 * servidor simulado — os dois lados compartilham toda a lógica e divergem só no
 * split final, onde as chaves trocam de direção.
 */
export type NoiseRole = 'initiator' | 'responder'

export type NoiseHandlerOptions = {
	/**
	 * Chave pública EFÊMERA do cliente. Importante: é a efêmera que entra no
	 * hash inicial, não a estática — a estática só aparece no ClientFinish.
	 * Os dois lados absorvem a MESMA chave (a do cliente) nesta posição.
	 */
	ephemeralPublic: Buffer
	/** Prólogo: o header WA, misturado no hash antes de tudo. */
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

	/** Mistura dados no hash de transcrição. Inerte após o handshake. */
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
		// Antes de finishInit as duas direções compartilham o contador de escrita.
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

	/** HKDF com o salt corrente, devolvendo duas chaves de 32 bytes. */
	private localHKDF(data: Buffer): [Buffer, Buffer] {
		const key = hkdf(data, 64, { salt: this.salt })

		return [key.subarray(0, 32), key.subarray(32)]
	}

	/** Absorve um segredo DH no estado, zerando os contadores. */
	mixIntoKey(data: Buffer): void {
		const [write, read] = this.localHKDF(data)

		this.salt = write
		this.encKey = read
		this.decKey = read
		this.readCounter = 0
		this.writeCounter = 0
	}

	/**
	 * Split final: uma chave por direção, transcrição descartada.
	 * O que é chave de escrita para um lado é de leitura para o outro.
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

	/** Exposto só para testes: permite comparar o estado dos dois lados. */
	debugState(): { hash: string; salt: string; encKey: string; decKey: string } {
		return {
			hash: this.hash.toString('hex'),
			salt: this.salt.toString('hex'),
			encKey: this.encKey.toString('hex'),
			decKey: this.decKey.toString('hex'),
		}
	}
}
