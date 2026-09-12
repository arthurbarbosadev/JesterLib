import { Curve, type KeyPair } from '../crypto/index.ts'
import { CertChain, HandshakeMessage, NoiseCertificateDetails } from '../proto/wa.ts'
import type { NoiseHandler } from './handler.ts'

/**
 * Driver do padrão Noise XX, lado cliente.
 *
 *   -> e                          (ClientHello)
 *   <- e, ee, s, es               (ServerHello)
 *   -> s, se                      (ClientFinish + ClientPayload)
 *
 * Cada token da direita é um DH que entra na chave. A ordem importa: trocar
 * dois `mixIntoKey` produz chaves diferentes e o servidor só derruba a conexão,
 * sem dizer o motivo.
 */

/** Serial esperado do emissor do certificado intermediário do WhatsApp. */
const EXPECTED_ISSUER_SERIAL = 0

export type HandshakeContext = {
	noise: NoiseHandler
	/** Par efêmero desta conexão — descartado ao final. */
	ephemeral: KeyPair
	/** Par estático persistido nas credenciais (`creds.noiseKey`). */
	staticKey: KeyPair
}

export class HandshakeError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'HandshakeError'
	}
}

/** Mensagem 1: `-> e`. O hash já absorveu a efêmera no construtor do handler. */
export function createClientHello(ephemeral: KeyPair): Buffer {
	return HandshakeMessage.encode({ clientHello: { ephemeral: ephemeral.public } })
}

/**
 * Valida a cadeia de certificados enviada pelo servidor.
 *
 * Atenção: isto confere apenas o serial do emissor, que é o mesmo que as
 * implementações de referência fazem. A verificação criptográfica da assinatura
 * contra a chave raiz do WhatsApp NÃO é feita aqui — em uma rede hostil isso
 * deixaria espaço para MITM. Está isolado nesta função para poder ser
 * endurecido sem tocar no resto do handshake.
 */
export function validateServerCertificate(certPayload: Buffer): void {
	const chain = CertChain.decode(certPayload)
	const intermediate = chain.intermediate

	if (!intermediate?.details) {
		throw new HandshakeError('cadeia de certificados sem certificado intermediário')
	}

	const details = NoiseCertificateDetails.decode(intermediate.details)

	if (details.issuerSerial !== EXPECTED_ISSUER_SERIAL) {
		throw new HandshakeError(
			`serial do emissor inesperado: ${details.issuerSerial} (esperado ${EXPECTED_ISSUER_SERIAL})`,
		)
	}
}

/**
 * Mensagens 2 e 3: consome o ServerHello e devolve o frame do ClientFinish.
 *
 * Ao retornar, o canal já está em modo transporte (`finishInit` foi chamado) e
 * todo tráfego seguinte é WABinary cifrado.
 */
export function completeHandshake(
	ctx: HandshakeContext,
	serverHelloFrame: Buffer,
	clientPayload: Buffer,
	opts: { validateCertificate?: boolean } = {},
): Buffer {
	const { noise, ephemeral, staticKey } = ctx
	const { serverHello } = HandshakeMessage.decode(serverHelloFrame)

	if (!serverHello?.ephemeral || !serverHello.static || !serverHello.payload) {
		throw new HandshakeError('ServerHello incompleto — o servidor rejeitou o ClientHello?')
	}

	// <- e
	noise.authenticate(serverHello.ephemeral)

	// ee: efêmera do cliente x efêmera do servidor
	noise.mixIntoKey(Curve.sharedKey(ephemeral.private, serverHello.ephemeral))

	// s: a estática do servidor vem cifrada com a chave derivada de `ee`
	const serverStatic = noise.decrypt(serverHello.static)

	// es: efêmera do cliente x estática do servidor
	noise.mixIntoKey(Curve.sharedKey(ephemeral.private, serverStatic))

	// O payload do ServerHello é a cadeia de certificados
	const certPayload = noise.decrypt(serverHello.payload)

	if (opts.validateCertificate !== false) {
		validateServerCertificate(certPayload)
	}

	// -> s: a estática do cliente, cifrada
	const encryptedStatic = noise.encrypt(staticKey.public)

	// se: estática do cliente x efêmera do servidor
	noise.mixIntoKey(Curve.sharedKey(staticKey.private, serverHello.ephemeral))

	const encryptedPayload = noise.encrypt(clientPayload)

	const finish = HandshakeMessage.encode({
		clientFinish: { static: encryptedStatic, payload: encryptedPayload },
	})

	noise.finishInit()

	return finish
}
