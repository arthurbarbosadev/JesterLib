import { Curve, type KeyPair } from '../crypto/index.ts'
import { CertChain, HandshakeMessage, NoiseCertificateDetails } from '../proto/wa.ts'
import type { NoiseHandler } from './handler.ts'

/**
 * Driver for the Noise XX pattern, client side.
 *
 *   -> e                          (ClientHello)
 *   <- e, ee, s, es               (ServerHello)
 *   -> s, se                      (ClientFinish + ClientPayload)
 *
 * Each token on the right is a DH that feeds into the key. Order matters:
 * swapping two `mixIntoKey` calls produces different keys, and the server just
 * drops the connection without saying why.
 */

/** Expected issuer serial of WhatsApp's intermediate certificate. */
const EXPECTED_ISSUER_SERIAL = 0

export type HandshakeContext = {
	noise: NoiseHandler
	/** This connection's ephemeral key pair — discarded at the end. */
	ephemeral: KeyPair
	/** Static key pair persisted in the credentials (`creds.noiseKey`). */
	staticKey: KeyPair
}

export class HandshakeError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'HandshakeError'
	}
}

/** Message 1: `-> e`. The hash already absorbed the ephemeral key in the handler's constructor. */
export function createClientHello(ephemeral: KeyPair): Buffer {
	return HandshakeMessage.encode({ clientHello: { ephemeral: ephemeral.public } })
}

/**
 * Validates the certificate chain sent by the server.
 *
 * Note: this only checks the issuer serial, which is what the reference
 * implementations do as well. The cryptographic verification of the signature
 * against WhatsApp's root key is NOT performed here — on a hostile network that
 * would leave room for MITM. It is isolated in this function so it can be
 * hardened without touching the rest of the handshake.
 */
export function validateServerCertificate(certPayload: Buffer): void {
	const chain = CertChain.decode(certPayload)
	const intermediate = chain.intermediate

	if (!intermediate?.details) {
		throw new HandshakeError('certificate chain has no intermediate certificate')
	}

	const details = NoiseCertificateDetails.decode(intermediate.details)

	if (details.issuerSerial !== EXPECTED_ISSUER_SERIAL) {
		throw new HandshakeError(
			`unexpected issuer serial: ${details.issuerSerial} (expected ${EXPECTED_ISSUER_SERIAL})`,
		)
	}
}

/**
 * Messages 2 and 3: consumes the ServerHello and returns the ClientFinish frame.
 *
 * On return the channel is already in transport mode (`finishInit` has been
 * called) and all following traffic is encrypted WABinary.
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
		throw new HandshakeError('incomplete ServerHello — did the server reject the ClientHello?')
	}

	// <- e
	noise.authenticate(serverHello.ephemeral)

	// ee: client ephemeral x server ephemeral
	noise.mixIntoKey(Curve.sharedKey(ephemeral.private, serverHello.ephemeral))

	// s: the server's static key arrives encrypted under the key derived from `ee`
	const serverStatic = noise.decrypt(serverHello.static)

	// es: client ephemeral x server static
	noise.mixIntoKey(Curve.sharedKey(ephemeral.private, serverStatic))

	// The ServerHello payload is the certificate chain
	const certPayload = noise.decrypt(serverHello.payload)

	if (opts.validateCertificate !== false) {
		validateServerCertificate(certPayload)
	}

	// -> s: the client's static key, encrypted
	const encryptedStatic = noise.encrypt(staticKey.public)

	// se: client static x server ephemeral
	noise.mixIntoKey(Curve.sharedKey(staticKey.private, serverHello.ephemeral))

	const encryptedPayload = noise.encrypt(clientPayload)

	const finish = HandshakeMessage.encode({
		clientFinish: { static: encryptedStatic, payload: encryptedPayload },
	})

	noise.finishInit()

	return finish
}
