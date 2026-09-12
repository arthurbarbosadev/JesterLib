import { createHash, createPublicKey, randomBytes, verify as nodeVerify } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { stripKeyType } from './curve.ts'

/**
 * XEdDSA sobre Curve25519 — assinar com uma chave X25519.
 *
 * O WhatsApp usa UM par de chaves para tudo: o mesmo Curve25519 faz ECDH e
 * assina (prekey assinada, identidade do dispositivo no pareamento). Ed25519 e
 * X25519 usam a mesma curva em formas diferentes (Edwards vs Montgomery), e o
 * XEdDSA é a ponte: converte a chave para a forma Edwards na hora de assinar.
 *
 * O Node expõe X25519 e Ed25519 nativos, mas não essa ponte — a API dele só
 * aceita uma *seed* Ed25519, que é hasheada para virar escalar. Aqui o escalar
 * Montgomery é usado diretamente, então a multiplicação de ponto precisa ser
 * feita na mão (via @noble/curves).
 *
 * A verificação, porém, é Ed25519 padrão: a equação `R == sB - hA` e o hash
 * `SHA512(R || A || M)` são idênticos. Por isso ela usa o verificador nativo do
 * Node — um caminho independente do código de assinatura, o que faz os testes
 * valerem de verdade.
 *
 * Referência: Signal, "The XEdDSA and VXEdDSA Signature Schemes".
 */

const CURVE = ed25519.Point.CURVE()

/** Primo do corpo (2^255 - 19) e ordem do grupo, lidos da própria curva. */
const P = CURVE.p
const Q = CURVE.n

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

/**
 * hash_1 do XEdDSA: SHA-512 com prefixo (2^256 - 2) em little-endian. O prefixo
 * separa este domínio do hash usado no cálculo de `h`, que não tem prefixo.
 */
const HASH1_PREFIX = Buffer.concat([Buffer.from([0xfe]), Buffer.alloc(31, 0xff)])

export const SIGNATURE_LENGTH = 64

function sha512(...parts: Buffer[]): Buffer {
	const hash = createHash('sha512')

	for (const part of parts) {
		hash.update(part)
	}

	return hash.digest()
}

function mod(a: bigint, m: bigint): bigint {
	const result = a % m

	return result >= 0n ? result : result + m
}

/** Inverso modular por Fermat — `m` é primo nos dois usos desta lib. */
function invert(a: bigint, m: bigint): bigint {
	if (a === 0n) {
		throw new Error('não existe inverso de zero')
	}

	let result = 1n
	let base = mod(a, m)
	let exp = m - 2n

	while (exp > 0n) {
		if (exp & 1n) {
			result = (result * base) % m
		}

		base = (base * base) % m
		exp >>= 1n
	}

	return result
}

function bytesToNumberLE(bytes: Uint8Array): bigint {
	let value = 0n

	for (let i = bytes.length - 1; i >= 0; i--) {
		value = (value << 8n) | BigInt(bytes[i]!)
	}

	return value
}

function numberToBytesLE(value: bigint, length: number): Buffer {
	const out = Buffer.alloc(length)
	let v = value

	for (let i = 0; i < length; i++) {
		out[i] = Number(v & 0xffn)
		v >>= 8n
	}

	return out
}

/**
 * Clamping do RFC 7748. O X25519 clampa internamente na hora de multiplicar, mas
 * aqui o escalar é usado direto na curva de Edwards — precisa vir clampado, ou a
 * chave pública derivada não bate com a do ECDH.
 */
function clamp(key: Buffer): Buffer {
	if (key.length !== 32) {
		throw new Error(`chave privada deve ter 32 bytes, recebido ${key.length}`)
	}

	const out = Buffer.from(key)
	out[0]! &= 248
	out[31]! &= 127
	out[31]! |= 64

	return out
}

/**
 * Deriva o par Edwards equivalente a um escalar Montgomery.
 *
 * A conversão zera o bit de sinal da chave pública; quando o ponto original
 * tinha sinal 1, o escalar é negado para compensar. Sem isso as assinaturas
 * saem inválidas em ~metade das chaves — um bug que só aparece de forma
 * intermitente.
 */
function calculateKeyPair(k: bigint): { publicKey: Buffer; scalar: bigint } {
	const point = ed25519.Point.BASE.multiply(mod(k, Q))
	const encoded = Buffer.from(point.toBytes())
	const signBit = (encoded[31]! >> 7) & 1

	encoded[31]! &= 0x7f

	return { publicKey: encoded, scalar: signBit === 1 ? mod(-k, Q) : mod(k, Q) }
}

/**
 * Converte a coordenada `u` (Montgomery) para `y` (Edwards): y = (u-1)/(u+1).
 * O bit de sinal fica zerado, como manda o XEdDSA.
 */
export function montgomeryToEdwardsPublic(montgomeryPublic: Buffer): Buffer {
	const u = mod(bytesToNumberLE(stripKeyType(montgomeryPublic)), P)

	if (u === P - 1n) {
		throw new Error('chave pública Montgomery inválida (u = -1)')
	}

	const y = mod((u - 1n) * invert(u + 1n, P), P)

	return numberToBytesLE(y, 32)
}

/**
 * Assina `message` com uma chave privada X25519.
 *
 * `nonce` existe só para testes determinísticos — em produção deixe vazio, que
 * 64 bytes aleatórios são sorteados. Diferente do Ed25519 puro, o XEdDSA é
 * randomizado: reusar um nonce com mensagens distintas vaza a chave privada.
 */
export function xeddsaSign(privateKey: Buffer, message: Buffer, nonce?: Buffer): Buffer {
	const k = bytesToNumberLE(clamp(privateKey))
	const { publicKey, scalar } = calculateKeyPair(k)

	const z = nonce ?? randomBytes(64)
	const r = mod(bytesToNumberLE(sha512(HASH1_PREFIX, numberToBytesLE(scalar, 32), message, z)), Q)

	if (r === 0n) {
		throw new Error('nonce degenerado; tente novamente')
	}

	const R = Buffer.from(ed25519.Point.BASE.multiply(r).toBytes())
	const h = mod(bytesToNumberLE(sha512(R, publicKey, message)), Q)
	const s = mod(r + h * scalar, Q)

	return Buffer.concat([R, numberToBytesLE(s, 32)])
}

/**
 * Verifica uma assinatura XEdDSA com o verificador Ed25519 nativo do Node.
 *
 * Isso é possível porque a equação de verificação é idêntica à do Ed25519 —
 * basta converter a chave pública para a forma Edwards.
 */
export function xeddsaVerify(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
	if (signature.length !== SIGNATURE_LENGTH) {
		return false
	}

	try {
		const edwards = montgomeryToEdwardsPublic(publicKey)

		const key = createPublicKey({
			key: Buffer.concat([ED25519_SPKI_PREFIX, edwards]),
			format: 'der',
			type: 'spki',
		})

		return nodeVerify(null, message, key, signature)
	} catch {
		return false
	}
}
