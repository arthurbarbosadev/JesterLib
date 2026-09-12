import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { Curve, addKeyType } from '../src/crypto/curve.ts'
import {
	SIGNATURE_LENGTH,
	montgomeryToEdwardsPublic,
	xeddsaSign,
	xeddsaVerify,
} from '../src/crypto/xeddsa.ts'

test('assina e verifica', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const message = Buffer.from('mensagem para assinar')
	const signature = xeddsaSign(priv, message)

	assert.equal(signature.length, SIGNATURE_LENGTH)
	assert.equal(xeddsaVerify(pub, message, signature), true)
})

test('aceita chave pública com o byte de tipo 0x05', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const message = Buffer.from('prekey assinada')
	const signature = xeddsaSign(priv, message)

	assert.equal(xeddsaVerify(addKeyType(pub), message, signature), true)
})

test('rejeita mensagem alterada', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const signature = xeddsaSign(priv, Buffer.from('original'))

	assert.equal(xeddsaVerify(pub, Buffer.from('adulterada'), signature), false)
})

test('rejeita assinatura alterada', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const message = Buffer.from('mensagem')
	const signature = xeddsaSign(priv, message)

	for (const index of [0, 31, 32, 63]) {
		const tampered = Buffer.from(signature)
		tampered.writeUInt8(tampered.readUInt8(index) ^ 0x01, index)

		assert.equal(xeddsaVerify(pub, message, tampered), false, `byte ${index} não detectado`)
	}
})

test('rejeita assinatura de outra chave', () => {
	const a = Curve.generateKeyPair()
	const b = Curve.generateKeyPair()
	const message = Buffer.from('mensagem')

	assert.equal(xeddsaVerify(b.public, message, xeddsaSign(a.private, message)), false)
})

test('rejeita assinatura de tamanho errado', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const message = Buffer.from('m')
	const signature = xeddsaSign(priv, message)

	assert.equal(xeddsaVerify(pub, message, signature.subarray(0, 63)), false)
	assert.equal(xeddsaVerify(pub, message, Buffer.concat([signature, Buffer.alloc(1)])), false)
})

test('é determinístico dado o mesmo nonce, e randomizado sem ele', () => {
	const { private: priv } = Curve.generateKeyPair()
	const message = Buffer.from('mensagem')
	const nonce = Buffer.alloc(64, 7)

	assert.deepEqual(xeddsaSign(priv, message, nonce), xeddsaSign(priv, message, nonce))
	assert.notDeepEqual(xeddsaSign(priv, message), xeddsaSign(priv, message))
})

/**
 * Caminho de verificação independente: o mesmo cálculo feito pelo @noble, não
 * pelo OpenSSL. Se os dois concordam, o erro teria que estar nos dois ao mesmo
 * tempo — e eles não compartilham código.
 */
test('a assinatura também verifica no Ed25519 do @noble', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()
	const message = Buffer.from('checagem cruzada')
	const signature = xeddsaSign(priv, message)
	const edwards = montgomeryToEdwardsPublic(pub)

	assert.equal(ed25519.verify(signature, message, edwards), true)
})

/**
 * Fecha o ciclo Montgomery -> Edwards -> Montgomery usando a conversão do
 * @noble na volta. Valida que o mapa biracional está correto nos dois sentidos.
 */
test('conversão Montgomery <-> Edwards é consistente', () => {
	for (let i = 0; i < 20; i++) {
		const { public: montgomery } = Curve.generateKeyPair()
		const edwards = montgomeryToEdwardsPublic(montgomery)

		assert.deepEqual(Buffer.from(ed25519.utils.toMontgomery(edwards)), montgomery)
	}
})

/**
 * O bit de sinal da chave Edwards é 1 em ~metade das chaves. Se a negação do
 * escalar estiver faltando, metade dos casos falha — este laço garante que os
 * dois ramos são exercitados.
 */
test('funciona para os dois valores do bit de sinal', () => {
	let comSinal = 0
	let semSinal = 0

	for (let i = 0; i < 40; i++) {
		const { private: priv, public: pub } = Curve.generateKeyPair()
		const message = randomBytes(32)

		assert.equal(xeddsaVerify(pub, message, xeddsaSign(priv, message)), true)

		// reconstrói o ponto Edwards não normalizado para saber qual ramo caiu
		const scalar = Buffer.from(priv)
		scalar[0]! &= 248
		scalar[31]! &= 127
		scalar[31]! |= 64

		let k = 0n
		for (let j = 31; j >= 0; j--) {
			k = (k << 8n) | BigInt(scalar[j]!)
		}

		const encoded = ed25519.Point.BASE.multiply(k % ed25519.Point.CURVE().n).toBytes()

		if ((encoded[31]! >> 7) & 1) {
			comSinal++
		} else {
			semSinal++
		}
	}

	assert.ok(comSinal > 0, 'nenhuma chave com bit de sinal 1 foi testada')
	assert.ok(semSinal > 0, 'nenhuma chave com bit de sinal 0 foi testada')
})

test('mensagem vazia e mensagem longa', () => {
	const { private: priv, public: pub } = Curve.generateKeyPair()

	for (const message of [Buffer.alloc(0), randomBytes(100_000)]) {
		assert.equal(xeddsaVerify(pub, message, xeddsaSign(priv, message)), true)
	}
})
