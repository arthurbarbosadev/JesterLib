import assert from 'node:assert/strict'
import { deflateSync } from 'node:zlib'
import { before, test } from 'node:test'
import { TAGS } from '../src/binary/constants.ts'
import { decodeBinaryNode, decodeBinaryNodeBody } from '../src/binary/decode.ts'
import { encodeBinaryNode, encodeBinaryNodeBody } from '../src/binary/encode.ts'
import { jidDecode, jidEncode } from '../src/binary/jid.ts'
import type { BinaryNode } from '../src/binary/node.ts'
import { MissingTokenDictionaryError, setTokenDictionary } from '../src/binary/tokens.ts'

/**
 * Dicionário sintético. O codec não pode depender da tabela real: toda a lógica
 * é exercitada aqui, e a tabela vendorizada só precisa estar correta em ordem.
 */
const SINGLE = [
	null, // índice 0 é LIST_EMPTY, nunca um token
	'iq',
	'to',
	'from',
	'type',
	'get',
	'set',
	'result',
	'message',
	'id',
	's.whatsapp.net',
	'g.us',
	'jester',
]

const DOUBLE = [
	['alpha', 'beta', 'gamma'],
	['delta', 'epsilon'],
	['zeta'],
	['eta', 'theta'],
]

before(() => {
	setTokenDictionary({ single: SINGLE, double: DOUBLE })
})

function roundTrip(node: BinaryNode): BinaryNode {
	return decodeBinaryNodeBody(encodeBinaryNodeBody(node))
}

test('nó simples sem atributos nem conteúdo', () => {
	const node: BinaryNode = { tag: 'iq', attrs: {} }

	assert.deepEqual(roundTrip(node), node)
})

test('tokens do dicionário primário gastam 1 byte', () => {
	// listStart(1) + token('iq')  =>  LIST_8, 1, 1
	const encoded = encodeBinaryNodeBody({ tag: 'iq', attrs: {} })

	assert.deepEqual([...encoded], [TAGS.LIST_8, 1, 1])
})

test('tokens do dicionário secundário gastam 2 bytes', () => {
	const encoded = encodeBinaryNodeBody({ tag: 'zeta', attrs: {} })

	// dicionário 2, índice 0
	assert.deepEqual([...encoded], [TAGS.LIST_8, 1, TAGS.DICTIONARY_2, 0])
})

test('atributos fazem round-trip', () => {
	const node: BinaryNode = {
		tag: 'iq',
		attrs: { type: 'get', id: 'abc123', to: 's.whatsapp.net' },
	}

	assert.deepEqual(roundTrip(node), node)
})

test('filhos aninhados fazem round-trip', () => {
	const node: BinaryNode = {
		tag: 'iq',
		attrs: { type: 'set' },
		content: [
			{ tag: 'message', attrs: { id: '1' } },
			{ tag: 'message', attrs: { id: '2' }, content: [{ tag: 'jester', attrs: {} }] },
		],
	}

	assert.deepEqual(roundTrip(node), node)
})

test('conteúdo binário faz round-trip preservando bytes', () => {
	const payload = Buffer.from('00ff10deadbeef', 'hex')
	const node: BinaryNode = { tag: 'message', attrs: {}, content: payload }
	const out = roundTrip(node)

	assert.ok(Buffer.isBuffer(out.content))
	assert.deepEqual(out.content, payload)
})

test('conteúdo string volta como Buffer UTF-8', () => {
	// A wire não distingue texto de binário em campos length-delimited, então o
	// decoder devolve Buffer e quem consome decide. Adivinhar UTF-8 corromperia
	// payloads binários que por acaso são UTF-8 válido.
	const text = 'olá, mundo — acentuado'
	const out = roundTrip({ tag: 'message', attrs: {}, content: text })

	assert.ok(Buffer.isBuffer(out.content))
	assert.equal((out.content as Buffer).toString('utf-8'), text)
})

test('string em atributo continua string (atributos são sempre texto)', () => {
	const node: BinaryNode = { tag: 'message', attrs: { id: 'olá — acentuado' } }

	assert.deepEqual(roundTrip(node), node)
})

test('JID de usuário usa JID_PAIR e volta idêntico', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { to: '5511987654321@s.whatsapp.net' } }

	assert.deepEqual(roundTrip(node), node)
})

test('JID com device usa AD_JID e volta idêntico', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { to: '5511987654321:3@s.whatsapp.net' } }
	const encoded = encodeBinaryNodeBody(node)

	assert.ok([...encoded].includes(TAGS.AD_JID), 'deveria usar AD_JID')
	assert.deepEqual(roundTrip(node), node)
})

test('JID em lid preserva o domínio', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { to: '123456@lid', from: '99887766:5@lid' } }

	assert.deepEqual(roundTrip(node), node)
})

test('device 0 é o aparelho primário e some da forma canônica', () => {
	const out = roundTrip({ tag: 'iq', attrs: { to: '123456:0@lid' } })

	assert.equal(out.attrs.to, '123456@lid')
})

test('JID de grupo faz round-trip', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { to: '120363001234567890@g.us' } }

	assert.deepEqual(roundTrip(node), node)
})

test('número longo vira nibble packed (2 chars por byte)', () => {
	const phone = '5511987654321'
	const encoded = encodeBinaryNodeBody({ tag: 'jester', attrs: {}, content: phone })

	// LIST_8, 2, token(jester), NIBBLE_8, lengthByte, ...bytes
	assert.equal(encoded[3], TAGS.NIBBLE_8)
	// 13 dígitos => 7 bytes com padding, e o bit alto do tamanho ligado
	assert.equal(encoded[4], 0x80 | 7)
	assert.equal(encoded.length, 5 + 7)
	assert.equal(decodeBinaryNodeBody(encoded).content, phone)
})

test('nibble packed de tamanho par não marca padding', () => {
	const even = '551198765432'
	const encoded = encodeBinaryNodeBody({ tag: 'jester', attrs: {}, content: even })

	assert.equal(encoded[4], 6)
	assert.equal(decodeBinaryNodeBody(encoded).content, even)
})

test('nibble aceita ponto e hífen', () => {
	const value = '2.3000.10-45'

	assert.equal(roundTrip({ tag: 'jester', attrs: {}, content: value }).content, value)
})

test('string hexadecimal vira hex packed', () => {
	const value = 'DEADBEEF0123456789ABCDEF'
	const encoded = encodeBinaryNodeBody({ tag: 'jester', attrs: {}, content: value })

	assert.equal(encoded[3], TAGS.HEX_8)
	assert.equal(decodeBinaryNodeBody(encoded).content, value)
})

test('conteúdo acima de 255 bytes usa BINARY_20', () => {
	const payload = Buffer.alloc(5000, 0xab)
	const encoded = encodeBinaryNodeBody({ tag: 'message', attrs: {}, content: payload })

	assert.equal(encoded[3], TAGS.BINARY_20)
	assert.deepEqual(decodeBinaryNodeBody(encoded).content, payload)
})

test('conteúdo acima de 1 MiB usa BINARY_32', () => {
	const payload = Buffer.alloc((1 << 20) + 10, 0x01)
	const encoded = encodeBinaryNodeBody({ tag: 'message', attrs: {}, content: payload })

	assert.equal(encoded[3], TAGS.BINARY_32)
	assert.deepEqual(decodeBinaryNodeBody(encoded).content, payload)
})

test('mais de 255 filhos usa LIST_16', () => {
	const content = Array.from({ length: 300 }, (_, i) => ({ tag: 'message', attrs: { id: String(i) } }))
	const node: BinaryNode = { tag: 'iq', attrs: {}, content }
	const encoded = encodeBinaryNodeBody(node)

	assert.equal(encoded[3], TAGS.LIST_16)
	assert.deepEqual(decodeBinaryNodeBody(encoded), node)
})

test('frame completo carrega byte de flag zerado', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { type: 'get' } }
	const frame = encodeBinaryNode(node)

	assert.equal(frame[0], 0)
	assert.deepEqual(decodeBinaryNode(frame), node)
})

test('frame com flag 0x02 é descomprimido com zlib', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { type: 'result', id: 'xyz' } }
	const body = encodeBinaryNodeBody(node)
	const frame = Buffer.concat([Buffer.from([0x02]), deflateSync(body)])

	assert.deepEqual(decodeBinaryNode(frame), node)
})

test('jidEncode / jidDecode são coerentes', () => {
	assert.deepEqual(jidDecode('5511987654321@s.whatsapp.net'), {
		user: '5511987654321',
		server: 's.whatsapp.net',
	})
	assert.deepEqual(jidDecode('5511987654321:12@s.whatsapp.net'), {
		user: '5511987654321',
		server: 's.whatsapp.net',
		device: 12,
	})
	assert.equal(jidEncode('5511987654321', 's.whatsapp.net'), '5511987654321@s.whatsapp.net')
	assert.equal(jidEncode('5511987654321', 's.whatsapp.net', 12), '5511987654321:12@s.whatsapp.net')
	assert.equal(jidDecode('sem-arroba'), undefined)
})

test('sem dicionário carregado o erro é explícito', async () => {
	const { setTokenDictionary: set, getTokenDictionary } = await import('../src/binary/tokens.ts')

	set({ single: [null], double: [] })
	assert.throws(() => getTokenDictionary(), MissingTokenDictionaryError)

	// restaura para os demais testes
	set({ single: SINGLE, double: DOUBLE })
})
