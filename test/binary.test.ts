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
 * Synthetic dictionary. The codec must not depend on the real table: all the
 * logic is exercised here, and the vendored table only needs to be in the right
 * order.
 */
const SINGLE = [
	null, // index 0 is LIST_EMPTY, never a token
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

test('simple node with no attributes and no content', () => {
	const node: BinaryNode = { tag: 'iq', attrs: {} }

	assert.deepEqual(roundTrip(node), node)
})

test('primary dictionary tokens cost 1 byte', () => {
	// listStart(1) + token('iq')  =>  LIST_8, 1, 1
	const encoded = encodeBinaryNodeBody({ tag: 'iq', attrs: {} })

	assert.deepEqual([...encoded], [TAGS.LIST_8, 1, 1])
})

test('secondary dictionary tokens cost 2 bytes', () => {
	const encoded = encodeBinaryNodeBody({ tag: 'zeta', attrs: {} })

	// dictionary 2, index 0
	assert.deepEqual([...encoded], [TAGS.LIST_8, 1, TAGS.DICTIONARY_2, 0])
})

test('attributes round-trip', () => {
	const node: BinaryNode = {
		tag: 'iq',
		attrs: { type: 'get', id: 'abc123', to: 's.whatsapp.net' },
	}

	assert.deepEqual(roundTrip(node), node)
})

test('nested children round-trip', () => {
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

test('binary content round-trips byte for byte', () => {
	const payload = Buffer.from('00ff10deadbeef', 'hex')
	const node: BinaryNode = { tag: 'message', attrs: {}, content: payload }
	const out = roundTrip(node)

	assert.ok(Buffer.isBuffer(out.content))
	assert.deepEqual(out.content, payload)
})

test('string content comes back as a UTF-8 Buffer', () => {
	// The wire does not distinguish text from binary in length-delimited fields,
	// so the decoder returns a Buffer and the caller decides. Guessing UTF-8 would
	// corrupt binary payloads that happen to be valid UTF-8.
	const text = 'hello, world — accented'
	const out = roundTrip({ tag: 'message', attrs: {}, content: text })

	assert.ok(Buffer.isBuffer(out.content))
	assert.equal((out.content as Buffer).toString('utf-8'), text)
})

test('attribute strings stay strings (attributes are always text)', () => {
	const node: BinaryNode = { tag: 'message', attrs: { id: 'hello — accented' } }

	assert.deepEqual(roundTrip(node), node)
})

test('a user JID uses JID_PAIR and comes back identical', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { to: '5511987654321@s.whatsapp.net' } }

	assert.deepEqual(roundTrip(node), node)
})

test('a JID with a device uses AD_JID and comes back identical', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { to: '5511987654321:3@s.whatsapp.net' } }
	const encoded = encodeBinaryNodeBody(node)

	assert.ok([...encoded].includes(TAGS.AD_JID), 'should have used AD_JID')
	assert.deepEqual(roundTrip(node), node)
})

test('a lid JID preserves its domain', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { to: '123456@lid', from: '99887766:5@lid' } }

	assert.deepEqual(roundTrip(node), node)
})

test('device 0 is the primary device and drops out of the canonical form', () => {
	const out = roundTrip({ tag: 'iq', attrs: { to: '123456:0@lid' } })

	assert.equal(out.attrs.to, '123456@lid')
})

test('a group JID round-trips', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { to: '120363001234567890@g.us' } }

	assert.deepEqual(roundTrip(node), node)
})

test('a long number becomes nibble-packed (2 chars per byte)', () => {
	const phone = '5511987654321'
	const encoded = encodeBinaryNodeBody({ tag: 'jester', attrs: {}, content: phone })

	// LIST_8, 2, token(jester), NIBBLE_8, lengthByte, ...bytes
	assert.equal(encoded[3], TAGS.NIBBLE_8)
	// 13 digits => 7 bytes with padding, and the length byte's high bit set
	assert.equal(encoded[4], 0x80 | 7)
	assert.equal(encoded.length, 5 + 7)
	assert.equal(decodeBinaryNodeBody(encoded).content, phone)
})

test('even-length nibble packing does not flag padding', () => {
	const even = '551198765432'
	const encoded = encodeBinaryNodeBody({ tag: 'jester', attrs: {}, content: even })

	assert.equal(encoded[4], 6)
	assert.equal(decodeBinaryNodeBody(encoded).content, even)
})

test('nibble packing accepts dots and hyphens', () => {
	const value = '2.3000.10-45'

	assert.equal(roundTrip({ tag: 'jester', attrs: {}, content: value }).content, value)
})

test('a hexadecimal string becomes hex-packed', () => {
	const value = 'DEADBEEF0123456789ABCDEF'
	const encoded = encodeBinaryNodeBody({ tag: 'jester', attrs: {}, content: value })

	assert.equal(encoded[3], TAGS.HEX_8)
	assert.equal(decodeBinaryNodeBody(encoded).content, value)
})

test('content over 255 bytes uses BINARY_20', () => {
	const payload = Buffer.alloc(5000, 0xab)
	const encoded = encodeBinaryNodeBody({ tag: 'message', attrs: {}, content: payload })

	assert.equal(encoded[3], TAGS.BINARY_20)
	assert.deepEqual(decodeBinaryNodeBody(encoded).content, payload)
})

test('content over 1 MiB uses BINARY_32', () => {
	const payload = Buffer.alloc((1 << 20) + 10, 0x01)
	const encoded = encodeBinaryNodeBody({ tag: 'message', attrs: {}, content: payload })

	assert.equal(encoded[3], TAGS.BINARY_32)
	assert.deepEqual(decodeBinaryNodeBody(encoded).content, payload)
})

test('more than 255 children uses LIST_16', () => {
	const content = Array.from({ length: 300 }, (_, i) => ({ tag: 'message', attrs: { id: String(i) } }))
	const node: BinaryNode = { tag: 'iq', attrs: {}, content }
	const encoded = encodeBinaryNodeBody(node)

	assert.equal(encoded[3], TAGS.LIST_16)
	assert.deepEqual(decodeBinaryNodeBody(encoded), node)
})

test('a full frame carries a zeroed flag byte', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { type: 'get' } }
	const frame = encodeBinaryNode(node)

	assert.equal(frame[0], 0)
	assert.deepEqual(decodeBinaryNode(frame), node)
})

test('a frame flagged 0x02 is inflated with zlib', () => {
	const node: BinaryNode = { tag: 'iq', attrs: { type: 'result', id: 'xyz' } }
	const body = encodeBinaryNodeBody(node)
	const frame = Buffer.concat([Buffer.from([0x02]), deflateSync(body)])

	assert.deepEqual(decodeBinaryNode(frame), node)
})

test('jidEncode and jidDecode agree', () => {
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

test('with no dictionary loaded the error is explicit', async () => {
	const { setTokenDictionary: set, getTokenDictionary } = await import('../src/binary/tokens.ts')

	set({ single: [null], double: [] })
	assert.throws(() => getTokenDictionary(), MissingTokenDictionaryError)

	// restore it for the remaining tests
	set({ single: SINGLE, double: DOUBLE })
})
