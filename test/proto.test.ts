import assert from 'node:assert/strict'
import { test } from 'node:test'
import { defineMessage, f, r } from '../src/proto/schema.ts'
import { ProtoReader, ProtoWriter } from '../src/proto/wire.ts'

test('varint bate com o exemplo canônico do protobuf (150 -> 08 96 01)', () => {
	const w = new ProtoWriter()
	w.tag(1, 0).varint(150)

	assert.equal(w.finish().toString('hex'), '089601')
	assert.equal(new ProtoReader(Buffer.from('9601', 'hex')).varintNumber(), 150)
})

test('string length-delimited bate com o exemplo canônico', () => {
	const Msg = defineMessage('Test2', { b: f(2, 'string') })

	assert.equal(Msg.encode({ b: 'testing' }).toString('hex'), '120774657374696e67')
	assert.deepEqual(Msg.decode(Buffer.from('120774657374696e67', 'hex')), { b: 'testing' })
})

const Inner = defineMessage('Inner', {
	value: f(1, 'string'),
	flag: f(2, 'bool'),
})

const Outer = defineMessage('Outer', {
	id: f(1, 'uint32'),
	big: f(2, 'uint64'),
	blob: f(3, 'bytes'),
	inner: f(4, Inner),
	tags: r(5, 'string'),
	numbers: r(6, 'uint32'),
	signed: f(7, 'sint32'),
	negative: f(8, 'int32'),
})

test('round-trip completo com aninhamento e repeated', () => {
	const value = {
		id: 42,
		big: 18446744073709551615n,
		blob: Buffer.from('deadbeef', 'hex'),
		inner: { value: 'oi', flag: true },
		tags: ['a', 'b', 'c'],
		numbers: [1, 300, 70000],
		signed: -12345,
		negative: -7,
	}

	assert.deepEqual(Outer.decode(Outer.encode(value)), value)
})

test('campos ausentes não são serializados', () => {
	assert.equal(Outer.encode({ id: 1 }).toString('hex'), '0801')
	assert.deepEqual(Outer.decode(Buffer.from('0801', 'hex')), { id: 1 })
})

test('campos desconhecidos são ignorados sem quebrar o stream', () => {
	// campo 99 (varint) + campo 1 (varint) — o 99 não existe no schema
	const buf = Buffer.concat([Buffer.from('98069601', 'hex'), Buffer.from('0801', 'hex')])

	assert.deepEqual(Outer.decode(buf), { id: 1 })
})

test('repeated escalar aceita codificação packed', () => {
	// campo 6 como length-delimited contendo 3 varints: 1, 300, 70000
	const packed = Buffer.from('3206' + '01' + 'ac02' + 'f0a204', 'hex')

	assert.deepEqual(Outer.decode(packed), { numbers: [1, 300, 70000] })
})

test('mensagens auto-referenciadas funcionam via lazy', () => {
	type Node = { name?: string; child?: Node }
	const Node: ReturnType<typeof defineMessage<{ name: any; child: any }>> = defineMessage('Node', {
		name: f(1, 'string'),
		child: f(2, () => Node),
	})

	const value = { name: 'a', child: { name: 'b', child: { name: 'c' } } }
	assert.deepEqual(Node.decode(Node.encode(value)) as Node, value)
})
