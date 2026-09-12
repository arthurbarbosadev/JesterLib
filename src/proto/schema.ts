import { ProtoReader, ProtoWriter, WireType, zigzagDecode, zigzagEncode } from './wire.ts'

/**
 * Camada declarativa sobre o wire format.
 *
 * Em vez de gerar código a partir de `.proto`, as mensagens são descritas como
 * objetos e o tipo TypeScript é inferido delas. Escrever `WAProto` à mão fica
 * viável e o schema serve de documentação do protocolo.
 */

export type ScalarType =
	| 'uint32' | 'uint64' | 'int32' | 'int64' | 'sint32' | 'sint64'
	| 'bool' | 'enum' | 'fixed32' | 'sfixed32' | 'fixed64' | 'sfixed64'
	| 'float' | 'double' | 'bytes' | 'string'

export type FieldType = ScalarType | MessageCodec<any> | (() => MessageCodec<any>)

export type FieldDef<T extends FieldType = FieldType, R extends boolean = boolean> = {
	id: number
	type: T
	repeated: R
}

export type FieldsShape = Record<string, FieldDef>

type ScalarValue<T> =
	T extends 'bytes' ? Buffer :
	T extends 'string' ? string :
	T extends 'bool' ? boolean :
	T extends 'uint64' | 'int64' | 'sint64' | 'fixed64' | 'sfixed64' ? bigint :
	number

type TypeOf<T> =
	T extends MessageCodec<infer U> ? U :
	T extends () => MessageCodec<infer U> ? U :
	ScalarValue<T>

export type Infer<S extends FieldsShape> = {
	[K in keyof S]?: S[K]['repeated'] extends true ? Array<TypeOf<S[K]['type']>> : TypeOf<S[K]['type']>
}

export type MessageCodec<T> = {
	readonly name: string
	readonly fields: FieldsShape
	encode(value: T): Buffer
	decode(buf: Buffer): T
}

/** Campo singular. */
export function f<T extends FieldType>(id: number, type: T): FieldDef<T, false> {
	return { id, type, repeated: false }
}

/** Campo `repeated`. */
export function r<T extends FieldType>(id: number, type: T): FieldDef<T, true> {
	return { id, type, repeated: true }
}

function resolve(type: FieldType): ScalarType | MessageCodec<any> {
	return typeof type === 'function' ? type() : type
}

const VARINT_TYPES = new Set<string>(['uint32', 'uint64', 'int32', 'int64', 'bool', 'enum'])
const ZIGZAG_TYPES = new Set<string>(['sint32', 'sint64'])
const FIXED32_TYPES = new Set<string>(['fixed32', 'sfixed32', 'float'])
const FIXED64_TYPES = new Set<string>(['fixed64', 'sfixed64', 'double'])

function wireTypeOf(type: ScalarType | MessageCodec<any>): number {
	if (typeof type !== 'string') {
		return WireType.LENGTH_DELIMITED
	}

	if (VARINT_TYPES.has(type) || ZIGZAG_TYPES.has(type)) {
		return WireType.VARINT
	}

	if (FIXED32_TYPES.has(type)) {
		return WireType.FIXED32
	}

	if (FIXED64_TYPES.has(type)) {
		return WireType.FIXED64
	}

	return WireType.LENGTH_DELIMITED
}

function writeValue(w: ProtoWriter, type: ScalarType | MessageCodec<any>, value: unknown): void {
	if (typeof type !== 'string') {
		w.bytes(type.encode(value))
		return
	}

	switch (type) {
		case 'bytes':
			w.bytes(value as Buffer)
			break
		case 'string':
			w.string(value as string)
			break
		case 'sint32':
		case 'sint64':
			w.varint(zigzagEncode(value as number))
			break
		case 'float':
			w.float(value as number)
			break
		case 'double':
			w.double(value as number)
			break
		case 'fixed32':
		case 'sfixed32':
			w.fixed32(value as number)
			break
		case 'fixed64':
		case 'sfixed64':
			w.fixed64(value as number | bigint)
			break
		default:
			w.varint(value as number)
	}
}

function readValue(rd: ProtoReader, type: ScalarType | MessageCodec<any>, wireType: number): unknown {
	if (typeof type !== 'string') {
		return type.decode(rd.bytes())
	}

	switch (type) {
		case 'bytes':
			return Buffer.from(rd.bytes())
		case 'string':
			return rd.bytes().toString('utf-8')
		case 'bool':
			return rd.varint() !== 0n
		case 'uint64':
		case 'int64':
		case 'fixed64':
		case 'sfixed64':
			return wireType === WireType.FIXED64 ? rd.fixed64() : rd.varint()
		case 'sint32':
			return Number(zigzagDecode(rd.varint()))
		case 'sint64':
			return zigzagDecode(rd.varint())
		case 'int32': {
			// int32 negativo é serializado em 64 bits; reinterpreta com sinal.
			const v = BigInt.asIntN(64, rd.varint())
			return Number(v)
		}
		case 'float':
			return rd.float()
		case 'double':
			return rd.double()
		case 'fixed32':
			return rd.fixed32()
		case 'sfixed32':
			return rd.fixed32() | 0
		default:
			return rd.varintNumber()
	}
}

export function defineMessage<S extends FieldsShape>(name: string, fields: S): MessageCodec<Infer<S>> {
	// Índice reverso (fieldNumber -> campo) montado uma vez por mensagem.
	let byId: Map<number, { key: string; def: FieldDef }> | undefined

	const index = () => {
		if (!byId) {
			byId = new Map()

			for (const [key, def] of Object.entries(fields)) {
				byId.set(def.id, { key, def })
			}
		}

		return byId
	}

	return {
		name,
		fields,

		encode(value: Infer<S>): Buffer {
			const w = new ProtoWriter()

			for (const [key, def] of Object.entries(fields)) {
				const raw = (value as Record<string, unknown>)[key]

				if (raw === undefined || raw === null) {
					continue
				}

				const type = resolve(def.type)
				const wt = wireTypeOf(type)

				if (def.repeated) {
					for (const item of raw as unknown[]) {
						w.tag(def.id, wt)
						writeValue(w, type, item)
					}
				} else {
					w.tag(def.id, wt)
					writeValue(w, type, raw)
				}
			}

			return w.finish()
		},

		decode(buf: Buffer): Infer<S> {
			const rd = new ProtoReader(buf)
			const out: Record<string, unknown> = {}
			const map = index()

			for (const [fieldNumber, wireType] of rd.fields()) {
				const entry = map.get(fieldNumber)

				if (!entry) {
					rd.skip(wireType)
					continue
				}

				const type = resolve(entry.def.type)

				if (entry.def.repeated) {
					const list = (out[entry.key] ??= []) as unknown[]

					// Campos escalares `repeated` podem vir packed em um único bloco.
					if (typeof type === 'string' && wireType === WireType.LENGTH_DELIMITED && wireTypeOf(type) !== WireType.LENGTH_DELIMITED) {
						const packed = rd.bytes()
						const inner = new ProtoReader(packed)

						while (!inner.eof) {
							list.push(readValue(inner, type, wireTypeOf(type)))
						}
					} else {
						list.push(readValue(rd, type, wireType))
					}
				} else {
					out[entry.key] = readValue(rd, type, wireType)
				}
			}

			return out as Infer<S>
		},
	}
}
