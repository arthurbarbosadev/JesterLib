import type { KeyPair } from '../crypto/index.ts'
import type { AuthenticationCreds } from './creds.ts'

/**
 * Armazenamento de chaves do Signal.
 *
 * A interface é deliberadamente estreita — `get` em lote e `set` em lote — para
 * que um adaptador em Supabase (ou Redis, ou disco) consiga implementá-la sem
 * round-trip por chave. O Signal em si ainda não está implementado; os tipos
 * abaixo já fixam o contrato para quando estiver.
 */

export type SignalDataTypeMap = {
	'pre-key': KeyPair
	session: Buffer
	'sender-key': Buffer
	'sender-key-memory': { [jid: string]: boolean }
	'app-state-sync-key': Buffer
	'app-state-sync-version': Buffer
}

export type SignalDataSet = {
	[T in keyof SignalDataTypeMap]?: { [id: string]: SignalDataTypeMap[T] | null }
}

export interface SignalKeyStore {
	get<T extends keyof SignalDataTypeMap>(
		type: T,
		ids: string[],
	): Promise<{ [id: string]: SignalDataTypeMap[T] }>

	/** `null` como valor remove a chave. */
	set(data: SignalDataSet): Promise<void>

	clear?(): Promise<void>
}

export type AuthenticationState = {
	creds: AuthenticationCreds
	keys: SignalKeyStore
}

/**
 * Store em memória. Serve para desenvolvimento e testes; em produção o estado
 * precisa sobreviver ao processo — veja `store/`.
 */
export function makeInMemoryKeyStore(
	initial: Record<string, Record<string, unknown>> = {},
): SignalKeyStore & { dump(): Record<string, Record<string, unknown>> } {
	const data: Record<string, Record<string, unknown>> = { ...initial }

	return {
		async get(type, ids) {
			const bucket = data[type] ?? {}
			const out: Record<string, never> = {}

			for (const id of ids) {
				if (bucket[id] !== undefined) {
					out[id] = bucket[id] as never
				}
			}

			return out
		},

		async set(update) {
			for (const [type, values] of Object.entries(update)) {
				const bucket = (data[type] ??= {})

				for (const [id, value] of Object.entries(values ?? {})) {
					if (value === null) {
						delete bucket[id]
					} else {
						bucket[id] = value
					}
				}
			}
		},

		async clear() {
			for (const key of Object.keys(data)) {
				delete data[key]
			}
		},

		dump() {
			return data
		},
	}
}
