import type { KeyPair } from '../crypto/index.ts'
import type { AuthenticationCreds } from './creds.ts'

/**
 * Signal key storage.
 *
 * The interface is deliberately narrow — batched `get` and batched `set` — so a
 * Supabase (or Redis, or disk) adapter can implement it without a round-trip
 * per key. Signal itself is not implemented yet; the types below already pin
 * down the contract for when it is.
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

	/** A `null` value deletes the key. */
	set(data: SignalDataSet): Promise<void>

	clear?(): Promise<void>
}

export type AuthenticationState = {
	creds: AuthenticationCreds
	keys: SignalKeyStore
}

/**
 * In-memory store. Fine for development and tests; in production the state
 * needs to outlive the process — see `store/`.
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
