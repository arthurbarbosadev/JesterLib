import { VENDORED_TOKENS } from './tokens.generated.ts'

/**
 * WABinary token dictionary.
 *
 * The protocol replaces frequent strings ("message", "from", "s.whatsapp.net"…)
 * with 1- or 2-byte indexes. This is *data*, not logic: the table lives in the
 * WhatsApp Web bundle and changes between versions. A single token out of order
 * shifts every token after it and the stream breaks silently — the server just
 * closes the connection, with no readable error.
 *
 * That is why the table is not written by hand: it is extracted with
 * `npm run vendor:tokens`, which writes `tokens.generated.ts`. The whole codec
 * in this module is independent of the table and is tested against a synthetic
 * dictionary.
 */

export type TokenDictionary = {
	/** Index 0 is reserved (LIST_EMPTY); usable tokens start at 1. */
	single: readonly (string | null)[]
	/** Four secondary dictionaries, addressed by DICTIONARY_0..3. */
	double: readonly (readonly string[])[]
}

type LoadedDictionary = TokenDictionary & {
	singleIndex: ReadonlyMap<string, number>
	doubleIndex: ReadonlyMap<string, readonly [number, number]>
}

let loaded: LoadedDictionary | undefined
/** Guards the one-time attempt to pick up the vendored table. */
let vendoredTried = false

/**
 * Registers the vendored table the first time the dictionary is needed.
 *
 * This lives here, not in the module barrel, because nothing inside the library
 * imports the barrel — `decode.ts` reaches for this module directly. Putting the
 * auto-load anywhere else means it silently never runs, and the first real
 * connection fails after a perfectly good handshake.
 *
 * The import is dynamic-free and safe: tokens.generated.ts only imports a *type*
 * from here, so there is no runtime cycle.
 */
function loadVendored(): void {
	// An explicit setTokenDictionary() wins — tests install a synthetic table on
	// purpose, and overwriting it here would make them exercise the real one.
	if (vendoredTried || loaded) {
		return
	}

	vendoredTried = true

	if (VENDORED_TOKENS.single.length > 1) {
		setTokenDictionary(VENDORED_TOKENS)
	}
}

export class MissingTokenDictionaryError extends Error {
	constructor() {
		super(
			'WABinary token dictionary is not loaded.\n' +
				'Run `npm run vendor:tokens` to generate src/binary/tokens.generated.ts, ' +
				'or call setTokenDictionary() manually before encoding/decoding.',
		)
		this.name = 'MissingTokenDictionaryError'
	}
}

export function setTokenDictionary(dict: TokenDictionary): void {
	const singleIndex = new Map<string, number>()

	for (let i = 0; i < dict.single.length; i++) {
		const token = dict.single[i]

		// First occurrence wins: lower indexes cost fewer bytes.
		if (token && !singleIndex.has(token)) {
			singleIndex.set(token, i)
		}
	}

	const doubleIndex = new Map<string, readonly [number, number]>()

	for (let d = 0; d < dict.double.length; d++) {
		const sub = dict.double[d] ?? []

		for (let i = 0; i < sub.length; i++) {
			const token = sub[i]

			if (token && !doubleIndex.has(token) && !singleIndex.has(token)) {
				doubleIndex.set(token, [d, i])
			}
		}
	}

	loaded = { ...dict, singleIndex, doubleIndex }
}

export function hasTokenDictionary(): boolean {
	loadVendored()

	return loaded !== undefined && loaded.single.length > 1
}

export function getTokenDictionary(): LoadedDictionary {
	loadVendored()

	if (!loaded || loaded.single.length <= 1) {
		throw new MissingTokenDictionaryError()
	}

	return loaded
}

/** The 1-byte index for a token, if it is in the primary dictionary. */
export function lookupSingleToken(token: string): number | undefined {
	return getTokenDictionary().singleIndex.get(token)
}

/** The (dictionary, index) pair for a token in a secondary dictionary. */
export function lookupDoubleToken(token: string): readonly [number, number] | undefined {
	return getTokenDictionary().doubleIndex.get(token)
}

export function singleTokenAt(index: number): string {
	const token = getTokenDictionary().single[index]

	if (token === null || token === undefined) {
		throw new Error(`invalid primary token at index ${index}`)
	}

	return token
}

export function doubleTokenAt(dictionary: number, index: number): string {
	const sub = getTokenDictionary().double[dictionary]

	if (!sub) {
		throw new Error(`secondary dictionary ${dictionary} does not exist`)
	}

	const token = sub[index]

	if (token === undefined) {
		throw new Error(`invalid token in dictionary ${dictionary} at index ${index}`)
	}

	return token
}

/** Number of primary tokens — defines where the token-tag range ends. */
export function singleTokenCount(): number {
	return getTokenDictionary().single.length
}
