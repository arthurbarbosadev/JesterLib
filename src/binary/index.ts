import { VENDORED_TOKENS } from './tokens.generated.ts'
import { setTokenDictionary } from './tokens.ts'

export * from './constants.ts'
export * from './jid.ts'
export * from './node.ts'
export * from './tokens.ts'
export * from './encode.ts'
export * from './decode.ts'

/**
 * Registers the vendored table. If it is still the placeholder, nothing
 * happens here — the error surfaces (with instructions) on the first encode.
 */
export function loadVendoredTokens(): boolean {
	if (VENDORED_TOKENS.single.length <= 1) {
		return false
	}

	setTokenDictionary(VENDORED_TOKENS)

	return true
}

loadVendoredTokens()
