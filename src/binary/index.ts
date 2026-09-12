import { VENDORED_TOKENS } from './tokens.generated.ts'
import { setTokenDictionary } from './tokens.ts'

export * from './constants.ts'
export * from './jid.ts'
export * from './node.ts'
export * from './tokens.ts'
export * from './encode.ts'
export * from './decode.ts'

/**
 * Registra a tabela vendorizada. Se ainda for o placeholder, nada acontece
 * aqui — o erro só aparece (com instruções) na primeira codificação.
 */
export function loadVendoredTokens(): boolean {
	if (VENDORED_TOKENS.single.length <= 1) {
		return false
	}

	setTokenDictionary(VENDORED_TOKENS)

	return true
}

loadVendoredTokens()
