/**
 * Dicionário de tokens do WABinary.
 *
 * O protocolo substitui strings frequentes ("message", "from", "s.whatsapp.net"…)
 * por índices de 1 ou 2 bytes. Isso é *dado*, não lógica: a tabela vive no bundle
 * do WhatsApp Web e muda entre versões. Um único token fora de ordem desloca
 * todos os seguintes e o stream quebra em silêncio — o servidor apenas fecha a
 * conexão, sem erro legível.
 *
 * Por isso a tabela não é escrita à mão: ela é extraída com
 * `npm run vendor:tokens`, que grava `tokens.generated.ts`. Todo o codec deste
 * módulo é independente da tabela e é testado com um dicionário sintético.
 */

export type TokenDictionary = {
	/** Índice 0 é reservado (LIST_EMPTY); tokens úteis começam em 1. */
	single: readonly (string | null)[]
	/** Quatro dicionários secundários, endereçados por DICTIONARY_0..3. */
	double: readonly (readonly string[])[]
}

type LoadedDictionary = TokenDictionary & {
	singleIndex: ReadonlyMap<string, number>
	doubleIndex: ReadonlyMap<string, readonly [number, number]>
}

let loaded: LoadedDictionary | undefined

export class MissingTokenDictionaryError extends Error {
	constructor() {
		super(
			'dicionário de tokens do WABinary não carregado.\n' +
				'Rode `npm run vendor:tokens` para gerar src/binary/tokens.generated.ts, ' +
				'ou chame setTokenDictionary() manualmente antes de codificar/decodificar.',
		)
		this.name = 'MissingTokenDictionaryError'
	}
}

export function setTokenDictionary(dict: TokenDictionary): void {
	const singleIndex = new Map<string, number>()

	for (let i = 0; i < dict.single.length; i++) {
		const token = dict.single[i]

		// Primeira ocorrência vence: índices menores gastam menos bytes.
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
	return loaded !== undefined && loaded.single.length > 1
}

export function getTokenDictionary(): LoadedDictionary {
	if (!loaded || loaded.single.length <= 1) {
		throw new MissingTokenDictionaryError()
	}

	return loaded
}

/** Índice de 1 byte para um token, se ele estiver no dicionário primário. */
export function lookupSingleToken(token: string): number | undefined {
	return getTokenDictionary().singleIndex.get(token)
}

/** Par (dicionário, índice) para um token do dicionário secundário. */
export function lookupDoubleToken(token: string): readonly [number, number] | undefined {
	return getTokenDictionary().doubleIndex.get(token)
}

export function singleTokenAt(index: number): string {
	const token = getTokenDictionary().single[index]

	if (token === null || token === undefined) {
		throw new Error(`token primário inválido no índice ${index}`)
	}

	return token
}

export function doubleTokenAt(dictionary: number, index: number): string {
	const sub = getTokenDictionary().double[dictionary]

	if (!sub) {
		throw new Error(`dicionário secundário ${dictionary} não existe`)
	}

	const token = sub[index]

	if (token === undefined) {
		throw new Error(`token inválido no dicionário ${dictionary}, índice ${index}`)
	}

	return token
}

/** Quantidade de tokens primários — define onde termina a faixa de tags-token. */
export function singleTokenCount(): number {
	return getTokenDictionary().single.length
}
