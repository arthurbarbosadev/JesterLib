#!/usr/bin/env node
/**
 * Extrai o dicionário de tokens do WABinary e grava src/binary/tokens.generated.ts.
 *
 * Essa tabela é dado, não lógica: ela vive no bundle do WhatsApp Web e muda
 * entre versões. Escrevê-la à mão é o jeito mais rápido de criar um bug
 * invisível — um token fora de ordem desloca todos os seguintes e o servidor
 * apenas fecha a conexão, sem erro legível.
 *
 * Fontes aceitas, em ordem de tentativa:
 *
 *   1. Um pacote de referência instalado (baileys, MIT):
 *        npm i -D baileys && npm run vendor:tokens
 *      Depois de gerar, o pacote pode ser removido — só os dados ficam.
 *
 *   2. Um bundle do WhatsApp Web salvo em disco:
 *        node scripts/vendor-tokens.mjs --bundle caminho/para/bundle.js
 */

import { createRequire } from 'node:module'
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const require = createRequire(import.meta.url)
const OUT_PATH = resolve(process.cwd(), 'src/binary/tokens.generated.ts')

const REFERENCE_PATHS = [
	'baileys/lib/WABinary/constants.js',
	'baileys/lib/WABinary/constants',
	'@whiskeysockets/baileys/lib/WABinary/constants.js',
]

function fromReferencePackage() {
	for (const path of REFERENCE_PATHS) {
		try {
			const mod = require(path)
			const single = mod.SINGLE_BYTE_TOKENS
			const double = mod.DOUBLE_BYTE_TOKENS

			if (Array.isArray(single) && Array.isArray(double)) {
				return { single, double, source: path }
			}
		} catch {
			// tenta o próximo caminho
		}
	}

	return null
}

/**
 * Nos bundles minificados as duas tabelas aparecem como arrays literais de
 * strings. A heurística: achar arrays grandes o bastante contendo âncoras que
 * sabidamente são tokens primários.
 */
function fromBundle(bundlePath) {
	const source = readFileSync(bundlePath, 'utf-8')
	const ANCHORS = ['s.whatsapp.net', 'g.us', 'message']

	const candidates = []
	const arrayRe = /\[(?:\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|null)\s*,?){20,}\]/g

	for (const match of source.matchAll(arrayRe)) {
		try {
			const parsed = JSON.parse(match[0].replace(/'/g, '"'))

			if (Array.isArray(parsed) && ANCHORS.every(a => parsed.includes(a))) {
				candidates.push(parsed)
			}
		} catch {
			// array com escape que o JSON.parse não aceita — ignora
		}
	}

	if (!candidates.length) {
		return null
	}

	// O dicionário primário é o que contém as âncoras; os secundários são os
	// arrays grandes seguintes. Confira o resultado antes de confiar.
	candidates.sort((a, b) => b.length - a.length)

	return { single: candidates[0], double: candidates.slice(1, 5), source: bundlePath }
}

function render({ single, double, source }) {
	const fmt = value => (value === null || value === undefined ? 'null' : JSON.stringify(value))

	const singleLines = single.map(t => `\t${fmt(t)},`).join('\n')
	const doubleLines = double
		.map(sub => `\t[\n${sub.map(t => `\t\t${fmt(t)},`).join('\n')}\n\t],`)
		.join('\n')

	return `// GERADO POR scripts/vendor-tokens.mjs — NÃO EDITE À MÃO.
// Fonte: ${source}
// Gerado em: ${new Date().toISOString()}
// Tokens primários: ${single.length} | dicionários secundários: ${double.length}

import type { TokenDictionary } from './tokens.ts'

const single: readonly (string | null)[] = [
${singleLines}
]

const double: readonly (readonly string[])[] = [
${doubleLines}
]

export const VENDORED_TOKENS: TokenDictionary = { single, double }
`
}

function main() {
	const bundleIdx = process.argv.indexOf('--bundle')
	const result = bundleIdx > -1 ? fromBundle(process.argv[bundleIdx + 1]) : fromReferencePackage()

	if (!result) {
		console.error(
			[
				'Não consegui extrair o dicionário de tokens.',
				'',
				'Opção 1 — pacote de referência (MIT):',
				'  npm i -D baileys && npm run vendor:tokens',
				'',
				'Opção 2 — bundle do WhatsApp Web salvo em disco:',
				'  node scripts/vendor-tokens.mjs --bundle ./bundle.js',
			].join('\n'),
		)
		process.exit(1)
	}

	writeFileSync(OUT_PATH, render(result), 'utf-8')

	console.log(`Dicionário gravado em ${OUT_PATH}`)
	console.log(`  fonte: ${result.source}`)
	console.log(`  tokens primários: ${result.single.length}`)
	console.log(`  dicionários secundários: ${result.double.length} (${result.double.map(d => d.length).join(', ')} tokens)`)
	console.log('')
	console.log('Rode `npm test` — o teste de sanidade confere se a tabela está coerente.')
}

main()
