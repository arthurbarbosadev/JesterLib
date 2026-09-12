// PLACEHOLDER — substituído por `npm run vendor:tokens`.
//
// A tabela real de tokens do WABinary não é escrita à mão de propósito: ela é
// dado extraído do bundle do WhatsApp Web, e um único token fora de ordem
// desloca todos os seguintes, quebrando o stream em silêncio. Todo o codec em
// encode.ts / decode.ts é independente desta tabela e é testado com um
// dicionário sintético.

import type { TokenDictionary } from './tokens.ts'

export const VENDORED_TOKENS: TokenDictionary = { single: [null], double: [] }
