// PLACEHOLDER — replaced by `npm run vendor:tokens`.
//
// The real WABinary token table is deliberately not written by hand: it is
// data extracted from the WhatsApp Web bundle, and a single token out of order
// shifts every token after it, breaking the stream silently. The whole codec in
// encode.ts / decode.ts is independent of this table and is tested against a
// synthetic dictionary.

import type { TokenDictionary } from './tokens.ts'

export const VENDORED_TOKENS: TokenDictionary = { single: [null], double: [] }
