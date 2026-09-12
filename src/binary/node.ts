/**
 * All post-handshake traffic is a tree of nodes — the binary equivalent of an
 * XMPP stanza. `<iq type="get" to="..."><query/></iq>` becomes:
 *
 *   { tag: 'iq', attrs: { type: 'get', to: '...' }, content: [{ tag: 'query', attrs: {} }] }
 */
export type BinaryNode = {
	tag: string
	attrs: Record<string, string>
	content?: BinaryNode[] | string | Buffer
}

/** Children as an array, whether the content is nodes, a string or binary. */
export function getBinaryNodeChildren(node: BinaryNode | undefined, tag?: string): BinaryNode[] {
	if (!Array.isArray(node?.content)) {
		return []
	}

	return tag === undefined ? node.content : node.content.filter(item => item.tag === tag)
}

export function getBinaryNodeChild(node: BinaryNode | undefined, tag: string): BinaryNode | undefined {
	return getBinaryNodeChildren(node, tag)[0]
}

export function getBinaryNodeChildBuffer(node: BinaryNode | undefined, tag: string): Buffer | undefined {
	const content = getBinaryNodeChild(node, tag)?.content

	if (Buffer.isBuffer(content)) {
		return content
	}

	return typeof content === 'string' ? Buffer.from(content, 'utf-8') : undefined
}

export function getBinaryNodeChildString(node: BinaryNode | undefined, tag: string): string | undefined {
	const content = getBinaryNodeChild(node, tag)?.content

	if (Buffer.isBuffer(content)) {
		return content.toString('utf-8')
	}

	return typeof content === 'string' ? content : undefined
}

export function getBinaryNodeChildUInt(node: BinaryNode | undefined, tag: string): number | undefined {
	const buf = getBinaryNodeChildBuffer(node, tag)

	if (!buf) {
		return undefined
	}

	let value = 0

	for (const byte of buf) {
		value = value * 256 + byte
	}

	return value
}

/** Pretty-printer for debugging — nested Buffers are unreadable in console.log. */
export function nodeToString(node: BinaryNode, indent = 0): string {
	const pad = '  '.repeat(indent)
	const attrs = Object.entries(node.attrs)
		.map(([k, v]) => ` ${k}="${v}"`)
		.join('')

	if (node.content === undefined) {
		return `${pad}<${node.tag}${attrs}/>`
	}

	if (Buffer.isBuffer(node.content)) {
		return `${pad}<${node.tag}${attrs}>[${node.content.length} bytes]</${node.tag}>`
	}

	if (typeof node.content === 'string') {
		return `${pad}<${node.tag}${attrs}>${node.content}</${node.tag}>`
	}

	const children = node.content.map(child => nodeToString(child, indent + 1)).join('\n')

	return `${pad}<${node.tag}${attrs}>\n${children}\n${pad}</${node.tag}>`
}

/** Strips undefined/null attributes so they do not break the encoder. */
export function cleanAttrs(attrs: Record<string, string | number | undefined | null>): Record<string, string> {
	const out: Record<string, string> = {}

	for (const [key, value] of Object.entries(attrs)) {
		if (value !== undefined && value !== null) {
			out[key] = String(value)
		}
	}

	return out
}
