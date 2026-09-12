import { randomBytes } from 'node:crypto'
import { S_WHATSAPP_NET } from '../binary/constants.ts'
import { getBinaryNodeChildren, type BinaryNode } from '../binary/node.ts'
import { isJidGroup, jidNormalizedUser } from '../binary/jid.ts'
import type { EncryptedMessage } from '../signal/cipher.ts'

/**
 * The `<message>` node: what actually travels once a session exists.
 *
 * Under multi-device a single logical message is encrypted separately for every
 * device of every recipient — including our own other devices, which is how the
 * phone sees what the bot sent. Each copy is its own `<enc>`.
 */

export type IncomingEnc = {
	type: 'pkmsg' | 'msg' | 'skmsg'
	version: string
	ciphertext: Buffer
}

export type IncomingMessage = {
	/** Server-assigned id; the ack must echo it or the message is redelivered. */
	id: string
	/** The chat: a user JID, or a group JID. */
	from: string
	/** In a group, who actually sent it. */
	participant?: string
	/** Unix seconds. */
	timestamp: number
	pushName?: string
	type?: string
	encs: IncomingEnc[]
	/** The address to decrypt against: the participant in a group, else `from`. */
	senderJid: string
}

export class MessageNodeError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'MessageNodeError'
	}
}

/** WhatsApp message ids are uppercase hex, conventionally 16 or 32 chars. */
export function generateMessageId(): string {
	return randomBytes(8).toString('hex').toUpperCase()
}

export function parseIncomingMessage(node: BinaryNode): IncomingMessage {
	const id = node.attrs.id
	const from = node.attrs.from

	if (!id || !from) {
		throw new MessageNodeError('<message> without id or from')
	}

	const encs: IncomingEnc[] = []

	for (const enc of getBinaryNodeChildren(node, 'enc')) {
		const type = enc.attrs.type

		if ((type === 'pkmsg' || type === 'msg' || type === 'skmsg') && Buffer.isBuffer(enc.content)) {
			encs.push({ type, version: enc.attrs.v ?? '2', ciphertext: enc.content })
		}
	}

	const participant = node.attrs.participant

	return {
		id,
		from,
		participant,
		timestamp: Number(node.attrs.t ?? 0),
		pushName: node.attrs.notify,
		type: node.attrs.type,
		encs,
		// In a group the ciphertext belongs to the participant's session, not to
		// the group. Decrypting against the group JID silently finds no session.
		senderJid: isJidGroup(from) ? (participant ?? from) : from,
	}
}

export type OutgoingRecipient = {
	/** Device JID, e.g. 5511999999999:3@s.whatsapp.net */
	jid: string
	encrypted: EncryptedMessage
}

/**
 * Builds the `<message>` node carrying one ciphertext per recipient device.
 *
 * With a single device the `<enc>` sits directly under `<message>`; with more
 * it goes under `<participants>`, one `<to>` per device. Getting that wrapper
 * wrong makes the server accept the node and nobody receive anything.
 */
export function buildOutgoingMessage(opts: {
	id: string
	to: string
	recipients: OutgoingRecipient[]
	/** `text` for ordinary messages. */
	type?: string
}): BinaryNode {
	if (!opts.recipients.length) {
		throw new MessageNodeError('no recipients to encrypt for')
	}

	const encFor = (recipient: OutgoingRecipient): BinaryNode => ({
		tag: 'enc',
		attrs: { v: '2', type: recipient.encrypted.type },
		content: recipient.encrypted.ciphertext,
	})

	const attrs: Record<string, string> = {
		id: opts.id,
		to: opts.to,
		type: opts.type ?? 'text',
	}

	if (opts.recipients.length === 1 && jidNormalizedUser(opts.recipients[0]!.jid) === jidNormalizedUser(opts.to)) {
		return { tag: 'message', attrs, content: [encFor(opts.recipients[0]!)] }
	}

	return {
		tag: 'message',
		attrs,
		content: [
			{
				tag: 'participants',
				attrs: {},
				content: opts.recipients.map(recipient => ({
					tag: 'to',
					attrs: { jid: recipient.jid },
					content: [encFor(recipient)],
				})),
			},
		],
	}
}

/**
 * Acknowledges a received message.
 *
 * Not optional: without an ack the server assumes delivery failed and sends the
 * message again, on a backoff, effectively forever. A bot that skips this
 * answers the same message repeatedly.
 */
export function buildMessageAck(message: IncomingMessage): BinaryNode {
	const attrs: Record<string, string> = {
		class: 'receipt',
		id: message.id,
		to: message.from,
	}

	if (message.participant) {
		attrs.participant = message.participant
	}

	return { tag: 'ack', attrs }
}

/** Marks a message delivered (the second tick on the sender's screen). */
export function buildDeliveryReceipt(message: IncomingMessage): BinaryNode {
	const attrs: Record<string, string> = { id: message.id, to: message.from }

	if (message.participant) {
		attrs.participant = message.participant
	}

	return { tag: 'receipt', attrs }
}

/** Marks messages read (the blue ticks). */
export function buildReadReceipt(opts: {
	jid: string
	ids: string[]
	participant?: string
}): BinaryNode {
	const [first, ...rest] = opts.ids

	if (!first) {
		throw new MessageNodeError('no message ids to mark as read')
	}

	const attrs: Record<string, string> = { id: first, to: opts.jid, type: 'read' }

	if (opts.participant) {
		attrs.participant = opts.participant
	}

	return {
		tag: 'receipt',
		attrs,
		content: rest.length
			? [{ tag: 'list', attrs: {}, content: rest.map(id => ({ tag: 'item', attrs: { id } })) }]
			: undefined,
	}
}

/** Asks the server which devices an account currently has linked. */
export function buildDeviceQuery(jids: string[]): BinaryNode {
	return {
		tag: 'iq',
		attrs: { to: S_WHATSAPP_NET, type: 'get', xmlns: 'usync' },
		content: [
			{
				tag: 'usync',
				attrs: { sid: generateMessageId(), mode: 'query', last: 'true', index: '0', context: 'message' },
				content: [
					{
						tag: 'query',
						attrs: {},
						content: [{ tag: 'devices', attrs: { version: '2' } }],
					},
					{
						tag: 'list',
						attrs: {},
						content: jids.map(jid => ({ tag: 'user', attrs: { jid } })),
					},
				],
			},
		],
	}
}

/** Pulls the device JIDs out of a usync result. */
export function parseDeviceQuery(result: BinaryNode): string[] {
	const devices: string[] = []

	for (const usync of getBinaryNodeChildren(result, 'usync')) {
		for (const list of getBinaryNodeChildren(usync, 'list')) {
			for (const user of getBinaryNodeChildren(list, 'user')) {
				for (const deviceList of getBinaryNodeChildren(user, 'devices')) {
					for (const deviceGroup of getBinaryNodeChildren(deviceList, 'device-list')) {
						for (const device of getBinaryNodeChildren(deviceGroup, 'device')) {
							if (device.attrs.id !== undefined && user.attrs.jid) {
								const [phone] = user.attrs.jid.split('@')
								devices.push(`${phone}:${device.attrs.id}@${S_WHATSAPP_NET}`)
							}
						}
					}
				}
			}
		}
	}

	return devices
}

// ---------------------------------------------------------------------------
// Presence
// ---------------------------------------------------------------------------

export type ChatState = 'composing' | 'paused' | 'recording'

/**
 * The "typing…" indicator.
 *
 * Worth more than polish on a sales bot: an instant reply reads as a robot and
 * people disengage. Showing composing for a beat proportional to the message
 * length makes the exchange feel handled by someone.
 *
 * The state is not sticky — WhatsApp clears it after a few seconds, so a long
 * pause needs it re-sent rather than set once.
 */
export function buildChatState(toJid: string, state: ChatState, fromJid?: string): BinaryNode {
	const attrs: Record<string, string> = { to: toJid }

	if (fromJid) {
		attrs.from = fromJid
	}

	return {
		tag: 'chatstate',
		attrs,
		content: [{ tag: state, attrs: {} }],
	}
}

/** Announces us as online/offline; required before presence is believed. */
export function buildPresence(type: 'available' | 'unavailable', name?: string): BinaryNode {
	return {
		tag: 'presence',
		attrs: name ? { name, type } : { type },
	}
}

/**
 * How long to "type" for a message of this length.
 *
 * Roughly 40 words per minute with a floor and a ceiling: fast enough not to
 * stall the funnel, slow enough not to look scripted. Capped because nobody
 * waits eight seconds for a price list.
 */
export function typingDurationFor(text: string): number {
	const perCharMs = 30

	return Math.min(Math.max(text.length * perCharMs, 700), 2800)
}
