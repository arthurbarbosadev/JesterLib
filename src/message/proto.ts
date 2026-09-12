import { defineMessage, f, type MessageCodec } from '../proto/schema.ts'

/**
 * The subset of WAProto's `Message` needed to send and receive text.
 *
 * The real definition has over a hundred fields, one per message type. Only the
 * ones below are implemented; anything else decodes to an empty object rather
 * than throwing, so an unsupported message type is visible instead of fatal.
 *
 * The types are written out by hand rather than inferred from the schema, which
 * is the exception in this codebase. `Message` is genuinely recursive — it
 * contains quoted messages and several wrapper types that contain a `Message` —
 * and inference cannot terminate on a cycle. The lazy `() => Message` field
 * breaks the cycle at runtime; these annotations break it at the type level.
 */

export type MessageKeyContent = {
	remoteJid?: string
	fromMe?: boolean
	id?: string
	participant?: string
}

export type ContextInfoContent = {
	stanzaId?: string
	participant?: string
	quotedMessage?: MessageContent
	remoteJid?: string
	mentionedJid?: string
	conversionSource?: string
	expiration?: number
}

export type ExtendedTextContent = {
	text?: string
	matchedText?: string
	canonicalUrl?: string
	description?: string
	title?: string
	jpegThumbnail?: Buffer
	contextInfo?: ContextInfoContent
}

export type DeviceSentContent = {
	destinationJid?: string
	message?: MessageContent
	phash?: string
}

export type FutureProofContent = {
	message?: MessageContent
}

export type MessageContent = {
	/** Plain text. The common case. */
	conversation?: string
	senderKeyDistributionMessage?: Buffer
	extendedTextMessage?: ExtendedTextContent
	/** Present when the message came from another device of our own account. */
	deviceSentMessage?: DeviceSentContent
	/** Newer types arrive wrapped in these so old clients degrade gracefully. */
	ephemeralMessage?: FutureProofContent
	viewOnceMessage?: FutureProofContent
	documentWithCaptionMessage?: FutureProofContent
	viewOnceMessageV2?: FutureProofContent
}

export type WebMessageInfoContent = {
	key?: MessageKeyContent
	message?: MessageContent
	messageTimestamp?: bigint
	status?: number
	participant?: string
	pushName?: string
}

export const MessageKey: MessageCodec<MessageKeyContent> = defineMessage('MessageKey', {
	remoteJid: f(1, 'string'),
	fromMe: f(2, 'bool'),
	id: f(3, 'string'),
	participant: f(4, 'string'),
})

export const ContextInfo: MessageCodec<ContextInfoContent> = defineMessage('ContextInfo', {
	stanzaId: f(1, 'string'),
	participant: f(2, 'string'),
	quotedMessage: f(3, () => Message),
	remoteJid: f(4, 'string'),
	mentionedJid: f(15, 'string'),
	conversionSource: f(18, 'string'),
	expiration: f(25, 'uint32'),
})

/** Text with extras: link previews, quotes, mentions. */
export const ExtendedTextMessage: MessageCodec<ExtendedTextContent> = defineMessage(
	'ExtendedTextMessage',
	{
		text: f(1, 'string'),
		matchedText: f(2, 'string'),
		canonicalUrl: f(4, 'string'),
		description: f(5, 'string'),
		title: f(6, 'string'),
		jpegThumbnail: f(16, 'bytes'),
		contextInfo: f(17, ContextInfo),
	},
)

/**
 * Wraps a message the account sent from another of its own devices.
 *
 * Easy to miss and confusing when you do: the phone echoes your own outgoing
 * messages to every linked device inside one of these. Unwrap it, or the bot
 * ends up replying to itself.
 */
export const DeviceSentMessage: MessageCodec<DeviceSentContent> = defineMessage(
	'DeviceSentMessage',
	{
		destinationJid: f(1, 'string'),
		message: f(2, () => Message),
		phash: f(3, 'string'),
	},
)

export const FutureProofMessage: MessageCodec<FutureProofContent> = defineMessage(
	'FutureProofMessage',
	{ message: f(1, () => Message) },
)

export const Message: MessageCodec<MessageContent> = defineMessage('Message', {
	conversation: f(1, 'string'),
	senderKeyDistributionMessage: f(2, 'bytes'),
	extendedTextMessage: f(14, ExtendedTextMessage),
	deviceSentMessage: f(31, DeviceSentMessage),
	ephemeralMessage: f(36, FutureProofMessage),
	viewOnceMessage: f(38, FutureProofMessage),
	documentWithCaptionMessage: f(53, FutureProofMessage),
	viewOnceMessageV2: f(55, FutureProofMessage),
})

export const WebMessageInfo: MessageCodec<WebMessageInfoContent> = defineMessage('WebMessageInfo', {
	key: f(1, MessageKey),
	message: f(2, Message),
	messageTimestamp: f(3, 'uint64'),
	status: f(4, 'enum'),
	participant: f(5, 'string'),
	pushName: f(6, 'string'),
})

/** The wrappers that hold another message inside, in the order to try them. */
function innerMessage(message: MessageContent): MessageContent | undefined {
	return (
		message.deviceSentMessage?.message ??
		message.ephemeralMessage?.message ??
		message.viewOnceMessage?.message ??
		message.viewOnceMessageV2?.message ??
		message.documentWithCaptionMessage?.message
	)
}

/**
 * Digs the text out of whatever wrapper it arrived in.
 *
 * Returns undefined for message types that carry no text (an image with no
 * caption, a sticker, a poll) — a normal outcome, not a failure.
 */
export function extractText(message: MessageContent | undefined): string | undefined {
	if (!message) {
		return undefined
	}

	if (message.conversation) {
		return message.conversation
	}

	if (message.extendedTextMessage?.text) {
		return message.extendedTextMessage.text
	}

	const inner = innerMessage(message)

	return inner ? extractText(inner) : undefined
}

/** Unwraps the outer containers, returning the message that actually matters. */
export function unwrapMessage(message: MessageContent | undefined): MessageContent | undefined {
	if (!message) {
		return undefined
	}

	const inner = innerMessage(message)

	return inner ? unwrapMessage(inner) : message
}
