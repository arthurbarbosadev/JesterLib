import type { PreKey } from '../auth/prekeys.ts'
import type { AuthenticationState } from '../auth/state.ts'
import { jidDecode } from '../binary/jid.ts'
import { addKeyType, xeddsaVerify } from '../crypto/index.ts'
import {
	createOutgoingSession,
	decryptPreKeyMessage,
	decryptSignalMessage,
	encrypt as encryptWithSession,
	type EncryptedMessage,
	type IncomingPreKeyContext,
	type PreKeyBundle,
} from './cipher.ts'
import { parsePreKeySignalMessage } from './message.ts'
import {
	createSessionRecord,
	deserializeSessionRecord,
	serializeSessionRecord,
	type SessionRecord,
} from './session.ts'

/**
 * Ties Signal sessions to the key store.
 *
 * Everything above this line is pure state machine; everything below is
 * storage. Keeping the glue in one place means a Supabase, Redis or disk store
 * only has to satisfy `SignalKeyStore` — it never learns what a ratchet is.
 */

export class SignalRepositoryError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'SignalRepositoryError'
	}
}

/**
 * Session address for a device JID.
 *
 * The device matters: `5511999999999@s.whatsapp.net` and
 * `5511999999999:3@s.whatsapp.net` are two different sessions with two
 * different ratchets. Collapsing them means decrypting one device's messages
 * with another device's keys, which fails with a bad MAC and looks like
 * corruption.
 */
export function sessionAddress(jid: string): string {
	const decoded = jidDecode(jid)

	if (!decoded?.user) {
		throw new SignalRepositoryError(`cannot derive a session address from "${jid}"`)
	}

	return `${decoded.user}.${decoded.device ?? 0}`
}

export type SignalRepository = {
	decrypt(jid: string, type: 'pkmsg' | 'msg', ciphertext: Buffer): Promise<Buffer>
	encrypt(jid: string, plaintext: Buffer): Promise<EncryptedMessage>
	/** Opens a session from a fetched bundle, verifying its signature first. */
	openSession(jid: string, bundle: PreKeyBundle): Promise<void>
	hasSession(jid: string): Promise<boolean>
	storePreKeys(preKeys: PreKey[]): Promise<void>
}

export function makeSignalRepository(auth: AuthenticationState): SignalRepository {
	const { creds, keys } = auth

	const localIdentity = () => ({
		identityKey: creds.signedIdentityKey,
		registrationId: creds.registrationId,
	})

	async function loadRecord(address: string): Promise<SessionRecord> {
		const stored = await keys.get('session', [address])
		const raw = stored[address]

		return raw ? deserializeSessionRecord(Buffer.from(raw)) : createSessionRecord()
	}

	async function saveRecord(address: string, record: SessionRecord): Promise<void> {
		await keys.set({ session: { [address]: serializeSessionRecord(record) } })
	}

	/**
	 * Resolves the keys a `pkmsg` addressed.
	 *
	 * The signed pre-key is almost always the current one, but a message can be
	 * in flight across a rotation, so the id is checked rather than assumed.
	 */
	async function resolveIncomingKeys(
		signedPreKeyId: number,
		preKeyId?: number,
	): Promise<IncomingPreKeyContext> {
		if (signedPreKeyId !== creds.signedPreKey.keyId) {
			throw new SignalRepositoryError(
				`message addressed signed pre-key ${signedPreKeyId}, but we hold ${creds.signedPreKey.keyId}`,
			)
		}

		const ctx: IncomingPreKeyContext = {
			local: localIdentity(),
			signedPreKey: creds.signedPreKey.keyPair,
		}

		if (preKeyId !== undefined) {
			const stored = await keys.get('pre-key', [String(preKeyId)])
			const preKey = stored[String(preKeyId)]

			if (!preKey) {
				throw new SignalRepositoryError(
					`one-time pre-key ${preKeyId} is gone — already consumed, or from before a reset`,
				)
			}

			ctx.preKey = preKey
		}

		return ctx
	}

	return {
		async decrypt(jid, type, ciphertext) {
			const address = sessionAddress(jid)
			const record = await loadRecord(address)

			if (type === 'msg') {
				const plaintext = decryptSignalMessage(record, ciphertext)
				await saveRecord(address, record)

				return plaintext
			}

			// `decryptPreKeyMessage` needs the pre-keys synchronously, so they are
			// resolved up front from the message's own ids.
			const parsed = parsePreKeySignalMessage(ciphertext)
			const ctx = await resolveIncomingKeys(parsed.signedPreKeyId, parsed.preKeyId)

			const result = decryptPreKeyMessage(record, ciphertext, () => ctx)

			await saveRecord(address, record)

			// A one-time pre-key is used exactly once. Leaving it in the store
			// would let a replay establish the same session again.
			if (result.usedPreKeyId !== undefined) {
				await keys.set({ 'pre-key': { [String(result.usedPreKeyId)]: null } })
			}

			return result.plaintext
		},

		async encrypt(jid, plaintext) {
			const address = sessionAddress(jid)
			const record = await loadRecord(address)

			if (!record.currentSession) {
				throw new SignalRepositoryError(
					`no session with ${jid} — fetch a pre-key bundle and call openSession first`,
				)
			}

			const encrypted = encryptWithSession(record, plaintext)
			await saveRecord(address, record)

			return encrypted
		},

		async openSession(jid, bundle) {
			// Verified here rather than left to the caller: an unverified bundle is
			// how a man in the middle gets in, and it is too easy to forget.
			const valid = xeddsaVerify(
				bundle.identityKeyPublic,
				addKeyType(bundle.signedPreKeyPublic),
				bundle.signedPreKeySignature,
			)

			if (!valid) {
				throw new SignalRepositoryError(
					`pre-key bundle for ${jid} failed signature verification — refusing to open a session`,
				)
			}

			const address = sessionAddress(jid)
			const record = await loadRecord(address)

			createOutgoingSession(localIdentity(), bundle, record)

			await saveRecord(address, record)
		},

		async hasSession(jid) {
			const address = sessionAddress(jid)
			const stored = await keys.get('session', [address])

			return !!stored[address]
		},

		async storePreKeys(preKeys) {
			const entries: Record<string, PreKey['keyPair']> = {}

			for (const preKey of preKeys) {
				entries[String(preKey.keyId)] = preKey.keyPair
			}

			await keys.set({ 'pre-key': entries })
		},
	}
}
