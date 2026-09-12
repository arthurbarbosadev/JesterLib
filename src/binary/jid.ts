import {
	BROADCAST_SERVER,
	CALL_SERVER,
	DOMAIN_TYPE,
	GROUP_SERVER,
	LID_SERVER,
	NEWSLETTER_SERVER,
	S_WHATSAPP_NET,
} from './constants.ts'

/**
 * Um JID identifica um destino: usuário, grupo, canal, ou um *dispositivo*
 * específico de um usuário. No multi-device o `device` é obrigatório para
 * endereçar sessões Signal — cada aparelho logado é um destinatário distinto.
 *
 * Forma textual: `user[:device][_agent]@server`
 */
export type FullJid = {
	user: string
	server: string
	device?: number
	agent?: number
}

export function jidEncode(user: string | null | undefined, server: string, device?: number, agent?: number): string {
	const devicePart = device !== undefined && device !== 0 ? `:${device}` : ''
	const agentPart = agent !== undefined && agent !== 0 ? `_${agent}` : ''

	return `${user ?? ''}${agentPart}${devicePart}@${server}`
}

export function jidDecode(jid: string | undefined): FullJid | undefined {
	if (typeof jid !== 'string') {
		return undefined
	}

	const sepIdx = jid.indexOf('@')

	if (sepIdx < 0) {
		return undefined
	}

	const server = jid.slice(sepIdx + 1)
	const userCombined = jid.slice(0, sepIdx)
	const [userAgent = '', deviceStr] = userCombined.split(':')
	const [user = '', agentStr] = userAgent.split('_')

	const out: FullJid = { user, server }

	if (deviceStr) {
		out.device = Number(deviceStr)
	}

	if (agentStr) {
		out.agent = Number(agentStr)
	}

	return out
}

/** Remove device/agent — útil para agrupar por conta em vez de por aparelho. */
export function jidNormalizedUser(jid: string | undefined): string {
	const decoded = jidDecode(jid)

	if (!decoded) {
		return ''
	}

	const server = decoded.server === 'c.us' ? S_WHATSAPP_NET : decoded.server

	return jidEncode(decoded.user, server)
}

/** Compara ignorando device/agent. */
export function areJidsSameUser(a: string | undefined, b: string | undefined): boolean {
	return jidNormalizedUser(a) === jidNormalizedUser(b)
}

export function isJidUser(jid: string | undefined): boolean {
	return !!jid?.endsWith(`@${S_WHATSAPP_NET}`)
}

export function isJidGroup(jid: string | undefined): boolean {
	return !!jid?.endsWith(`@${GROUP_SERVER}`)
}

export function isJidBroadcast(jid: string | undefined): boolean {
	return !!jid?.endsWith(`@${BROADCAST_SERVER}`)
}

export function isJidNewsletter(jid: string | undefined): boolean {
	return !!jid?.endsWith(`@${NEWSLETTER_SERVER}`)
}

export function isLidUser(jid: string | undefined): boolean {
	return !!jid?.endsWith(`@${LID_SERVER}`)
}

export function isJidCall(jid: string | undefined): boolean {
	return !!jid?.endsWith(`@${CALL_SERVER}`)
}

/**
 * O AD_JID codifica o servidor em um byte em vez de uma string. Só os dois
 * domínios abaixo cabem nessa forma compacta.
 */
export function serverToDomainType(server: string): number | undefined {
	if (server === S_WHATSAPP_NET) {
		return DOMAIN_TYPE.WHATSAPP
	}

	if (server === LID_SERVER) {
		return DOMAIN_TYPE.LID
	}

	return undefined
}

export function domainTypeToServer(domainType: number): string {
	return domainType === DOMAIN_TYPE.LID ? LID_SERVER : S_WHATSAPP_NET
}
