/**
 * Connects to WhatsApp and prints the pairing QR.
 *
 *   npm run example:connect
 *
 * Credentials are saved to ./auth.json, so a second run logs in instead of
 * asking for a new QR. That file holds this device's private keys — treat it
 * like a password file.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import qrcode from 'qrcode-terminal'
import { deserializeCreds, initAuthCreds, serializeCreds } from '../src/auth/creds.ts'
import { makeInMemoryKeyStore } from '../src/auth/state.ts'
import { nodeToString } from '../src/binary/node.ts'
import { ConnectionError, DisconnectReason, JesterSocket } from '../src/socket/connection.ts'

const AUTH_FILE = new URL('../auth.json', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')

const creds = existsSync(AUTH_FILE)
	? deserializeCreds(readFileSync(AUTH_FILE, 'utf-8'))
	: initAuthCreds()

const verbose = process.argv.includes('--verbose')

const logger = {
	debug: (obj: unknown, msg?: string) => verbose && console.log('  ·', msg ?? '', obj ?? ''),
	info: (obj: unknown, msg?: string) => console.log('  i', msg ?? '', obj ?? ''),
	warn: (obj: unknown, msg?: string) => console.warn('  !', msg ?? '', obj ?? ''),
	error: (obj: unknown, msg?: string) => console.error('  x', msg ?? '', obj ?? ''),
}

const socket = new JesterSocket({
	auth: { creds, keys: makeInMemoryKeyStore() },
	logger,
})

socket.on('connection.update', update => {
	if (update.connection) {
		console.log(`\n[conexao] ${update.connection}`)
	}

	if (update.qr) {
		console.log('\n[qr] leia com WhatsApp > Aparelhos conectados > Conectar um aparelho\n')
		qrcode.generate(update.qr, { small: true })
	}

	if (update.isNewLogin) {
		console.log('\n[pareado] o servidor vai fechar com 515 agora; isso e esperado')
	}

	if (update.connection === 'close') {
		const error = update.lastDisconnect?.error as ConnectionError | undefined
		console.log(`[motivo] ${error?.message ?? 'desconhecido'} (code ${error?.code ?? '?'})`)

		if (error?.code === DisconnectReason.restartRequired) {
			console.log('[dica] rode de novo: as credenciais ja foram salvas')
		}
	}
})

socket.on('creds.update', updated => {
	writeFileSync(AUTH_FILE, serializeCreds(updated))
	console.log('[creds] salvas em auth.json')
})

socket.on('node', node => {
	if (verbose) {
		console.log('\n[no recebido]\n' + nodeToString(node))
	} else {
		console.log(`[no] <${node.tag}${node.attrs.type ? ` type="${node.attrs.type}"` : ''}>`)
	}
})

console.log('conectando em wss://web.whatsapp.com/ws/chat ...')

await socket.connect()

// Keep the process alive; the socket exits on its own when the server closes.
process.on('SIGINT', () => {
	socket.end()
	process.exit(0)
})
