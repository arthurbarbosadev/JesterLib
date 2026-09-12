# Jester

Implementação em TypeScript do protocolo do WhatsApp Web (multi-device), escrita do zero.

Não é um wrapper: o transporte, o handshake Noise, o XML binário, o protobuf e as
assinaturas Curve25519 são implementados aqui. O objetivo é uma biblioteca com
estado 100% serializável, para que o processo que segura o socket seja
descartável — cai, sobe outro, retoma a sessão sem ler QR de novo.

## Estado atual

| Camada | Situação | Onde |
|---|---|---|
| Cripto (X25519, HKDF, AES-GCM/CBC, SHA/HMAC) | pronto, validado contra RFC 7748 e 5869 | [src/crypto/](src/crypto/) |
| Assinatura XEdDSA (Curve25519) | pronto, verificação cruzada com dois verificadores independentes | [src/crypto/xeddsa.ts](src/crypto/xeddsa.ts) |
| Runtime protobuf + schemas WAProto | pronto, validado contra encodings canônicos | [src/proto/](src/proto/) |
| WABinary (encode/decode, JID, packing) | lógica pronta e testada; **falta vendorizar a tabela de tokens** | [src/binary/](src/binary/) |
| Framing + handshake Noise XX | pronto, validado contra servidor simulado | [src/noise/](src/noise/) |
| Credenciais e estado de autenticação | pronto, serializável | [src/auth/](src/auth/) |
| Conexão (handshake, queries, roteamento de nós) | pronto, validado ponta a ponta | [src/socket/](src/socket/) |
| Pareamento por QR (ADV, contra-assinatura) | pronto, validado contra celular simulado | [src/auth/pairing.ts](src/auth/pairing.ts) |
| Signal (E2E) | não começado | — |
| App state sync, mídia | fora do escopo inicial | — |

`npm test` → 83 testes, todos passando. `npm run typecheck` e `npm run build` → limpos.

## O passo que falta antes de conectar de verdade

O WABinary substitui strings frequentes por índices de 1–2 bytes. Essa tabela é
**dado**, não lógica: vive no bundle do WhatsApp Web e muda entre versões. Um
token fora de ordem desloca todos os seguintes e o servidor simplesmente fecha a
conexão, sem erro legível — por isso ela não foi escrita à mão.

```bash
npm i -D baileys       # pacote de referência, MIT
npm run vendor:tokens  # grava src/binary/tokens.generated.ts
```

Todo o codec é independente dessa tabela e já é testado com um dicionário
sintético, então o que falta é só preencher os dados.

## Uso

```ts
import { initAuthCreds, makeInMemoryKeyStore, JesterSocket } from 'jester'

const socket = new JesterSocket({
  auth: { creds: initAuthCreds(), keys: makeInMemoryKeyStore() },
})

socket.on('connection.update', ({ connection, qr }) => {
  if (qr) console.log('leia este QR:', qr)
  if (connection === 'open') console.log('conectado')
})

socket.on('creds.update', creds => {
  // persista aqui — sem isso, QR novo a cada reconexão
})

await socket.connect()
```

### Pareamento

Depois que o celular lê o QR, o servidor **derruba a conexão** com
`stream:error code="515"` (`restartRequired`). Isso é esperado, não é erro: as
credenciais já foram gravadas, e basta reconectar — a segunda conexão já usa o
payload de login.

```ts
socket.on('connection.update', ({ connection, lastDisconnect }) => {
  if (connection === 'close') {
    const code = (lastDisconnect?.error as ConnectionError)?.code
    const deveReconectar = code !== DisconnectReason.loggedOut

    if (deveReconectar) reconecta()   // nova instância, mesmas credenciais
  }
})
```

## Arquitetura

```
src/
  crypto/    primitivas: X25519 nativo do Node + XEdDSA sobre @noble/curves
  proto/     runtime protobuf próprio + schemas do WAProto
  binary/    o "XML binário" do WhatsApp: tokens, JIDs, nibble/hex packing
  noise/     handshake Noise_XX_25519_AESGCM_SHA256 + framing
  socket/    conexão, ClientPayload, transporte abstraído
  auth/      credenciais serializáveis e store de chaves Signal
  store/     (a fazer) persistência em Supabase
```

## Decisões de projeto

**Quase zero dependências.** X25519, AES, HKDF e a verificação Ed25519 saem da API
nativa do Node. O runtime protobuf são ~220 linhas próprias. Em produção a lib
depende só de `ws` e `@noble/curves` — este último apenas para a aritmética de
ponto na curva de Edwards, que o Node não expõe.

**Verificação por caminho independente.** O XEdDSA é assinado com `@noble` e
verificado com o OpenSSL do Node — dois códigos que não se falam. Se os dois
concordam, o erro teria que estar nos dois.

**Servidores simulados em vez de mocks.** O handshake Noise e a conexão inteira
são testados contra um responder de verdade implementado em
[test/helpers/fake-server.ts](test/helpers/fake-server.ts), falando Noise e
WABinary sobre um par de transportes em memória. Isso pega ordem de DH, contador
de nonce e casamento de resposta por id — os erros que normalmente só aparecem
como "o servidor fechou a conexão".

**Conteúdo binário volta como `Buffer`, sempre.** A wire não distingue texto de
binário em campos length-delimited. Adivinhar UTF-8 corromperia payloads binários
que por acaso são UTF-8 válido.

## Próximos passos

1. Vendorizar a tabela de tokens (acima)
2. Upload de prekeys (`<iq xmlns="encrypt">`)
3. Persistência em Supabase para o estado de autenticação
4. Signal Protocol: sessões, receber e enviar texto

## Avisos

Este cliente se apresenta como um dispositivo companheiro do WhatsApp Web. É
engenharia reversa de protocolo, fora dos Termos de Uso do WhatsApp — contas que
usam clientes não oficiais podem ser banidas, especialmente em padrões de envio
em massa. Use um número que você pode perder.

A validação do certificado do servidor confere apenas o serial do emissor, não a
assinatura criptográfica contra a chave raiz do WhatsApp. Está isolada em
`validateServerCertificate` para poder ser endurecida.

MIT.
