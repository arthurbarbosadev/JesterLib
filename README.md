# Jester

Implementação em TypeScript do protocolo do WhatsApp Web (multi-device), escrita do zero.

Não é um wrapper: o transporte, o handshake Noise, o XML binário e o protobuf são
implementados aqui. O objetivo é uma biblioteca com estado 100% serializável, para
que o processo que segura o socket seja descartável — cai, sobe outro, retoma a
sessão sem ler QR de novo.

## Estado atual

| Camada | Situação | Onde |
|---|---|---|
| Cripto (X25519, HKDF, AES-GCM/CBC, SHA/HMAC) | pronto, validado contra RFC 7748 e 5869 | [src/crypto/](src/crypto/) |
| Runtime protobuf + schemas WAProto | pronto, validado contra encodings canônicos | [src/proto/](src/proto/) |
| WABinary (encode/decode, JID, packing) | lógica pronta e testada; **falta vendorizar a tabela de tokens** | [src/binary/](src/binary/) |
| Framing (prefixo de 3 bytes, streaming) | pronto | [src/noise/frame.ts](src/noise/frame.ts) |
| Handshake Noise XX | pronto, validado contra servidor simulado | [src/noise/](src/noise/) |
| Socket / conexão | **não começado** | — |
| Pareamento por QR | **não começado** | — |
| Signal (E2E) | **não começado** | — |
| App state sync, mídia | fora do escopo inicial | — |

`npm test` → 50 testes, todos passando. `npm run typecheck` → limpo.

## O passo que falta antes de conectar

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

## Arquitetura

```
src/
  crypto/    primitivas (X25519 via API nativa do Node, sem dependência)
  proto/     runtime protobuf próprio + schemas do WAProto
  binary/    o "XML binário" do WhatsApp: tokens, JIDs, nibble/hex packing
  noise/     handshake Noise_XX_25519_AESGCM_SHA256 + framing
  socket/    (a fazer) conexão WebSocket e roteamento de nós
  auth/      (a fazer) pareamento por QR e credenciais
  store/     (a fazer) persistência plugável (memória, Supabase)
```

As três camadas de baixo não têm dependência de rede e são testáveis offline —
foi essa a razão de construí-las primeiro.

## Decisões de projeto

**Zero dependências no núcleo.** X25519 sai da API nativa do Node (`node:crypto`),
via envelope DER de tamanho fixo. O runtime protobuf são ~200 linhas. A única
dependência de produção é `ws`.

**Schemas protobuf declarativos.** Em vez de codegen a partir de `.proto`, as
mensagens são objetos e o tipo TypeScript é inferido delas
([src/proto/wa.ts](src/proto/wa.ts)). O schema serve de documentação do protocolo.

**Papéis no Noise.** O handler implementa `initiator` e `responder`. O lado
servidor não é usado em produção — existe para que o handshake seja testável
contra um servidor simulado, o que pega erro de ordem de DH, de contador
compartilhado e de split final sem precisar de rede.

**Conteúdo binário volta como `Buffer`, sempre.** A wire não distingue texto de
binário em campos length-delimited. Adivinhar UTF-8 corromperia payloads binários
que por acaso são UTF-8 válido.

## Próximos passos

1. Vendorizar a tabela de tokens (acima)
2. `src/socket/` — WebSocket, orquestração do handshake, fila de IQ
3. `src/auth/` — geração do QR, `pair-device` / `pair-success`, credenciais
4. Persistência em Supabase para o estado de autenticação
5. Signal Protocol para receber e enviar texto

## Avisos

Este cliente se apresenta como um dispositivo companheiro do WhatsApp Web. É
engenharia reversa de protocolo, fora dos Termos de Uso do WhatsApp — contas que
usam clientes não oficiais podem ser banidas, especialmente em padrões de envio
em massa. Use um número que você pode perder.

MIT.
