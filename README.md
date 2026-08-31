# ValidadorPDF

Verifica assinaturas digitais em PDF — ICP-Brasil, Gov.br, Adobe, Docusign,
Clicksign, D4Sign, ZapSign — **no próprio dispositivo**. O arquivo não sai do
navegador.

**→ https://fabric-io-rodrigues.github.io/validadorpdf/**

Ferramenta independente, de código aberto, sem vínculo com o ITI nem com
qualquer órgão público. Não emite parecer: tudo que o relatório afirma vem do
arquivo enviado.

## Usar

Abra o link e escolha um PDF. Para instalar como aplicativo:

- **Android (Chrome):** menu → *Instalar app*
- **iPhone (Safari):** compartilhar → *Adicionar à Tela de Início*

Instalado, abre em tela cheia e funciona sem internet.

Os três botões do topo: abrir outro PDF, baixar todos os dados extraídos em
JSON, imprimir.

## O que verifica

| | |
|---|---|
| **Integridade** | recalcula o hash da área coberta pelo `/ByteRange` e compara com o `messageDigest` assinado |
| **Autoria** | confere a assinatura contra a chave pública do certificado embutido (RSA e ECDSA, SHA-1 a SHA-512) |
| **Cadeia** | verifica que cada certificado foi assinado pela autoridade seguinte, que os intermediários são ACs e que todos estavam vigentes |
| **Identidade** | lê as extensões ICP-Brasil do certificado (CPF, nascimento, CNPJ, responsável) e confere os dígitos verificadores |
| **Abrangência** | se a assinatura cobre o arquivo inteiro, apenas a revisão vigente, ou se aponta para fora do arquivo |
| **Data** | classifica em quatro níveis, abaixo |
| **Carimbo do tempo** | lê o token RFC 3161 e confere se ele se refere àquela assinatura |

Encontra também **assinaturas órfãs**: assinatura válida que saiu do formulário
do PDF numa revisão posterior e por isso não aparece em validadores que
enumeram pelo `/AcroForm`.

Quando uma assinatura não confere, distingue os casos. Assinatura que confere
com a chave do certificado mas cujo hash do conteúdo não bate não é assinatura
falsa: é assinatura autêntica referente a **outro arquivo**.

## Níveis da data

| Nível | Quando |
|---|---|
| Comprovada por carimbo do tempo | carimbo RFC 3161 presente e conferido |
| Protegida pela assinatura | `signingTime` nos atributos assinados e dentro da vigência do certificado |
| Não protegida pela assinatura | data só no dicionário do PDF, fora da área assinada |
| Inconsistente | data fora da vigência, ou carimbo que é de outra assinatura |

O segundo nível existe porque assinatura do Gov.br não traz carimbo RFC 3161,
mas traz `signingTime` protegido pela assinatura — alterar o valor invalidaria
a assinatura. Tratar isso como "data não comprovada" desqualificaria documento
legítimo.

## O que NÃO verifica

- **Ancoragem em raiz oficial.** A cadeia é conferida elo por elo, mas só é
  declarada confiável se a impressão digital da raiz constar da lista de
  âncoras. Sem âncoras carregadas, o status é *cadeia consistente, sem
  ancoragem aferida*.
- **Revogação.** Não consulta CRL nem OCSP. Certificado revogado dentro do
  prazo de validade aparece como vigente.
- **RSA-PSS.** Produz status *não verificada*, nunca *inválida*.
- **PDF cifrado.** A assinatura é verificada normalmente, mas os metadados do
  arquivo não são extraídos.

## Nada sai do dispositivo

1. Nenhuma API de rede no código da página: sem `fetch`, `XMLHttpRequest`,
   `WebSocket` ou `sendBeacon`.
2. Nenhum recurso externo: sem CDN, fonte remota ou analytics.
3. A política de segurança no HTML bloqueia o resto — `connect-src 'none'`,
   `form-action 'none'`, `default-src 'self'`.
4. O service worker é o único componente que poderia acessar a rede, porque não
   herda a política do documento. Por isso se restringe a mesma origem, `GET` e
   uma lista fixa de URLs. Ele nunca vê os bytes do PDF, que são lidos em
   memória e nunca se tornam requisição.

## Arquivos

| | |
|---|---|
| `js/der.js` | parser DER/BER (TLV), com suporte a comprimento indefinido |
| `js/oid.js` | tabelas de OID: DN, extensões, atributos CMS, algoritmos, ICP-Brasil |
| `js/x509.js` | certificados X.509: DN, validade, extensões, SAN, SPKI |
| `js/cms.js` | CMS/PKCS#7 SignedData, SignerInfo, carimbo RFC 3161 |
| `js/pdfdoc.js` | índice do PDF, construído uma vez e compartilhado |
| `js/pdfsig.js` | varredura das assinaturas e abrangência do `/ByteRange` |
| `js/pdfmeta.js` | páginas, `/Info`, tamanho da página, versão, `/Encrypt` |
| `js/objstm.js` | descompressão de object streams |
| `js/icpbrasil.js` | identidade ICP-Brasil (DOC-ICP-04) e dígitos verificadores |
| `js/verify.js` | verificação criptográfica |
| `js/trust.js` | cadeia de certificados e ancoragem |
| `js/trust-anchors.js` | autoridades raiz reconhecidas. **Gerado**, começa vazio |
| `js/analyze.js` | orquestra e devolve o relatório. Não toca no DOM |
| `js/dom.js` | utilitários de DOM |
| `js/rotulos.js` | rótulos de uma linha para os enums |
| `js/render-simples.js` | renderizador |
| `js/preview.js` | miniatura da 1ª página, via PDF.js |
| `js/dump.js` | export dos dados em JSON |
| `js/worker.js` | roda a análise fora da thread principal |
| `js/validador.js` | controlador da página |
| `sw.js` | service worker |
| `tools/build-anchors.mjs` | gera `trust-anchors.js` |

Sem framework e sem passo de build. O relatório que o núcleo devolve é dado
puro — enum, número, booleano — sem frase montada. Quem exibe decide como dizer.

Para abrir localmente, qualquer servidor estático serve
(`python -m http.server`). Módulos ES não carregam por `file://`.

## Âncoras de confiança

A lista em `js/trust-anchors.js` começa vazia de propósito: ancorar na raiz que
veio dentro do próprio PDF seria circular, porque o documento atestaria a si
mesmo. A âncora tem de vir de fora, e a impressão digital SHA-256 é a forma
mais compacta de trazê-la.

Para popular, baixe as ACs Raiz do repositório oficial do ITI e rode:

```bash
node tools/build-anchors.mjs <pasta-com-os-certificados> \
     --procedencia "ITI, baixado em AAAA-MM-DD"
```

O script recusa certificado que não seja auto-assinado e imprime a impressão
digital de cada um, para conferir contra a lista publicada pelo ITI antes de
commitar.

## PDF.js

`vendor/pdfjs/` tem dois arquivos do `pdfjs-dist` 5.7.284, com o conteúdo
inalterado, usados só para a miniatura da primeira página e carregados sob
demanda.

Ficaram de fora, de propósito: `pdf.sandbox` (o executor de JavaScript embutido
no PDF — sem o arquivo, a página não tem como rodar script de documento),
`standard_fonts/`, `wasm/` e `cmaps/`. O PDF nunca vai para um `<iframe>` nem
para o visualizador do navegador.

Os arquivos terminam em `.js` e não `.mjs` porque o Windows registra `.mjs` como
`text/plain`, e o navegador recusa o módulo por *strict MIME checking*.
Procedência e comando de atualização em `vendor/pdfjs/PROCEDENCIA.txt`.

## Licença

Código próprio. O PDF.js em `vendor/pdfjs/` é da Mozilla, sob Apache-2.0 — ver
`vendor/pdfjs/LICENSE`.
