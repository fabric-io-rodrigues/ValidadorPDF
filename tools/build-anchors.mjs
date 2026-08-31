/**
 * build-anchors.mjs - Gera js/trust-anchors.js a partir de certificados raiz
 * baixados do repositorio oficial.
 *
 * Uso:
 *   node tools/build-anchors.mjs <pasta-com-certificados>
 *   node tools/build-anchors.mjs <pasta> --procedencia "ITI, baixado em 2026-08-31"
 *
 * Aceita .crt, .cer, .pem e .der, em DER binario ou PEM. Imprime a impressao
 * digital SHA-256 de cada certificado para que voce confira contra a lista
 * publicada pelo ITI ANTES de commitar o arquivo gerado.
 *
 * Certificados que nao sejam auto-assinados sao recusados: ancora de confianca
 * e raiz, nao intermediario. Um intermediario legitimo ja e verificado pela
 * cadeia normal.
 */

import { readdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join, extname, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Certificate } from '../js/x509.js';

const here = dirname(fileURLToPath(import.meta.url));
const saida = resolve(here, '..', 'js', 'trust-anchors.js');

const pasta = process.argv[2];
if (!pasta) {
  console.error('uso: node tools/build-anchors.mjs <pasta-com-certificados> [--procedencia "..."]');
  process.exit(2);
}

const idx = process.argv.indexOf('--procedencia');
const procedencia = idx !== -1
  ? process.argv[idx + 1]
  : `arquivos de ${pasta}`;

if (!statSync(pasta).isDirectory()) {
  console.error(`nao e uma pasta: ${pasta}`);
  process.exit(2);
}

const EXTENSOES = new Set(['.crt', '.cer', '.pem', '.der']);
const arquivos = readdirSync(pasta).filter((n) => EXTENSOES.has(extname(n).toLowerCase()));

if (arquivos.length === 0) {
  console.error(`nenhum certificado (.crt/.cer/.pem/.der) em ${pasta}`);
  process.exit(1);
}

const ancoras = [];
const recusados = [];

for (const nome of arquivos) {
  const bruto = new Uint8Array(readFileSync(join(pasta, nome)));

  for (const der of extrairCertificados(bruto)) {
    let cert;
    try {
      cert = Certificate.fromDER(der);
    } catch (err) {
      recusados.push(`${nome}: ilegivel (${err.message})`);
      continue;
    }

    if (!cert.selfIssued) {
      recusados.push(`${nome}: ${cert.commonName} nao e auto-assinado (intermediario)`);
      continue;
    }

    const sha256 = await impressao(der);
    if (ancoras.some((a) => a.sha256 === sha256)) continue;

    ancoras.push({
      nome: cert.commonName ?? nome,
      sha256,
      procedencia,
      subject: cert.subjectHumanFriendly,
      notAfter: cert.notAfter ? cert.notAfter.toISOString() : null,
      arquivo: nome,
    });
  }
}

ancoras.sort((a, b) => a.nome.localeCompare(b.nome, 'pt-BR'));

console.log(`\n${ancoras.length} ancora(s) encontrada(s):\n`);
for (const a of ancoras) {
  console.log(`  ${a.nome}`);
  console.log(`    SHA-256: ${formatarImpressao(a.sha256)}`);
  console.log(`    valido ate: ${a.notAfter ?? '(indeterminado)'}`);
  console.log(`    arquivo: ${a.arquivo}\n`);
}

if (recusados.length) {
  console.log('Recusados:');
  for (const r of recusados) console.log(`  - ${r}`);
  console.log();
}

writeFileSync(saida, gerarModulo(ancoras, procedencia), 'utf8');
console.log(`escrito: ${saida}`);
console.log('\nCONFIRA as impressoes digitais acima contra as publicadas pelo ITI');
console.log('antes de commitar o arquivo gerado.');

// ---------------------------------------------------------------- auxiliares

/** Extrai um ou mais certificados DER de um arquivo PEM ou DER. */
function extrairCertificados(bruto) {
  const texto = new TextDecoder('latin1').decode(bruto);

  if (texto.includes('-----BEGIN CERTIFICATE-----')) {
    const out = [];
    const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
    let m;
    while ((m = re.exec(texto)) !== null) {
      out.push(Uint8Array.from(Buffer.from(m[1].replace(/\s+/g, ''), 'base64')));
    }
    return out;
  }

  // DER cru: precisa comecar com SEQUENCE.
  return bruto[0] === 0x30 ? [bruto] : [];
}

async function impressao(der) {
  const digest = await crypto.subtle.digest('SHA-256', der);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function formatarImpressao(hex) {
  return hex.toUpperCase().match(/.{2}/g).join(':');
}

function gerarModulo(lista, proc) {
  const entradas = lista.map((a) => `  {
    nome: ${JSON.stringify(a.nome)},
    sha256: '${a.sha256}',
    procedencia: ${JSON.stringify(a.procedencia)},
    subject: ${JSON.stringify(a.subject)},
  },`).join('\n');

  return `/**
 * trust-anchors.js - Autoridades raiz reconhecidas por esta pagina.
 *
 * GERADO por tools/build-anchors.mjs. Nao edite a mao.
 * Procedencia declarada: ${proc}
 * Ancoras: ${lista.length}
 *
 * Cada ancora e a impressao digital SHA-256 do certificado raiz. A pagina
 * compara a raiz que veio dentro do PDF com esta lista; so se a impressao casar
 * a raiz e aceita. O certificado embutido serve apenas de portador da chave
 * publica, e so depois de a impressao digital casar - por isso a lista nao
 * precisa carregar os certificados inteiros.
 *
 * Para regerar: node tools/build-anchors.mjs <pasta-com-certificados>
 */

/**
 * @typedef {object} Ancora
 * @property {string} nome
 * @property {string} sha256
 * @property {string} procedencia
 * @property {string} [subject]
 */

/** @type {Ancora[]} */
export const ANCORAS = [
${entradas}
];

/** Indice por impressao digital, montado uma vez. */
const POR_IMPRESSAO = new Map(ANCORAS.map((a) => [a.sha256.toLowerCase(), a]));

/**
 * @param {string} sha256Hex impressao digital do certificado candidato a raiz
 * @returns {Ancora|null}
 */
export function anchorByFingerprint(sha256Hex) {
  return POR_IMPRESSAO.get(String(sha256Hex).toLowerCase()) ?? null;
}
`;
}
