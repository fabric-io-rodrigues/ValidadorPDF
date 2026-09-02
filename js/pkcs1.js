/**
 * pkcs1.js - Assinatura no formato adbe.x509.rsa_sha1 (ISO 32000-1, 12.8.3.2).
 *
 * Difere do CMS em tres pontos:
 *
 *   /Contents  um OCTET STRING com a assinatura crua, sem conteiner PKCS#7;
 *   /Cert      o certificado (ou a cadeia) numa string do proprio dicionario;
 *   assinatura incide direto sobre os bytes do /ByteRange, sem signedAttrs.
 *
 * Sem signedAttrs nao existe `messageDigest` para comparar, logo `integro` fica
 * `null`: aqui a integridade e a propria assinatura, nao um segundo teste.
 *
 * O nome do SubFilter diz `sha1`, mas o digest usado nao esta declarado em
 * lugar algum - o arquivo de referencia deste caminho usa SHA-512. Por isso a
 * verificacao tenta os algoritmos em ordem.
 */

import { parse, TAG } from './der.js';
import { Certificate } from './x509.js';
import { verifyWithCertificate, consolidarStatus, digestHex } from './verify.js';

const DIGESTS = ['SHA-256', 'SHA-512', 'SHA-384', 'SHA-1'];

/** @param {string|null} subFilter */
export function ehPkcs1(subFilter) {
  return /^adbe\.x509\./.test(subFilter ?? '');
}

/**
 * @param {import('./pdfsig.js').PdfSignature} sig
 * @param {Uint8Array} signedBytes bytes cobertos pelo /ByteRange
 */
export async function lerPkcs1(sig, signedBytes) {
  const certificados = [];
  for (const der of sig.certDer ?? []) {
    try {
      certificados.push(Certificate.fromDER(der));
    } catch {
      // Entrada ilegivel na cadeia nao invalida as demais.
    }
  }

  if (certificados.length === 0) {
    return {
      erro: 'assinatura adbe.x509 sem certificado legível em /Cert',
      diagnostico: {
        codigo: 'CERT_AUSENTE',
        titulo: 'Certificado ilegível',
        severidade: 'erro',
      },
    };
  }

  const assinatura = desembrulhar(sig.cms);
  if (!assinatura) {
    return {
      erro: '/Contents não é um OCTET STRING',
      diagnostico: {
        codigo: 'PKCS1_ILEGIVEL',
        titulo: 'Assinatura ilegível',
        severidade: 'erro',
      },
    };
  }

  const cert = certificados[0];
  const familia = cert.publicKeyAlgorithm.name ?? 'RSA';
  const observacoes = [];

  let assinaturaOk = false;
  let digestUsado = null;

  for (const digest of DIGESTS) {
    const r = await verifyWithCertificate(cert, assinatura, signedBytes, familia, digest);
    if (r.ok === true) {
      assinaturaOk = true;
      digestUsado = digest;
      break;
    }
    if (r.ok === null) {
      // Algoritmo ou curva sem suporte: nao e "nao confere".
      assinaturaOk = null;
      observacoes.push(...r.observacoes);
      break;
    }
  }

  if (assinaturaOk === false) {
    observacoes.push('a assinatura não confere com a chave pública do certificado');
  }

  return {
    formato: 'PKCS1',
    cert,
    certificados,
    detached: true,
    cossignatarios: 1,
    signingTime: null,
    datas: {},
    cripto: {
      integro: null,
      assinaturaOk,
      status: consolidarStatus(null, assinaturaOk),
      digestAlgoritmo: digestUsado,
      assinaturaAlgoritmo: digestUsado ? `${familia} + ${digestUsado}` : familia,
      hashCalculado: digestUsado ? await digestHex(digestUsado, signedBytes) : null,
      hashDeclarado: null,
      tamanhoAssinatura: assinatura.length,
      observacoes,
    },
  };
}

/** /Contents = OCTET STRING; devolve o conteudo. */
function desembrulhar(contents) {
  try {
    const n = parse(contents);
    return n.is(TAG.OCTET_STRING) ? n.content : null;
  } catch {
    return null;
  }
}
