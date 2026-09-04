/**
 * verify.js - Verificacao criptografica via WebCrypto.
 *
 * Reproduz as duas perguntas que o pyHanko responde com `intact` e `valid`:
 *
 *   integro       o documento nao mudou depois de assinado;
 *   assinaturaOk  a assinatura sobre os signedAttrs confere com a chave
 *                 publica do certificado do signatario.
 *
 * O que `integro` compara depende de o CMS encapsular ou nao o conteudo. Numa
 * assinatura detached (adbe.pkcs7.detached, ETSI.CAdES.detached) o
 * `messageDigest` e o hash do proprio /ByteRange, e uma comparacao resolve.
 *
 * Num carimbo de documento (ETSI.RFC3161) o CMS carrega um eContent - a
 * estrutura TSTInfo - e a regra do CMS e que o `messageDigest` e o hash do
 * conteudo assinado, isto e, do TSTInfo. Quem liga o carimbo ao PDF e o
 * `messageImprint` DENTRO do TSTInfo. Comparar o messageDigest com o
 * /ByteRange nesse caso acusa divergencia em documento intacto.
 *
 * Um algoritmo nao suportado devolve status INDETERMINADO. Nunca INVALIDO:
 * relatorio forense que confunde "não sei verificar" com "adulterado" e pior
 * que relatorio nenhum.
 */

import { decodeOID, toHex } from './der.js';

const CURVES = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
};

const subtle = globalThis.crypto?.subtle;

export async function sha256Hex(bytes) {
  const digest = await subtle.digest('SHA-256', bytes);
  return toHex(new Uint8Array(digest));
}

async function digestBytes(algorithm, bytes) {
  return new Uint8Array(await subtle.digest(algorithm, bytes));
}

/** Digest em hexadecimal, com o algoritmo informado. */
export async function digestHex(algorithm, bytes) {
  return toHex(await digestBytes(algorithm, bytes));
}

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Verifica um SignerInfo contra os bytes assinados.
 * @param {SignerInfo} signerInfo
 * @param {Uint8Array} signedBytes conteudo apontado pelo /ByteRange
 */
export async function verifySignerInfo(signerInfo, signedBytes, eContent = null) {
  const result = {
    integro: null,
    assinaturaOk: null,
    conteudoConfere: null,
    digestAlgoritmo: signerInfo.digestAlgorithm.name,
    assinaturaAlgoritmo: null,
    hashCalculado: null,
    hashDeclarado: null,
    imprintCalculado: null,
    imprintDeclarado: null,
    status: 'INDETERMINADO',
    observacoes: [],
  };

  const digestAlg = signerInfo.digestAlgorithm.name;
  if (!digestAlg) {
    result.observacoes.push(`algoritmo de hash não suportado (${signerInfo.digestAlgorithm.oid})`);
    return result;
  }

  // ---- integridade: hash do conteudo assinado x messageDigest declarado
  const conteudo = eContent ?? signedBytes;
  const declared = signerInfo.messageDigest;
  const calculated = await digestBytes(digestAlg, conteudo);
  result.hashCalculado = toHex(calculated);

  if (declared) {
    result.hashDeclarado = toHex(declared);
    result.conteudoConfere = bytesEqual(declared, calculated);

    // Sem eContent, o conteudo assinado E o documento: um teste responde as
    // duas perguntas. Com eContent, quem responde por `integro` e o chamador,
    // a partir do messageImprint.
    if (!eContent) result.integro = result.conteudoConfere;

    if (!result.conteudoConfere) {
      result.observacoes.push('o hash do conteúdo assinado não confere com o messageDigest');
    }
  } else if (signerInfo.signedAttrs.length === 0) {
    // Sem signedAttrs a assinatura incide direto sobre o conteudo: a
    // integridade e comprovada pela propria verificacao da assinatura.
    result.integro = null;
    result.observacoes.push('assinatura sem signedAttrs: integridade aferida pela assinatura');
  } else {
    result.observacoes.push('signedAttrs presente mas sem messageDigest');
  }

  // ---- assinatura: chave publica do certificado x bytes assinados
  const cert = signerInfo.signerCertificate;
  if (!cert) {
    result.observacoes.push('certificado do signatário não está embutido no PDF');
    return finalize(result);
  }

  const payload = signerInfo.signedAttrsForVerification() ?? signedBytes;
  const family = resolveFamily(signerInfo, cert);
  result.assinaturaAlgoritmo = family ? `${family} + ${digestAlg}` : signerInfo.signatureAlgorithm.oid;

  const veredito = await verifyWithCertificate(cert, signerInfo.signature, payload, family, digestAlg);
  result.assinaturaOk = veredito.ok;
  result.observacoes.push(...veredito.observacoes);

  if (result.assinaturaOk === false) {
    result.observacoes.push('a assinatura não confere com a chave pública do certificado');
  }

  return finalize(result);
}

/**
 * Verifica uma assinatura qualquer contra a chave publica de um certificado.
 * Usado tanto para o SignerInfo do CMS quanto para cada elo da cadeia de
 * certificados, onde o "conteudo" e o tbsCertificate do certificado filho.
 *
 * Devolve `{ok: null}` quando o algoritmo nao e suportado - nunca `false`, para
 * nao transformar "não sei verificar" em "invalido".
 *
 * @returns {Promise<{ok: boolean|null, observacoes: string[]}>}
 */
export async function verifyWithCertificate(cert, signature, payload, family, digestAlg) {
  const observacoes = [];

  if (!digestAlg) {
    observacoes.push('algoritmo de hash não suportado');
    return { ok: null, observacoes };
  }

  try {
    if (family === 'RSA') {
      const key = await subtle.importKey(
        'spki', cert.spki,
        { name: 'RSASSA-PKCS1-v1_5', hash: digestAlg },
        false, ['verify'],
      );
      const ok = await subtle.verify('RSASSA-PKCS1-v1_5', key, signature, payload);
      if (!ok) observacoes.push('a assinatura não confere com a chave pública do certificado');
      return { ok, observacoes };
    }

    if (family === 'ECDSA') {
      const oid = curveOid(cert);
      const curve = CURVES[oid];
      if (!curve) throw new Error(`curva não suportada (${oid})`);
      const key = await subtle.importKey(
        'spki', cert.spki, { name: 'ECDSA', namedCurve: curve }, false, ['verify'],
      );
      const raw = derEcdsaToRaw(signature, curve);
      const ok = await subtle.verify({ name: 'ECDSA', hash: digestAlg }, key, raw, payload);
      if (!ok) observacoes.push('a assinatura não confere com a chave pública do certificado');
      return { ok, observacoes };
    }

    if (family === 'RSA-PSS') {
      // Os parametros PSS (salt, MGF) exigem leitura da AlgorithmIdentifier;
      // nao implementado - fica explicito em vez de gerar falso negativo.
      observacoes.push('RSA-PSS ainda não suportado nesta página');
      return { ok: null, observacoes };
    }

    observacoes.push(`algoritmo de assinatura não suportado (${family ?? 'desconhecido'})`);
    return { ok: null, observacoes };
  } catch (err) {
    observacoes.push(`falha ao verificar a assinatura: ${err.message}`);
    return { ok: null, observacoes };
  }
}

/** SHA-256 de um buffer, em hexadecimal - usado como impressao digital. */
export async function fingerprint(bytes) {
  return toHex(new Uint8Array(await subtle.digest('SHA-256', bytes)));
}

/** Status unico a partir de integridade e assinatura. */
export function consolidarStatus(integro, assinaturaOk) {
  if (assinaturaOk === true && integro !== false) return 'VALIDA';
  if (assinaturaOk === false || integro === false) return 'INVALIDA';
  return 'INDETERMINADO';
}

function finalize(result) {
  result.status = consolidarStatus(result.integro, result.assinaturaOk);
  return result;
}

/**
 * A familia vem do signatureAlgorithm; quando ele e apenas `rsaEncryption`
 * (sem digest), o digest efetivo e o do campo digestAlgorithm.
 */
function resolveFamily(signerInfo, cert) {
  return signerInfo.signatureAlgorithm.family ?? cert.publicKeyAlgorithm.name ?? null;
}

function curveOid(cert) {
  const params = cert.publicKeyAlgorithm.params;
  if (!params) return null;
  try {
    return decodeOID(params);
  } catch {
    return null;
  }
}

/** ECDSA no CMS e SEQUENCE{r,s}; a WebCrypto espera r||s de tamanho fixo. */
function derEcdsaToRaw(der, curve) {
  const size = curve === 'P-256' ? 32 : curve === 'P-384' ? 48 : 66;
  let pos = 0;
  if (der[pos++] !== 0x30) throw new Error('assinatura ECDSA malformada');
  if (der[pos] & 0x80) pos += 1 + (der[pos] & 0x7f); else pos += 1;

  const readInt = () => {
    if (der[pos++] !== 0x02) throw new Error('INTEGER esperado na assinatura ECDSA');
    const len = der[pos++];
    let value = der.subarray(pos, pos + len);
    pos += len;
    while (value.length > size && value[0] === 0x00) value = value.subarray(1);
    const out = new Uint8Array(size);
    out.set(value, size - value.length);
    return out;
  };

  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(size * 2);
  raw.set(r, 0);
  raw.set(s, size);
  return raw;
}

/**
 * Confere se o carimbo do tempo RFC 3161 se refere a esta assinatura:
 * o messageImprint do token deve ser o hash dos bytes da assinatura.
 */
export async function verifyTimestampImprint(tst, signatureBytes) {
  if (!tst || !tst.imprintAlgorithm || !tst.imprintHash) return null;
  try {
    const calc = await digestBytes(tst.imprintAlgorithm, signatureBytes);
    return toHex(calc) === tst.imprintHash;
  } catch {
    return null;
  }
}

/** Vigencia do certificado na data de referencia informada. */
export function checkValidity(cert, referenceDate) {
  if (!cert || !cert.notBefore || !cert.notAfter) return null;
  const ref = referenceDate ?? new Date();
  return {
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
    vigenteNaAssinatura: ref >= cert.notBefore && ref <= cert.notAfter,
    referencia: ref,
  };
}
